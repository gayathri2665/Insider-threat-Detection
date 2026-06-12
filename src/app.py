import os
import sys
import threading
import time
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

# Add root folder to path so imports work correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.database import DatabaseManager
from src.uba import UBAManager
from src.model import EvidentialDetector, ComparativeModelsSuite
from src.alerts import AlertManager
from src.adaptive import FeedbackLoopManager, ConceptDriftHandler
from src.simulator import DatabaseSimulator
from wazuh.wazuh_agent_simulator import WazuhAgentSimulator

# Set paths
STATIC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'static'))
os.makedirs(STATIC_DIR, exist_ok=True)

app = Flask(__name__, static_folder=STATIC_DIR)
CORS(app) # Allow Cross-Origin Requests

# Core instances
db = DatabaseManager()
uba = UBAManager(db)
detector = EvidentialDetector()
detector.load() # Load weights
alerter = AlertManager(db, detector.model)
feedback_manager = FeedbackLoopManager(db, uba)
drift_handler = ConceptDriftHandler()
simulator = DatabaseSimulator(db)

# Shared lock for model retraining to avoid race conditions
retrain_lock = threading.Lock()

# Background log shipping thread callback
def process_incoming_log(log_entry):
    username = log_entry["username"]
    session_id = log_entry["session_id"]
    
    # 1. Insert log entry to queries_log table
    db.insert_query_log(
        username=username,
        session_id=session_id,
        query_type=log_entry["query_type"],
        query_text=log_entry["query_text"],
        tables_accessed=log_entry["tables_accessed"],
        rows_affected=log_entry["rows_affected"],
        bytes_returned=log_entry["bytes_returned"],
        execution_time_ms=log_entry["execution_time_ms"],
        is_failed=log_entry["is_failed"],
        error_message=log_entry["error_message"],
        timestamp=log_entry["timestamp"]
    )
    
    # 2. Retrieve all queries in the current session
    session_queries = db.fetch_all(
        "SELECT * FROM queries_log WHERE session_id = ? ORDER BY timestamp ASC",
        (session_id,)
    )
    
    # 3. Extract and standardize features
    raw_features = uba.extract_session_features(session_queries)
    normalized_features = uba.standardize_features(raw_features, username)
    
    # 4. Predict
    prediction = detector.predict(normalized_features)
    
    # 5. Route decision
    if prediction["decision"] in ["High-Confidence Threat", "Uncertain Activity"]:
        # Log and generate alert in database
        alerter.process_and_alert(
            username=username,
            raw_features=raw_features,
            normalized_features=normalized_features,
            prediction=prediction
        )
        # Check drift
        drift_handler.add_score(prediction["threat_score"])
    else:
        # Update user profile dynamically (normal baseline online adaptation)
        uba.update_user_profile_online(username, raw_features, lr=0.01)

# Function to run the Wazuh shipper in a separate background thread
def run_wazuh_agent():
    agent = WazuhAgentSimulator(log_path="data/mysql_audit.log", callback_fn=process_incoming_log)
    agent.start()

# API Endpoints

@app.route('/')
def serve_index():
    return send_from_directory(STATIC_DIR, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(STATIC_DIR, path)

@app.route('/api/status', methods=['GET'])
def get_status():
    users = db.fetch_all("SELECT * FROM users")
    alerts = db.fetch_all("SELECT * FROM alerts")
    feedback = db.fetch_all("SELECT * FROM feedback")
    queries_count = db.fetch_one("SELECT COUNT(*) as cnt FROM queries_log")
    
    # Load user baselines
    user_baselines = []
    for u in users:
        username = u["username"]
        profile = uba.get_or_create_profile(username)
        user_baselines.append({
            "username": username,
            "role": u["role"],
            "avg_queries": round(profile.get("query_count_mean", 0.0), 2),
            "avg_sensitive_access": round(profile.get("sensitive_access_mean", 0.0), 2),
            "avg_privileged_ops": round(profile.get("privileged_op_mean", 0.0), 2),
            "off_hours_ratio": round(profile.get("off_hours_ratio", 0.0) * 100, 1)
        })
        
    status_summary = {
        "users_count": len(users),
        "total_alerts": len(alerts),
        "open_alerts": len([a for a in alerts if a["status"] == "OPEN"]),
        "reviewed_alerts": len(feedback),
        "total_queries": queries_count["cnt"] if queries_count else 0,
        "drift_threshold": round(drift_handler.get_threshold(), 2),
        "users": user_baselines
    }
    return jsonify(status_summary)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    alerts = db.get_alerts(limit=100)
    return jsonify(alerts)

@app.route('/api/queries', methods=['GET'])
def get_queries():
    queries = db.get_queries_log(limit=50)
    return jsonify(queries)

@app.route('/api/trigger', methods=['POST'])
def trigger_scenario():
    data = request.get_json()
    scenario = data.get("scenario")
    if not scenario:
        return jsonify({"error": "Missing scenario parameter"}), 400
        
    try:
        # Trigger simulation (writes to mysql_audit.log)
        logs = simulator.trigger_threat_scenario(scenario)
        
        # VERCEL COMPATIBILITY: Direct synchronous log processing in serverless environment
        if os.environ.get('VERCEL') and logs:
            for log in logs:
                process_incoming_log(log)
                
        return jsonify({"status": "success", "message": f"Triggered scenario: {scenario}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/feedback', methods=['POST'])
def submit_feedback():
    data = request.get_json()
    alert_id = data.get("alert_id")
    feedback_type = data.get("type")
    comments = data.get("comments", "")
    
    if not alert_id or not feedback_type:
        return jsonify({"error": "Missing alert_id or type"}), 400
        
    try:
        # 1. Process feedback
        feedback_manager.process_admin_feedback(
            alert_id=alert_id,
            feedback_type=feedback_type,
            comments=comments
        )
        
        # 2. Run model retraining in a separate thread so it doesn't block HTTP response
        def retrain_task():
            with retrain_lock:
                print(f"[*] Background retraining started triggered by feedback on Alert #{alert_id}...")
                all_logs = db.fetch_all("SELECT * FROM queries_log ORDER BY username, session_id, timestamp ASC")
                sessions_dict = {}
                for log in all_logs:
                    user = log["username"]
                    sess = log["session_id"]
                    if user not in sessions_dict:
                        sessions_dict[user] = {}
                    if sess not in sessions_dict[user]:
                        sessions_dict[user][sess] = []
                    sessions_dict[user][sess].append(log)
                    
                X = []
                for user, sessions in sessions_dict.items():
                    for sess_id, queries in sessions.items():
                        raw_feats = uba.extract_session_features(queries)
                        norm_feats = uba.standardize_features(raw_feats, user)
                        X.append(norm_feats)
                        
                import numpy as np
                X = np.array(X)
                
                from src.cli import CLIAdminConsole
                console = CLIAdminConsole()
                combined_X, combined_y = console._prepare_training_data(X)
                
                # Retrain evidential model incorporating feedback
                feedback_manager.retrain_model_with_feedback(detector, combined_X, combined_y)
                
                # Reload model weights into active alerter/evaluator
                detector.load()
                alerter.model = detector.model
                print("[+] Background retraining complete.")
                
        threading.Thread(target=retrain_task).start()
        
        return jsonify({"status": "success", "message": "Feedback recorded. Retraining started."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/evaluate', methods=['GET'])
def get_evaluation():
    try:
        # Load training logs
        all_logs = db.fetch_all("SELECT * FROM queries_log ORDER BY username, session_id, timestamp ASC")
        sessions_dict = {}
        for log in all_logs:
            user = log["username"]
            sess = log["session_id"]
            if user not in sessions_dict:
                sessions_dict[user] = {}
            if sess not in sessions_dict[user]:
                sessions_dict[user][sess] = []
            sessions_dict[user][sess].append(log)
            
        X_train = []
        for user, sessions in sessions_dict.items():
            for sess_id, queries in sessions.items():
                raw_feats = uba.extract_session_features(queries)
                norm_feats = uba.standardize_features(raw_feats, user)
                X_train.append(norm_feats)
                
        import numpy as np
        X_train = np.array(X_train)
        
        # Fit baselines
        suite = ComparativeModelsSuite()
        from src.cli import CLIAdminConsole
        console = CLIAdminConsole()
        combined_X, combined_y = console._prepare_training_data(X_train)
        suite.train_all(combined_X, combined_y)
        
        # Run evaluation and format results
        from src.evaluation import PerformanceEvaluator
        evaluator = PerformanceEvaluator(db, uba)
        report = evaluator.run_evaluation(detector, suite)
        
        # Clean scores from JSON response since NumPy arrays are not serializable
        serializable_report = {}
        for k, v in report.items():
            serializable_report[k] = {
                "Accuracy": round(v["Accuracy"], 3),
                "Precision": round(v["Precision"], 3),
                "Recall": round(v["Recall"], 3),
                "F1-Score": round(v["F1-Score"], 3),
                "FPR": round(v["FPR"], 3),
                "FNR": round(v["FNR"], 3),
                "Latency": round(v["Latency (ms)"], 3),
                "TP": int(v["TP"]),
                "TN": int(v["TN"]),
                "FP": int(v["FP"]),
                "FN": int(v["FN"])
            }
            
        return jsonify(serializable_report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Start the wazuh simulator agent in a daemon background thread
    wazuh_thread = threading.Thread(target=run_wazuh_agent, daemon=True)
    wazuh_thread.start()
    
    # Start the web app on local port 5000
    print("[*] Launching API Server on http://127.0.0.1:5000...")
    app.run(host='127.0.0.1', port=5000, debug=False)
