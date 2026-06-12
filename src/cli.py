import os
import sys
import time
import argparse
from tabulate import tabulate
from src.database import DatabaseManager
from src.simulator import DatabaseSimulator
from src.uba import UBAManager
from src.model import EvidentialDetector, ComparativeModelsSuite
from src.alerts import AlertManager
from src.adaptive import FeedbackLoopManager, ConceptDriftHandler
from src.evaluation import PerformanceEvaluator
from wazuh.wazuh_agent_simulator import WazuhAgentSimulator

class CLIAdminConsole:
    def __init__(self):
        self.db = DatabaseManager()
        self.uba = UBAManager(self.db)
        self.detector = EvidentialDetector()
        
        # Load evidential weights if trained
        self.detector.load()
        self.alerter = AlertManager(self.db, self.detector.model)
        self.feedback_manager = FeedbackLoopManager(self.db, self.uba)
        self.drift_handler = ConceptDriftHandler()
        self.simulator = DatabaseSimulator(self.db)

    def init_db(self):
        """Initializes database schema and generates baseline training data."""
        print("[*] Initializing Database & Generating Baseline Logs...")
        self.db.initialize_schema()
        # Seed users and generate baseline query logs (50 sessions per user)
        self.simulator.generate_baseline_data(num_sessions=50)
        # Process logs in DB to establish baseline profiles
        self.uba.build_profiles_from_db()
        print("[+] Database initialized and baseline profiles built.")

    def _prepare_training_data(self, X_normal):
        """Generates synthetic threat vectors and returns a combined dataset for training."""
        synthetic_threats_X = []
        synthetic_threats_y = []
        
        for norm_vec in X_normal:
            # Threat 1: Massive sensitive table accesses
            v1 = norm_vec.copy()
            v1[2] += 8.0  # sensitive_access_count
            v1[0] += 5.0  # query_count
            synthetic_threats_X.append(v1)
            synthetic_threats_y.append(1.0)
            
            # Threat 2: Administrative operations executed off-hours
            v2 = norm_vec.copy()
            v2[3] += 10.0 # privileged_op_count
            v2[6] = 5.0   # off_hours_ratio
            synthetic_threats_X.append(v2)
            synthetic_threats_y.append(1.0)
            
            # Threat 3: Data Exfiltration (large bytes returned)
            v3 = norm_vec.copy()
            v3[4] += 12.0 # log_bytes_returned
            synthetic_threats_X.append(v3)
            synthetic_threats_y.append(1.0)
            
            # Threat 4: High failed queries count (failed logins/syntax injection errors)
            v4 = norm_vec.copy()
            v4[1] += 8.0  # failed_query_count
            synthetic_threats_X.append(v4)
            synthetic_threats_y.append(1.0)
            
            # Threat 5: SQL Injection signature (failed queries + sensitive access)
            v5 = norm_vec.copy()
            v5[1] += 5.0  # failed queries
            v5[2] += 4.0  # sensitive access
            synthetic_threats_X.append(v5)
            synthetic_threats_y.append(1.0)
            
            # Threat 6: Sudden burst of queries off-hours
            v6 = norm_vec.copy()
            v6[0] += 12.0 # query count
            v6[6] = 6.0   # off hours ratio
            synthetic_threats_X.append(v6)
            synthetic_threats_y.append(1.0)
            
        synthetic_threats_X = np.array(synthetic_threats_X)
        synthetic_threats_y = np.array(synthetic_threats_y)
        
        y_normal = np.zeros(len(X_normal))
        
        combined_X = np.vstack([X_normal, synthetic_threats_X])
        combined_y = np.concatenate([y_normal, synthetic_threats_y])
        return combined_X, combined_y

    def train_models(self):
        """Builds training datasets from database history and trains models."""
        print("[*] Extracting user session features from database logs...")
        all_logs = self.db.fetch_all("SELECT * FROM queries_log ORDER BY username, session_id, timestamp ASC")
        
        # Group queries by username and session
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
                raw_feats = self.uba.extract_session_features(queries)
                norm_feats = self.uba.standardize_features(raw_feats, user)
                X.append(norm_feats)
                
        X = np.array(X)
        print(f"[*] Extracted {len(X)} normal user session vectors.")
        print("[*] Generating synthetic threat profiles for model training...")
        
        combined_X, combined_y = self._prepare_training_data(X)
        
        # Train Deep Evidential Model
        print("[*] Training Deep Evidential Anomaly Classifier...")
        self.detector.train(combined_X, combined_y)
        
        # Train Comparative Suite (Baselines)
        print("[*] Training comparative baseline suite (I-Forest, OC-SVM, Autoencoder, Random Forest)...")
        suite = ComparativeModelsSuite()
        suite.train_all(combined_X, combined_y)
        
        print("[+] All models trained and serialized successfully.")

    def run_monitor(self):
        """Starts real-time log ingestion and anomaly detection."""
        print("\n" + "="*70)
        print("    STARTING REAL-TIME INSIDER THREAT MONITORING (WAZUH SHIPPER)")
        print("="*70)
        print("[*] Monitoring 'data/mysql_audit.log' for activity...")
        print("[*] Press Ctrl+C to terminate monitor.")
        
        # Define the log shipper callback
        def process_new_log(log_entry):
            username = log_entry["username"]
            session_id = log_entry["session_id"]
            
            # 1. Insert log entry to queries_log table (Wazuh ships to DB)
            self.db.insert_query_log(
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
            session_queries = self.db.fetch_all(
                "SELECT * FROM queries_log WHERE session_id = ? ORDER BY timestamp ASC",
                (session_id,)
            )
            
            # 3. Extract feature vector and standardize
            raw_features = self.uba.extract_session_features(session_queries)
            normalized_features = self.uba.standardize_features(raw_features, username)
            
            # 4. Run model inference
            prediction = self.detector.predict(normalized_features)
            
            # 5. Route decisions
            if prediction["decision"] in ["High-Confidence Threat", "Uncertain Activity"]:
                # Generate alert
                alert = self.alerter.process_and_alert(
                    username=username,
                    raw_features=raw_features,
                    normalized_features=normalized_features,
                    prediction=prediction
                )
                # Print alert to CLI
                print(AlertManager.format_alert_cli(alert))
                
                # Check for concept drift using alert threat score
                self.drift_handler.add_score(prediction["threat_score"])
            else:
                # Update user running baseline profile with normal behavior (adaptive learning)
                # Lower learning rate for online drift
                self.uba.update_user_profile_online(username, raw_features, lr=0.01)
                
        # Instantiate agent simulator and start polling
        agent = WazuhAgentSimulator(callback_fn=process_new_log)
        try:
            agent.start()
        except KeyboardInterrupt:
            agent.stop()
            print("[+] Monitor stopped.")

    def trigger_attack(self, scenario):
        """Appends queries representing an attack scenario to the audit log."""
        print(f"[*] Simulating insider attack scenario: {scenario}...")
        self.simulator.trigger_threat_scenario(scenario)

    def submit_feedback(self, alert_id, feedback_type, comment=""):
        """Submits administrator feedback and updates baselines/models."""
        print(f"[*] Admin submitting feedback on alert #{alert_id} ({feedback_type})...")
        self.feedback_manager.process_admin_feedback(alert_id, feedback_type, comments=comment)
        
        # Load baseline logs to retrain model with feedback
        all_logs = self.db.fetch_all("SELECT * FROM queries_log ORDER BY username, session_id, timestamp ASC")
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
                raw_feats = self.uba.extract_session_features(queries)
                norm_feats = self.uba.standardize_features(raw_feats, user)
                X.append(norm_feats)
        X = np.array(X)
        
        # Retrain evidential classifier including feedback labels and synthetic threats
        combined_X, combined_y = self._prepare_training_data(X)
        self.feedback_manager.retrain_model_with_feedback(self.detector, combined_X, combined_y)

    def run_eval_suite(self):
        """Runs the benchmark evaluation comparing all models."""
        print("[*] Running Performance Evaluation Benchmark Suite...")
        evaluator = PerformanceEvaluator(self.db, self.uba)
        # Run evaluation against baselines
        suite = ComparativeModelsSuite()
        
        # Quick model fit for baselines comparison on training data
        all_logs = self.db.fetch_all("SELECT * FROM queries_log ORDER BY username, session_id, timestamp ASC")
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
                raw_feats = self.uba.extract_session_features(queries)
                norm_feats = self.uba.standardize_features(raw_feats, user)
                X_train.append(norm_feats)
                
        X_train = np.array(X_train)
        combined_X, combined_y = self._prepare_training_data(X_train)
        
        suite.train_all(combined_X, combined_y)
        evaluator.run_evaluation(self.detector, suite)

    def show_status(self):
        """Displays summaries of user baselines, alerts, and feedback."""
        users = self.db.fetch_all("SELECT * FROM users")
        alerts = self.db.fetch_all("SELECT * FROM alerts ORDER BY timestamp DESC")
        feedback = self.db.fetch_all("SELECT * FROM feedback")
        
        print("\n" + "="*70)
        print("          INSIDER THREAT FRAMEWORK STATUS SUMMARY")
        print("="*70)
        print(f"Registered Database Users: {len(users)}")
        print(f"Total Detected Security Alerts: {len(alerts)}")
        print(f"Total Reviewed Alerts (Feedback Logs): {len(feedback)}")
        
        # Show recent alerts
        if alerts:
            print("\nRecent Security Alerts:")
            alerts_table = []
            for a in alerts[:8]:
                alerts_table.append([
                    a["id"], a["username"], a["alert_level"],
                    f"{a['threat_score']:.3f}", f"{a['confidence_score']:.3f}",
                    a["status"], a["timestamp"]
                ])
            print(tabulate(alerts_table, headers=["ID", "User", "Risk", "Threat Sc", "Conf Sc", "Status", "Timestamp"], tablefmt="presto"))
            
        # Show user profile baselines
        print("\nActive User Behavioral Profiles:")
        profiles_table = []
        for u in users:
            username = u["username"]
            profile = self.uba.get_or_create_profile(username)
            profiles_table.append([
                username, u["role"],
                f"{profile.get('query_count_mean', 0.0):.2f}",
                f"{profile.get('sensitive_access_mean', 0.0):.2f}",
                f"{profile.get('privileged_op_mean', 0.0):.2f}",
                f"{profile.get('off_hours_ratio', 0.0)*100:.1f}%"
            ])
        print(tabulate(profiles_table, headers=["User", "Role", "Avg Queries", "Avg Sens Access", "Avg Priv Ops", "Off-Hours %"], tablefmt="presto"))
        print("="*70)

# Import numpy inside CLI console
import numpy as np
