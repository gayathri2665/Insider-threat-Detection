import os
import json
import numpy as np
import torch
from src.database import DatabaseManager
from src.uba import UBAManager

class FeedbackLoopManager:
    def __init__(self, db_manager, uba_manager):
        self.db = db_manager
        self.uba = uba_manager

    def process_admin_feedback(self, alert_id, feedback_type, admin_username="admin", comments=""):
        """Processes administrator feedback on a security alert.
        feedback_type: 'TRUE_POSITIVE' or 'FALSE_POSITIVE'
        """
        # Save feedback in the DB
        self.db.insert_feedback(alert_id, admin_username, feedback_type, comments)
        print(f"[*] Feedback recorded for alert #{alert_id}: {feedback_type}")

        # Retrieve the alert details to get the username and context
        alert = self.db.fetch_one("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        if not alert:
            print(f"[!] Alert #{alert_id} not found.")
            return

        username = alert["username"]
        
        # If FALSE_POSITIVE, the flagged activity was actually normal.
        # We must update the user's behavioral baseline so that similar activity is tolerated.
        if feedback_type == "FALSE_POSITIVE":
            # Find queries associated with this alert's timestamp and user
            # In a production system, we'd link the specific session.
            # Let's find the queries within the hour of the alert.
            timestamp_str = alert["timestamp"]
            query = """
            SELECT * FROM queries_log 
            WHERE username = ? 
              AND timestamp >= datetime(?, '-1 hour')
              AND timestamp <= datetime(?, '+1 hour')
            """
            # Use appropriate syntax if MySQL is active
            if self.db.use_mysql:
                query = query.replace("datetime(?, '-1 hour')", "DATE_SUB(%s, INTERVAL 1 HOUR)")
                query = query.replace("datetime(?, '+1 hour')", "DATE_ADD(%s, INTERVAL 1 HOUR)")
                query = query.replace("?", "%s")
                queries = self.db.fetch_all(query, (username, timestamp_str, timestamp_str))
            else:
                queries = self.db.fetch_all(query, (username, timestamp_str, timestamp_str))

            if queries:
                # Reconstruct raw feature vector of the false positive session
                raw_features = self.uba.extract_session_features(queries)
                print(f"[*] False positive session features: {raw_features}")
                
                # Update user profile with a HIGHER learning rate to quickly incorporate admin approval
                self.uba.update_user_profile_online(username, raw_features, lr=0.20)
                print(f"[+] User profile for '{username}' updated/adapted based on False Positive feedback.")
            else:
                print(f"[!] No query logs found for '{username}' around alert time. Baselines unchanged.")
        
        elif feedback_type == "TRUE_POSITIVE":
            print(f"[*] Confirmed Threat for user '{username}'. Profile baseline updates blocked to prevent poisoning.")

    def retrain_model_with_feedback(self, evidential_detector, baseline_X, baseline_y):
        """Retrains the Deep Evidential network, combining original baseline data with admin feedback."""
        print("[*] Performing incremental model training incorporating administrator feedback...")
        
        # Load feedback samples from DB
        feedback_rows = self.db.fetch_all("""
            SELECT f.feedback_type, a.username, a.explanation, a.timestamp 
            FROM feedback f 
            JOIN alerts a ON f.alert_id = a.id
        """)
        
        if not feedback_rows:
            print("[*] No admin feedback logs found. Running standard training.")
            evidential_detector.train(baseline_X, baseline_y)
            return
            
        feedback_X = []
        feedback_y = []
        
        for row in feedback_rows:
            username = row["username"]
            timestamp_str = row["timestamp"]
            feedback_type = row["feedback_type"]
            
            # Query session logs around alert timestamp
            query = """
            SELECT * FROM queries_log 
            WHERE username = ? 
              AND timestamp >= datetime(?, '-1 hour')
              AND timestamp <= datetime(?, '+1 hour')
            """
            if self.db.use_mysql:
                query = query.replace("datetime(?, '-1 hour')", "DATE_SUB(%s, INTERVAL 1 HOUR)")
                query = query.replace("datetime(?, '+1 hour')", "DATE_ADD(%s, INTERVAL 1 HOUR)")
                query = query.replace("?", "%s")
                queries = self.db.fetch_all(query, (username, timestamp_str, timestamp_str))
            else:
                queries = self.db.fetch_all(query, (username, timestamp_str, timestamp_str))

            if queries:
                raw_feats = self.uba.extract_session_features(queries)
                norm_feats = self.uba.standardize_features(raw_feats, username)
                feedback_X.append(norm_feats)
                # Label feedback: False Positive is Normal (0), True Positive is Threat (1)
                label = 0.0 if feedback_type == "FALSE_POSITIVE" else 1.0
                feedback_y.append(label)
                
        if feedback_X:
            feedback_X = np.array(feedback_X)
            feedback_y = np.array(feedback_y)
            
            # Combine baseline data with feedback data (weighting feedback data to emphasize it)
            combined_X = np.vstack([baseline_X, feedback_X])
            combined_y = np.concatenate([baseline_y, feedback_y])
            
            # Train model
            evidential_detector.train(combined_X, combined_y)
            print(f"[+] Retrained model successfully. Total samples: {len(combined_X)} (including {len(feedback_X)} admin-labeled samples).")
        else:
            print("[!] Could not extract features for feedback alerts. Falling back to standard training.")
            evidential_detector.train(baseline_X, baseline_y)


class ConceptDriftHandler:
    def __init__(self, window_size=50, drift_threshold=2.0):
        self.window_size = window_size
        self.drift_threshold = drift_threshold
        self.running_threat_scores = []
        self.adaptive_threat_threshold = 0.5

    def add_score(self, threat_score):
        """Adds a threat score to the sliding window and evaluates concept drift."""
        self.running_threat_scores.append(threat_score)
        if len(self.running_threat_scores) > self.window_size:
            self.running_threat_scores.pop(0)

        # Check for system-wide drift if window is full
        if len(self.running_threat_scores) == self.window_size:
            window_mean = np.mean(self.running_threat_scores)
            window_std = np.std(self.running_threat_scores)
            
            # If standard deviation is extremely low, cap it to prevent division issues
            window_std = max(window_std, 1e-4)
            
            # If the mean threat score increases significantly (e.g. more than threshold Z-scores from nominal 0.15)
            nominal_mean = 0.15
            z_score = (window_mean - nominal_mean) / window_std
            
            if z_score > self.drift_threshold:
                print(f"\n[!] CONCEPT DRIFT DETECTED: System-wide database workloads or user query profiles have shifted.")
                print(f"    - Window Mean Threat Score: {window_mean:.4f} (Nominal: {nominal_mean:.4f}, Z-Score: {z_score:.2f})")
                
                # Adapt decision threshold to tolerate system-wide changes
                old_threshold = self.adaptive_threat_threshold
                self.adaptive_threat_threshold = min(0.75, 0.5 + 0.05 * z_score)
                print(f"    - Adapting Threat Decision Threshold: {old_threshold:.2f} -> {self.adaptive_threat_threshold:.2f}")
                return True
                
        return False
        
    def get_threshold(self):
        return self.adaptive_threat_threshold
