import os
import json
import datetime
import math
import numpy as np
from src.database import DatabaseManager

SENSITIVE_TABLES = ["salaries", "credentials", "credit_cards", "hr_files", "audit_logs"]

# Index mapping for our feature vector
FEATURE_NAMES = [
    "query_count",
    "failed_query_count",
    "sensitive_access_count",
    "privileged_op_count",
    "log_bytes_returned",
    "avg_execution_time",
    "off_hours_ratio",
    "select_ratio"
]

class UBAManager:
    def __init__(self, db_manager):
        self.db = db_manager

    @staticmethod
    def is_off_hours(timestamp_str):
        """Checks if a timestamp falls outside typical working hours (8 AM - 7 PM)."""
        try:
            dt = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            # Off-hours: 7 PM to 8 AM
            return 1.0 if dt.hour < 8 or dt.hour >= 19 else 0.0
        except Exception:
            return 0.0

    def extract_session_features(self, session_queries):
        """Extracts the raw feature vector from a list of queries in a session.
        Returns a numpy array of size 8.
        """
        if not session_queries:
            return np.zeros(len(FEATURE_NAMES))

        query_count = len(session_queries)
        failed_query_count = sum(1 for q in session_queries if q.get("is_failed", 0) == 1)
        
        # Check for sensitive tables
        sensitive_access_count = 0
        for q in session_queries:
            tables = str(q.get("tables_accessed", "")).lower()
            if any(st in tables for st in SENSITIVE_TABLES):
                sensitive_access_count += 1
                
        # Check for privileged operations
        privileged_op_count = sum(1 for q in session_queries if q.get("query_type") in ["ALTER", "DROP", "GRANT", "REVOKE"])
        
        # Data volume in bytes (using log scale to prevent extreme outliers from skewing mean/variance)
        total_bytes = sum(q.get("bytes_returned", 0) for q in session_queries)
        log_bytes = math.log1p(total_bytes)
        
        # Average execution time
        avg_exec_time = sum(q.get("execution_time_ms", 0) for q in session_queries) / query_count
        
        # Off-hours ratio
        off_hours_count = sum(UBAManager.is_off_hours(q.get("timestamp")) for q in session_queries)
        off_hours_ratio = off_hours_count / query_count
        
        # Select ratio
        select_count = sum(1 for q in session_queries if q.get("query_type") == "SELECT")
        select_ratio = select_count / query_count

        return np.array([
            float(query_count),
            float(failed_query_count),
            float(sensitive_access_count),
            float(privileged_op_count),
            float(log_bytes),
            float(avg_exec_time),
            float(off_hours_ratio),
            float(select_ratio)
        ])

    def get_or_create_profile(self, username):
        """Retrieves user profile from database. Creates a default profile if not found."""
        profile_row = self.db.get_user_profile(username)
        
        if profile_row:
            # Profile exists
            profile_dict = {
                "query_count_mean": profile_row["query_count_mean"],
                "query_count_std": profile_row["query_count_std"],
                "failed_logins_mean": profile_row["failed_logins_mean"],
                "sensitive_access_mean": profile_row["sensitive_access_mean"],
                "privileged_ops_mean": profile_row["privileged_ops_mean"],
                "bytes_returned_mean": profile_row["bytes_returned_mean"],
                "execution_time_mean": profile_row["execution_time_mean"],
                "off_hours_ratio": profile_row["off_hours_ratio"],
            }
            # Add back std deviations or default them if missing from DB fields
            # We can parse the full profile_data JSON
            try:
                extended = json.loads(profile_row["profile_data"])
                profile_dict.update(extended)
            except Exception:
                pass
            return profile_dict
        else:
            # Create default baseline profile
            default_profile = {
                "query_count_mean": 10.0,
                "query_count_std": 3.0,
                
                "failed_query_count_mean": 0.05,
                "failed_query_count_std": 0.2,
                
                "sensitive_access_mean": 0.05,
                "sensitive_access_std": 0.2,
                
                "privileged_op_mean": 0.01,
                "privileged_op_std": 0.1,
                
                "log_bytes_returned_mean": 6.0, # e^6 ~ 400 bytes
                "log_bytes_returned_std": 1.5,
                
                "avg_execution_time_mean": 15.0,
                "avg_execution_time_std": 10.0,
                
                "off_hours_ratio": 0.05,
                
                "select_ratio_mean": 0.7,
                "select_ratio_std": 0.2,
                
                "session_count": 0
            }
            self.db.save_user_profile(username, default_profile)
            return default_profile

    def get_profile_vectors(self, profile):
        """Extracts mean and standard deviation vectors from profile dict.
        Guarantees vectors match the index of FEATURE_NAMES.
        """
        means = np.array([
            profile.get("query_count_mean", 10.0),
            profile.get("failed_query_count_mean", 0.1),
            profile.get("sensitive_access_mean", 0.1),
            profile.get("privileged_op_mean", 0.01),
            profile.get("log_bytes_returned_mean", 6.0),
            profile.get("avg_execution_time_mean", 15.0),
            profile.get("off_hours_ratio", 0.05), # no std needed for ratio directly, or we default it
            profile.get("select_ratio_mean", 0.7)
        ])
        
        stds = np.array([
            profile.get("query_count_std", 3.0),
            profile.get("failed_query_count_std", 0.5),
            profile.get("sensitive_access_std", 0.5),
            profile.get("privileged_op_std", 0.1),
            profile.get("log_bytes_returned_std", 1.5),
            profile.get("avg_execution_time_std", 10.0),
            0.15, # Std dev for off_hours_ratio
            profile.get("select_ratio_std", 0.2)
        ])
        
        # Ensure stds are not too close to zero to prevent division by zero
        stds = np.maximum(stds, 1e-4)
        
        return means, stds

    def standardize_features(self, raw_features, username):
        """Standardizes raw features using the user's baseline profile.
        Returns a normalized vector z.
        """
        profile = self.get_or_create_profile(username)
        means, stds = self.get_profile_vectors(profile)
        
        # Compute standard Z-score: z = (x - mean) / std
        normalized = (raw_features - means) / stds
        return normalized

    def update_user_profile_online(self, username, raw_features, lr=0.05):
        """Updates the running mean and variance for a user profile using exponential moving average (EMA).
        This executes the adaptive learning mechanism.
        """
        profile = self.get_or_create_profile(username)
        
        profile["session_count"] = profile.get("session_count", 0) + 1
        
        # We update each feature's mean and std
        # index mapping
        keys_mean_std = [
            ("query_count_mean", "query_count_std"),
            ("failed_query_count_mean", "failed_query_count_std"),
            ("sensitive_access_mean", "sensitive_access_std"),
            ("privileged_op_mean", "privileged_op_std"),
            ("log_bytes_returned_mean", "log_bytes_returned_std"),
            ("avg_execution_time_mean", "avg_execution_time_std"),
            (None, None), # off_hours_ratio has running update of ratio
            ("select_ratio_mean", "select_ratio_std")
        ]
        
        for i, val in enumerate(raw_features):
            mean_key, std_key = keys_mean_std[i]
            
            if mean_key and std_key:
                old_mean = profile.get(mean_key, 0.0)
                old_std = profile.get(std_key, 1.0)
                
                # Update mean
                new_mean = (1 - lr) * old_mean + lr * val
                # Update variance: var = (1 - lr) * var + lr * (val - mean)^2
                old_var = old_std ** 2
                new_var = (1 - lr) * old_var + lr * ((val - old_mean) * (val - new_mean))
                new_std = math.sqrt(max(new_var, 1e-6))
                
                profile[mean_key] = new_mean
                profile[std_key] = new_std
            elif i == 6:
                # off_hours_ratio update
                old_ratio = profile.get("off_hours_ratio", 0.05)
                profile["off_hours_ratio"] = (1 - lr) * old_ratio + lr * val
                
        # Save updated profile back to DB
        self.db.save_user_profile(username, profile)
        return profile

    def build_profiles_from_db(self):
        """Processes all query logs currently in the database to build historical profiles for all users."""
        print("[*] Rebuilding user behavioral profiles from database log history...")
        
        # Get all queries grouped by user and session
        all_logs = self.db.fetch_all("SELECT * FROM queries_log ORDER BY username, session_id, timestamp ASC")
        
        # Group logs by user, then session
        grouped = {}
        for log in all_logs:
            user = log["username"]
            sess = log["session_id"]
            if user not in grouped:
                grouped[user] = {}
            if sess not in grouped[user]:
                grouped[user][sess] = []
            grouped[user][sess].append(log)
            
        for user, sessions in grouped.items():
            print(f"[*] Processing {len(sessions)} sessions for user: {user}")
            
            # Reset user profile to defaults
            profile = {
                "query_count_mean": 0.0, "query_count_std": 0.0,
                "failed_query_count_mean": 0.0, "failed_query_count_std": 0.0,
                "sensitive_access_mean": 0.0, "sensitive_access_std": 0.0,
                "privileged_op_mean": 0.0, "privileged_op_std": 0.0,
                "log_bytes_returned_mean": 0.0, "log_bytes_returned_std": 0.0,
                "avg_execution_time_mean": 0.0, "avg_execution_time_std": 0.0,
                "off_hours_ratio": 0.0,
                "select_ratio_mean": 0.0, "select_ratio_std": 0.0,
                "session_count": len(sessions)
            }
            
            session_features = []
            for sess_id, queries in sessions.items():
                features = self.extract_session_features(queries)
                session_features.append(features)
                
            session_features = np.array(session_features)
            
            # Compute statistical properties
            means = np.mean(session_features, axis=0)
            stds = np.std(session_features, axis=0)
            
            # Map statistical properties back to profile fields
            profile["query_count_mean"] = float(means[0])
            profile["query_count_std"] = float(stds[0])
            
            profile["failed_query_count_mean"] = float(means[1])
            profile["failed_query_count_std"] = float(stds[1])
            
            profile["sensitive_access_mean"] = float(means[2])
            profile["sensitive_access_std"] = float(stds[2])
            
            profile["privileged_op_mean"] = float(means[3])
            profile["privileged_op_std"] = float(stds[3])
            
            profile["log_bytes_returned_mean"] = float(means[4])
            profile["log_bytes_returned_std"] = float(stds[4])
            
            profile["avg_execution_time_mean"] = float(means[5])
            profile["avg_execution_time_std"] = float(stds[5])
            
            profile["off_hours_ratio"] = float(means[6])
            
            profile["select_ratio_mean"] = float(means[7])
            profile["select_ratio_std"] = float(stds[7])
            
            # Save to db
            self.db.save_user_profile(user, profile)
            
        print("[+] Finished rebuilding profiles.")
