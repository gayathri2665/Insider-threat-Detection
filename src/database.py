import os
import json
import sqlite3
import datetime
from pathlib import Path

# Try to import mysql connector, but let it be optional
try:
    import mysql.connector
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False

class DatabaseManager:
    def __init__(self, use_mysql=False, mysql_config=None):
        self.use_mysql = use_mysql and MYSQL_AVAILABLE
        self.mysql_config = mysql_config or {}
        
        # VERCEL COMPATIBILITY: Use /tmp directory for writeable database in Serverless environment
        if os.environ.get('VERCEL'):
            self.db_path = Path("/tmp/security_monitor.db")
        else:
            self.db_path = Path("data/security_monitor.db")
        
        # Ensure data directory exists
        if os.environ.get('VERCEL'):
            os.makedirs("/tmp", exist_ok=True)
        else:
            os.makedirs("data", exist_ok=True)
        
        # Initialize connection
        self.conn = None
        self.connect()
        self.initialize_schema()
        self.seed_default_data_if_empty()

    def seed_default_data_if_empty(self):
        """Seeds default users and behavioral profile baselines if database is empty.
        This ensures web dashboards work out-of-the-box on serverless (Vercel) environments.
        """
        try:
            # Check if users are empty
            user_count = self.fetch_one("SELECT COUNT(*) as cnt FROM users")
            if user_count and user_count["cnt"] == 0:
                print("[*] Seeding default users and profiles for Vercel/serverless environments...")
                # 1. Insert users
                users_to_create = [
                    ("alice_hr", "HR", 3),
                    ("bob_dev", "Developer", 2),
                    ("charlie_analyst", "Analyst", 4),
                    ("service_acc", "ServiceAccount", 5),
                    ("stranger_danger", "Guest", 1)
                ]
                for username, role, clearance in users_to_create:
                    self.insert_user(username, role, clearance)
                    
                # 2. Insert default profiles (matching simulated baselines)
                default_profiles = {
                    "alice_hr": {
                        "query_count_mean": 14.18, "query_count_std": 3.2,
                        "failed_query_count_mean": 0.05, "failed_query_count_std": 0.2,
                        "sensitive_access_mean": 4.60, "sensitive_access_std": 1.2,
                        "privileged_op_mean": 0.0, "privileged_op_std": 0.1,
                        "log_bytes_returned_mean": 6.8, "log_bytes_returned_std": 1.1,
                        "avg_execution_time_mean": 24.5, "avg_execution_time_std": 8.0,
                        "off_hours_ratio": 0.0, "select_ratio_mean": 0.8, "select_ratio_std": 0.1,
                        "session_count": 50
                    },
                    "bob_dev": {
                        "query_count_mean": 13.96, "query_count_std": 2.9,
                        "failed_query_count_mean": 0.05, "failed_query_count_std": 0.2,
                        "sensitive_access_mean": 0.0, "sensitive_access_std": 0.1,
                        "privileged_op_mean": 0.0, "privileged_op_std": 0.1,
                        "log_bytes_returned_mean": 5.9, "log_bytes_returned_std": 1.3,
                        "avg_execution_time_mean": 16.2, "avg_execution_time_std": 5.0,
                        "off_hours_ratio": 0.0, "select_ratio_mean": 0.55, "select_ratio_std": 0.15,
                        "session_count": 50
                    },
                    "charlie_analyst": {
                        "query_count_mean": 14.12, "query_count_std": 3.5,
                        "failed_query_count_mean": 0.05, "failed_query_count_std": 0.2,
                        "sensitive_access_mean": 0.0, "sensitive_access_std": 0.1,
                        "privileged_op_mean": 0.0, "privileged_op_std": 0.1,
                        "log_bytes_returned_mean": 8.2, "log_bytes_returned_std": 1.4,
                        "avg_execution_time_mean": 125.0, "avg_execution_time_std": 30.0,
                        "off_hours_ratio": 0.0, "select_ratio_mean": 1.0, "select_ratio_std": 0.05,
                        "session_count": 50
                    },
                    "service_acc": {
                        "query_count_mean": 2.0, "query_count_std": 0.1,
                        "failed_query_count_mean": 0.0, "failed_query_count_std": 0.05,
                        "sensitive_access_mean": 0.0, "sensitive_access_std": 0.05,
                        "privileged_op_mean": 0.0, "privileged_op_std": 0.05,
                        "log_bytes_returned_mean": 6.2, "log_bytes_returned_std": 0.2,
                        "avg_execution_time_mean": 3.0, "avg_execution_time_std": 0.5,
                        "off_hours_ratio": 0.56, "select_ratio_mean": 1.0, "select_ratio_std": 0.05,
                        "session_count": 50
                    },
                    "stranger_danger": {
                        "query_count_mean": 10.0, "query_count_std": 3.0,
                        "failed_query_count_mean": 0.1, "failed_query_count_std": 0.5,
                        "sensitive_access_mean": 0.05, "sensitive_access_std": 0.5,
                        "privileged_op_mean": 0.01, "privileged_op_std": 0.1,
                        "log_bytes_returned_mean": 6.0, "log_bytes_returned_std": 1.5,
                        "avg_execution_time_mean": 15.0, "avg_execution_time_std": 10.0,
                        "off_hours_ratio": 0.05, "select_ratio_mean": 0.7, "select_ratio_std": 0.2,
                        "session_count": 5
                    }
                }
                for username, profile_dict in default_profiles.items():
                    self.save_user_profile(username, profile_dict)
                print("[+] Seeding complete.")
        except Exception as e:
            print(f"[!] Database auto-seeding error: {e}")

    def connect(self):
        """Establishes database connection."""
        if self.use_mysql:
            try:
                self.conn = mysql.connector.connect(**self.mysql_config)
                # Ensure we use dictionary cursor or standard behavior
            except Exception as e:
                print(f"[!] MySQL connection failed: {e}. Falling back to SQLite.")
                self.use_mysql = False
                self.connect_sqlite()
        else:
            self.connect_sqlite()

    def connect_sqlite(self):
        """Connects to local SQLite database."""
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

    def get_cursor(self):
        """Returns cursor based on active database engine."""
        try:
            # Check connection health and reconnect if necessary
            if self.use_mysql:
                if not self.conn.is_connected():
                    self.connect()
                return self.conn.cursor(dictionary=True)
            else:
                return self.conn.cursor()
        except Exception:
            self.connect()
            if self.use_mysql:
                return self.conn.cursor(dictionary=True)
            else:
                return self.conn.cursor()

    def commit(self):
        if self.conn:
            self.conn.commit()

    def close(self):
        if self.conn:
            self.conn.close()

    def initialize_schema(self):
        """Reads schema.sql and creates tables if they don't exist."""
        # Absolute path relative to database.py file
        schema_path = Path(__file__).parent.parent / "schema.sql"
        if not schema_path.exists():
            schema_path = Path("schema.sql")
        if not schema_path.exists():
            schema_path = Path("../schema.sql")
            
        if not schema_path.exists():
            print("[!] schema.sql not found. Table creation skipped.")
            return

        with open(schema_path, "r") as f:
            schema_sql = f.read()

        cursor = self.get_cursor()
        if self.use_mysql:
            # Adapt schema.sql for MySQL syntax
            mysql_schema = schema_sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "INT AUTO_INCREMENT PRIMARY KEY")
            mysql_schema = mysql_schema.replace("AUTOINCREMENT", "AUTO_INCREMENT")
            # MySQL might not support CREATE TABLE with AUTOINCREMENT in SQLite syntax directly
            # Execute multiple statements by splitting
            statements = [s.strip() for s in mysql_schema.split(";") if s.strip()]
            for statement in statements:
                try:
                    cursor.execute(statement)
                except Exception as e:
                    print(f"[!] Error executing statement: {e}")
            self.commit()
        else:
            # SQLite supports executing script directly
            try:
                # sqlite3 cursor doesn't have executescript in standard format, but connection does
                self.conn.executescript(schema_sql)
                self.commit()
            except Exception as e:
                print(f"[!] SQLite schema initialization error: {e}")

    def execute(self, query, params=None):
        """Executes a query and commits it (for INSERT/UPDATE/DELETE)."""
        cursor = self.get_cursor()
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            self.commit()
            # Return last inserted row ID
            if self.use_mysql:
                return cursor.lastrowid
            else:
                return cursor.lastrowid
        except Exception as e:
            print(f"[!] Database execution error: {e}")
            raise e

    def fetch_all(self, query, params=None):
        """Executes a SELECT query and returns all rows."""
        cursor = self.get_cursor()
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            rows = cursor.fetchall()
            if self.use_mysql:
                return rows
            else:
                # Convert SQLite sqlite3.Row to dict
                return [dict(row) for row in rows]
        except Exception as e:
            print(f"[!] Database fetch_all error: {e}")
            return []

    def fetch_one(self, query, params=None):
        """Executes a SELECT query and returns a single row."""
        cursor = self.get_cursor()
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            row = cursor.fetchone()
            if row is None:
                return None
            if self.use_mysql:
                return row
            else:
                return dict(row)
        except Exception as e:
            print(f"[!] Database fetch_one error: {e}")
            return None

    # App-specific database operations

    def insert_user(self, username, role, clearance_level):
        """Inserts a new user."""
        query = """
        INSERT OR IGNORE INTO users (username, role, clearance_level)
        VALUES (?, ?, ?)
        """
        if self.use_mysql:
            query = query.replace("INSERT OR IGNORE", "INSERT IGNORE")
            query = query.replace("?", "%s")
        return self.execute(query, (username, role, clearance_level))

    def insert_query_log(self, username, session_id, query_type, query_text, 
                         tables_accessed, rows_affected, bytes_returned, 
                         execution_time_ms, is_failed, error_message, timestamp=None):
        """Inserts a query log entry."""
        if timestamp is None:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        query = """
        INSERT INTO queries_log (username, session_id, query_type, query_text, 
                                 tables_accessed, rows_affected, bytes_returned, 
                                 execution_time_ms, is_failed, error_message, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        if self.use_mysql:
            query = query.replace("?", "%s")
            
        params = (username, session_id, query_type, query_text, tables_accessed, 
                  rows_affected, bytes_returned, execution_time_ms, is_failed, 
                  error_message, timestamp)
        return self.execute(query, params)

    def insert_alert(self, username, threat_score, confidence_score, uncertainty_score, 
                     alert_level, description, explanation, recommended_action, timestamp=None):
        """Inserts a new security alert."""
        if timestamp is None:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        query = """
        INSERT INTO alerts (username, threat_score, confidence_score, uncertainty_score, 
                            alert_level, description, explanation, recommended_action, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        if self.use_mysql:
            query = query.replace("?", "%s")
            
        params = (username, threat_score, confidence_score, uncertainty_score, 
                  alert_level, description, explanation, recommended_action, timestamp)
        return self.execute(query, params)

    def insert_feedback(self, alert_id, admin_username, feedback_type, comments):
        """Inserts administrator feedback."""
        query = """
        INSERT INTO feedback (alert_id, admin_username, feedback_type, comments)
        VALUES (?, ?, ?, ?)
        """
        if self.use_mysql:
            query = query.replace("?", "%s")
            
        # Also update the alert status based on feedback
        self.execute(query, (alert_id, admin_username, feedback_type, comments))
        
        status = 'FALSE_POSITIVE' if feedback_type == 'FALSE_POSITIVE' else 'CONFIRMED_THREAT'
        update_query = "UPDATE alerts SET status = ? WHERE id = ?"
        if self.use_mysql:
            update_query = update_query.replace("?", "%s")
        self.execute(update_query, (status, alert_id))

    def get_user_profile(self, username):
        """Retrieves a user profile baseline."""
        query = "SELECT * FROM user_profiles WHERE username = ?"
        if self.use_mysql:
            query = query.replace("?", "%s")
        return self.fetch_one(query, (username,))

    def save_user_profile(self, username, profile_data_dict):
        """Saves or updates a user profile baseline."""
        # Check if profile exists
        profile = self.get_user_profile(username)
        
        # Serialize baseline dict to profile_data JSON
        profile_json = json.dumps(profile_data_dict)
        
        if profile:
            # Update
            query = """
            UPDATE user_profiles 
            SET last_updated = CURRENT_TIMESTAMP,
                query_count_mean = ?, query_count_std = ?,
                failed_logins_mean = ?, sensitive_access_mean = ?,
                privileged_ops_mean = ?, bytes_returned_mean = ?,
                execution_time_mean = ?, off_hours_ratio = ?,
                profile_data = ?
            WHERE username = ?
            """
            params = (
                profile_data_dict.get('query_count_mean', 0.0),
                profile_data_dict.get('query_count_std', 1.0),
                profile_data_dict.get('failed_logins_mean', 0.0),
                profile_data_dict.get('sensitive_access_mean', 0.0),
                profile_data_dict.get('privileged_ops_mean', 0.0),
                profile_data_dict.get('bytes_returned_mean', 0.0),
                profile_data_dict.get('execution_time_mean', 0.0),
                profile_data_dict.get('off_hours_ratio', 0.0),
                profile_json,
                username
            )
        else:
            # Insert
            query = """
            INSERT INTO user_profiles (username, query_count_mean, query_count_std,
                                       failed_logins_mean, sensitive_access_mean,
                                       privileged_ops_mean, bytes_returned_mean,
                                       execution_time_mean, off_hours_ratio, profile_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            params = (
                username,
                profile_data_dict.get('query_count_mean', 0.0),
                profile_data_dict.get('query_count_std', 1.0),
                profile_data_dict.get('failed_logins_mean', 0.0),
                profile_data_dict.get('sensitive_access_mean', 0.0),
                profile_data_dict.get('privileged_ops_mean', 0.0),
                profile_data_dict.get('bytes_returned_mean', 0.0),
                profile_data_dict.get('execution_time_mean', 0.0),
                profile_data_dict.get('off_hours_ratio', 0.0),
                profile_json
            )
            
        if self.use_mysql:
            query = query.replace("?", "%s")
        self.execute(query, params)

    def get_queries_log(self, username=None, limit=1000):
        """Fetches query logs, optionally filtered by user."""
        if username:
            query = "SELECT * FROM queries_log WHERE username = ? ORDER BY timestamp DESC LIMIT ?"
            if self.use_mysql:
                query = query.replace("?", "%s")
            return self.fetch_all(query, (username, limit))
        else:
            query = "SELECT * FROM queries_log ORDER BY timestamp DESC LIMIT ?"
            if self.use_mysql:
                query = query.replace("?", "%s")
            return self.fetch_all(query, (limit,))

    def get_alerts(self, status=None, limit=100):
        """Fetches alerts, optionally filtered by status."""
        if status:
            query = "SELECT * FROM alerts WHERE status = ? ORDER BY timestamp DESC LIMIT ?"
            if self.use_mysql:
                query = query.replace("?", "%s")
            return self.fetch_all(query, (status, limit))
        else:
            query = "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?"
            if self.use_mysql:
                query = query.replace("?", "%s")
            return self.fetch_all(query, (limit,))
            
    def get_all_users(self):
        """Retrieves list of all users."""
        query = "SELECT * FROM users"
        return self.fetch_all(query)
