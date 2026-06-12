import os
import random
import time
import json
import datetime
from pathlib import Path
from src.database import DatabaseManager

# Sensitive tables that require high clearance or are restricted
SENSITIVE_TABLES = ["salaries", "credentials", "credit_cards", "hr_files", "audit_logs"]

# Common database tables for normal queries
NORMAL_TABLES = ["products", "orders", "customers", "inventory", "sales", "departments", "employees", "tickets"]

class DatabaseSimulator:
    def __init__(self, db_manager):
        self.db = db_manager
        self.log_file = Path("data/mysql_audit.log")
        os.makedirs("data", exist_ok=True)
        self.init_users()

    def init_users(self):
        """Pre-populates the database with users and roles."""
        users_to_create = [
            ("alice_hr", "HR", 3),
            ("bob_dev", "Developer", 2),
            ("charlie_analyst", "Analyst", 4),
            ("service_acc", "ServiceAccount", 5),
            ("stranger_danger", "Guest", 1)
        ]
        for username, role, clearance in users_to_create:
            self.db.insert_user(username, role, clearance)

    def write_to_audit_log(self, log_entry):
        """Appends log entry to raw audit log file (simulating mysql audit plugin)."""
        with open(self.log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

    def generate_random_timestamp(self, user, hour_override=None, is_off_hours=False):
        """Generates a timestamp. If is_off_hours, creates a time between 11 PM and 5 AM."""
        now = datetime.datetime.now()
        if is_off_hours:
            hour = random.choice([23, 0, 1, 2, 3, 4])
        elif hour_override is not None:
            hour = hour_override
        else:
            # Normal working hours (9 AM - 6 PM) for human users, 24/7 for service account
            if user == "service_acc":
                hour = random.randint(0, 23)
            else:
                hour = random.choice([9, 10, 11, 12, 13, 14, 15, 16, 17, 18])
                
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        # Generate date within the last 7 days
        days_ago = random.randint(0, 7)
        timestamp = now - datetime.timedelta(days=days_ago)
        timestamp = timestamp.replace(hour=hour, minute=minute, second=second)
        return timestamp.strftime("%Y-%m-%d %H:%M:%S")

    def generate_normal_queries(self, user, session_id, count=10, timestamp_override=None):
        """Generates normal query sequence based on user role."""
        logs = []
        role_profile = self.db.get_user_profile(user)
        
        for _ in range(count):
            # Select table based on user role
            if user == "alice_hr":
                table = random.choice(["employees", "departments", "hr_files"])
                query_type = random.choice(["SELECT", "SELECT", "INSERT", "UPDATE"])
                bytes_returned = random.randint(200, 2000)
                execution_time = random.randint(5, 50)
            elif user == "bob_dev":
                table = random.choice(["products", "inventory", "tickets"])
                query_type = random.choice(["SELECT", "UPDATE", "INSERT", "DELETE"])
                bytes_returned = random.randint(100, 1500)
                execution_time = random.randint(2, 30)
            elif user == "charlie_analyst":
                table = random.choice(["sales", "orders", "customers"])
                query_type = "SELECT" # Analysts mostly read
                bytes_returned = random.randint(2000, 50000) # Analyst downloads more data
                execution_time = random.randint(50, 400)
            elif user == "service_acc":
                table = "inventory"
                query_type = "SELECT"
                bytes_returned = 512
                execution_time = 3
            else:
                table = "products"
                query_type = "SELECT"
                bytes_returned = 50
                execution_time = 2

            # Formulate query text
            if query_type == "SELECT":
                query_text = f"SELECT * FROM {table} WHERE id = {random.randint(1, 1000)}"
            elif query_type == "INSERT":
                query_text = f"INSERT INTO {table} (status, updated_at) VALUES ('ACTIVE', NOW())"
            elif query_type == "UPDATE":
                query_text = f"UPDATE {table} SET last_modified = NOW() WHERE id = {random.randint(1, 100)}"
            elif query_type == "DELETE":
                query_text = f"DELETE FROM {table} WHERE id = {random.randint(1000, 2000)}"

            timestamp = timestamp_override or self.generate_random_timestamp(user)
            
            log_entry = {
                "username": user,
                "session_id": session_id,
                "timestamp": timestamp,
                "query_type": query_type,
                "query_text": query_text,
                "tables_accessed": table,
                "rows_affected": 1 if query_type != "SELECT" else random.randint(1, 100),
                "bytes_returned": bytes_returned,
                "execution_time_ms": execution_time,
                "is_failed": 0,
                "error_message": ""
            }
            logs.append(log_entry)
            self.write_to_audit_log(log_entry)
            
        return logs

    def generate_baseline_data(self, num_sessions=50):
        """Generates a large history of normal queries to train models on."""
        print(f"[*] Generating {num_sessions} normal user sessions for baselines...")
        users = ["alice_hr", "bob_dev", "charlie_analyst", "service_acc"]
        
        # Clear log file first
        if self.log_file.exists():
            self.log_file.unlink()
            
        total_queries = 0
        for user in users:
            for s in range(num_sessions):
                session_id = f"sess_{user}_{s:04d}"
                # Service accounts are regular. Humans query mostly during day.
                timestamp_override = None
                if user == "service_acc":
                    # Generate spreads across all hours
                    timestamp_override = self.generate_random_timestamp(user, hour_override=s % 24)
                
                # Queries count
                q_count = random.randint(5, 25) if user != "service_acc" else 2
                logs = self.generate_normal_queries(user, session_id, q_count, timestamp_override)
                
                # Also directly write baseline history to database for UBA features
                for log in logs:
                    self.db.insert_query_log(
                        username=log["username"],
                        session_id=log["session_id"],
                        query_type=log["query_type"],
                        query_text=log["query_text"],
                        tables_accessed=log["tables_accessed"],
                        rows_affected=log["rows_affected"],
                        bytes_returned=log["bytes_returned"],
                        execution_time_ms=log["execution_time_ms"],
                        is_failed=log["is_failed"],
                        error_message=log["error_message"],
                        timestamp=log["timestamp"]
                    )
                total_queries += len(logs)
                
        print(f"[+] Successfully wrote {total_queries} queries to {self.log_file} and database.")

    def trigger_threat_scenario(self, scenario_name):
        """Triggers a specific insider threat scenario log entry."""
        session_id = f"threat_sess_{int(time.time())}"
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logs = []

        if scenario_name == "mass_data_exfiltration":
            # HR user Alice suddenly downloads large volume of salaries off-hours
            user = "alice_hr"
            timestamp = self.generate_random_timestamp(user, is_off_hours=True)
            for i in range(15):
                log_entry = {
                    "username": user,
                    "session_id": session_id,
                    "timestamp": timestamp,
                    "query_type": "SELECT",
                    "query_text": f"SELECT * FROM salaries LIMIT 100000 OFFSET {i * 10000}",
                    "tables_accessed": "salaries",
                    "rows_affected": 10000,
                    "bytes_returned": 1024 * 1024 * 3, # 3MB per query
                    "execution_time_ms": random.randint(800, 1500), # Long query
                    "is_failed": 0,
                    "error_message": ""
                }
                logs.append(log_entry)
                
        elif scenario_name == "privilege_escalation":
            # Developer Bob tries to grant himself root privileges and modify tables
            user = "bob_dev"
            # Attempt 1: sensitive table access
            log_entry1 = {
                "username": user,
                "session_id": session_id,
                "timestamp": timestamp,
                "query_type": "SELECT",
                "query_text": "SELECT * FROM credentials",
                "tables_accessed": "credentials",
                "rows_affected": 0,
                "bytes_returned": 0,
                "execution_time_ms": 5,
                "is_failed": 1,
                "error_message": "Access denied for table 'credentials'"
            }
            logs.append(log_entry1)
            # Attempt 2: privilege grant
            log_entry2 = {
                "username": user,
                "session_id": session_id,
                "timestamp": timestamp,
                "query_type": "GRANT",
                "query_text": "GRANT ALL PRIVILEGES ON *.* TO 'bob_dev'@'%'",
                "tables_accessed": "*.*",
                "rows_affected": 0,
                "bytes_returned": 0,
                "execution_time_ms": 10,
                "is_failed": 1,
                "error_message": "Access denied; you need the GRANT OPTION privilege for this operation"
            }
            logs.append(log_entry2)
            # Attempt 3: alter credentials table
            log_entry3 = {
                "username": user,
                "session_id": session_id,
                "timestamp": timestamp,
                "query_type": "ALTER",
                "query_text": "ALTER TABLE credentials ADD COLUMN backdoor VARCHAR(100)",
                "tables_accessed": "credentials",
                "rows_affected": 0,
                "bytes_returned": 0,
                "execution_time_ms": 8,
                "is_failed": 1,
                "error_message": "Table modification denied"
            }
            logs.append(log_entry3)

        elif scenario_name == "sql_injection":
            # Charlie the analyst performs suspicious queries with SQL Injection signatures
            user = "charlie_analyst"
            queries = [
                "SELECT * FROM customers WHERE customer_id = 1 OR '1'='1'",
                "SELECT * FROM sales UNION SELECT username, password, NULL FROM credentials",
                "SELECT * FROM transactions WHERE card_number = '' OR 1=1 --",
            ]
            for i, q in enumerate(queries):
                log_entry = {
                    "username": user,
                    "session_id": session_id,
                    "timestamp": timestamp,
                    "query_type": "SELECT",
                    "query_text": q,
                    "tables_accessed": "customers" if i==0 else ("sales,credentials" if i==1 else "transactions"),
                    "rows_affected": random.randint(10, 100),
                    "bytes_returned": random.randint(5000, 100000),
                    "execution_time_ms": random.randint(30, 200),
                    "is_failed": 0,
                    "error_message": ""
                }
                logs.append(log_entry)

        elif scenario_name == "off_hours_burst":
            # Charlie logs in at 3 AM and executes a burst of queries
            user = "charlie_analyst"
            timestamp = self.generate_random_timestamp(user, is_off_hours=True)
            for _ in range(40): # Huge frequency burst
                log_entry = {
                    "username": user,
                    "session_id": session_id,
                    "timestamp": timestamp,
                    "query_type": "SELECT",
                    "query_text": "SELECT * FROM sales LIMIT 500",
                    "tables_accessed": "sales",
                    "rows_affected": 500,
                    "bytes_returned": 25000,
                    "execution_time_ms": 12,
                    "is_failed": 0,
                    "error_message": ""
                }
                logs.append(log_entry)

        elif scenario_name == "hijacked_service_account":
            # Automated service account suddenly behaves like a human analyst:
            # accesses sensitive tables, off-hours, runs heavy queries, gets access denied
            user = "service_acc"
            timestamp = self.generate_random_timestamp(user, is_off_hours=True)
            log_entry1 = {
                "username": user,
                "session_id": session_id,
                "timestamp": timestamp,
                "query_type": "SELECT",
                "query_text": "SELECT * FROM hr_files LIMIT 5000",
                "tables_accessed": "hr_files",
                "rows_affected": 0,
                "bytes_returned": 0,
                "execution_time_ms": 10,
                "is_failed": 1,
                "error_message": "Access denied for user 'service_acc'"
            }
            logs.append(log_entry1)
            log_entry2 = {
                "username": user,
                "session_id": session_id,
                "timestamp": timestamp,
                "query_type": "DROP",
                "query_text": "DROP TABLE audit_logs",
                "tables_accessed": "audit_logs",
                "rows_affected": 0,
                "bytes_returned": 0,
                "execution_time_ms": 15,
                "is_failed": 1,
                "error_message": "Access denied; cannot drop administrative table"
            }
            logs.append(log_entry2)

        elif scenario_name == "repeated_failed_logins":
            # A guest user tries to brute force login/access
            user = "stranger_danger"
            for _ in range(10):
                log_entry = {
                    "username": user,
                    "session_id": session_id,
                    "timestamp": timestamp,
                    "query_type": "LOGIN",
                    "query_text": "CONNECT TO mysql",
                    "tables_accessed": "",
                    "rows_affected": 0,
                    "bytes_returned": 0,
                    "execution_time_ms": 1,
                    "is_failed": 1,
                    "error_message": "Access denied for user 'stranger_danger'@'localhost' (using password: YES)"
                }
                logs.append(log_entry)
                
        # Write to file
        for log in logs:
            self.write_to_audit_log(log)
            
        print(f"[+] Triggered threat scenario: {scenario_name} ({len(logs)} queries logged).")
        return logs
