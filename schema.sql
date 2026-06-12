-- MySQL / SQLite compatible database schema for Insider Threat Detection Framework

-- Users and privileges
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    role VARCHAR(50) NOT NULL,
    clearance_level INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Real-time SQL activity log
CREATE TABLE IF NOT EXISTS queries_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL,
    session_id VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    query_type VARCHAR(20) NOT NULL, -- SELECT, INSERT, UPDATE, DELETE, ALTER, DROP, GRANT
    query_text TEXT NOT NULL,
    tables_accessed TEXT, -- Comma-separated list of tables
    rows_affected INT DEFAULT 0,
    bytes_returned INT DEFAULT 0,
    execution_time_ms INT DEFAULT 0,
    is_failed INT DEFAULT 0, -- 0 for success, 1 for fail
    error_message TEXT
);

-- Dynamically updated user behavior baselines
CREATE TABLE IF NOT EXISTS user_profiles (
    username VARCHAR(50) PRIMARY KEY,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    query_count_mean FLOAT DEFAULT 0.0,
    query_count_std FLOAT DEFAULT 1.0,
    failed_logins_mean FLOAT DEFAULT 0.0,
    sensitive_access_mean FLOAT DEFAULT 0.0,
    privileged_ops_mean FLOAT DEFAULT 0.0,
    bytes_returned_mean FLOAT DEFAULT 0.0,
    execution_time_mean FLOAT DEFAULT 0.0,
    off_hours_ratio FLOAT DEFAULT 0.0,
    profile_data TEXT -- JSON representation of extended baseline variables
);

-- Insider threat security alerts
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    threat_score FLOAT NOT NULL,
    confidence_score FLOAT NOT NULL,
    uncertainty_score FLOAT NOT NULL,
    alert_level VARCHAR(20) NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
    description TEXT NOT NULL,
    explanation TEXT, -- Feature contributions and why flagged
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, FALSE_POSITIVE, CONFIRMED_THREAT
    recommended_action TEXT
);

-- Admin feedback loop for online adaptive learning
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INT NOT NULL,
    admin_username VARCHAR(50) NOT NULL,
    feedback_type VARCHAR(20) NOT NULL, -- TRUE_POSITIVE, FALSE_POSITIVE
    comments TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(alert_id) REFERENCES alerts(id)
);
