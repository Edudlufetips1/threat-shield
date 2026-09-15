CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    source TEXT,
    date TIMESTAMP,
    ransomware_use TEXT,
    due_date TEXT,
    threat_index DOUBLE PRECISION
);

CREATE TABLE IF NOT EXISTS vulnerability_history (
    id BIGSERIAL PRIMARY KEY,           
    cve_id TEXT NOT NULL,              
    title TEXT NOT NULL,
    description TEXT,
    source TEXT,
    date_added TIMESTAMP,
    ransomware_use TEXT,
    due_date TEXT,
    threat_index DOUBLE PRECISION,
    observed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);