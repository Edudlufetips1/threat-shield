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