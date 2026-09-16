CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    source TEXT,
    date DATE,
    ransomware_use TEXT,
    due_date DATE,
    threat_index DOUBLE PRECISION
);

CREATE TABLE IF NOT EXISTS vulnerability_history (
    id BIGSERIAL PRIMARY KEY,           
    cve_id TEXT NOT NULL,              
    title TEXT NOT NULL,
    description TEXT,
    source TEXT,
    date_added DATE,
    ransomware_use TEXT,
    due_date DATE,
    threat_index DOUBLE PRECISION,
    observed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE vulnerabilities
    ALTER COLUMN date TYPE DATE USING date::date,
    ALTER COLUMN due_date TYPE DATE USING due_date::date;

ALTER TABLE vulnerability_history
    ALTER COLUMN date_added TYPE DATE USING date_added::date,
    ALTER COLUMN due_date TYPE DATE USING due_date::date;