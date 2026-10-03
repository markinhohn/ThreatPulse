CREATE TABLE vulnerabilities (
    cve_id TEXT PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    vendor TEXT NOT NULL CHECK (length(trim(vendor)) > 0),
    product TEXT NOT NULL CHECK (length(trim(product)) > 0),
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    description TEXT NOT NULL CHECK (length(trim(description)) > 0)
);

CREATE TABLE kev_entries (
    cve_id TEXT PRIMARY KEY REFERENCES vulnerabilities(cve_id),
    date_added DATE NOT NULL,
    required_action TEXT NOT NULL CHECK (length(trim(required_action)) > 0),
    due_date DATE NOT NULL,
    ransomware_use TEXT NOT NULL CHECK (ransomware_use IN ('Known', 'Unknown')),
    notes TEXT,
    source_url TEXT NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL,
    raw_record JSONB NOT NULL CHECK (jsonb_typeof(raw_record) = 'object')
);
