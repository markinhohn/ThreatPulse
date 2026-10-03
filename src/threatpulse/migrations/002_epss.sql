CREATE TABLE epss_observations (
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id),
    score_date DATE NOT NULL,
    epss NUMERIC NOT NULL CHECK (epss >= 0 AND epss <= 1),
    percentile NUMERIC NOT NULL CHECK (percentile >= 0 AND percentile <= 1),
    source_url TEXT NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL,
    raw_record JSONB NOT NULL CHECK (jsonb_typeof(raw_record) = 'object'),
    PRIMARY KEY (cve_id, score_date)
);
