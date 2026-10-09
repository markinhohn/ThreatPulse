CREATE TABLE ingestion_runs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_date DATE NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed', 'interrupted')),
    error_type TEXT
);
CREATE INDEX ingestion_runs_date ON ingestion_runs (run_date, id DESC);
CREATE TABLE ingestion_steps (
    run_id BIGINT NOT NULL REFERENCES ingestion_runs(id),
    source TEXT NOT NULL CHECK (source IN ('kev', 'epss', 'nvd')),
    processed INTEGER NOT NULL CHECK (processed >= 0),
    missing_cves JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(missing_cves) = 'array'),
    finished_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, source)
);
-- Observations, not reconstructed source history. A run's rows are immutable.
CREATE TABLE kev_snapshots (
    run_id BIGINT NOT NULL REFERENCES ingestion_runs(id),
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id),
    observation JSONB NOT NULL CHECK (jsonb_typeof(observation) = 'object'),
    PRIMARY KEY (run_id, cve_id)
);
CREATE TABLE nvd_snapshots (
    run_id BIGINT NOT NULL REFERENCES ingestion_runs(id),
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id),
    observation JSONB NOT NULL CHECK (jsonb_typeof(observation) = 'object'),
    PRIMARY KEY (run_id, cve_id)
);
