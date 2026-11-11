-- Prospective research storage. No non-KEV rows enter dashboard tables.
CREATE TABLE tracking_cohorts (
    cohort_id UUID PRIMARY KEY,
    definition JSONB NOT NULL CHECK (jsonb_typeof(definition) = 'object'),
    definition_sha256 TEXT NOT NULL UNIQUE CHECK (definition_sha256 ~ '^[a-f0-9]{64}$'),
    label TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE tracking_registry (
    cve_id TEXT PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    first_seen_at TIMESTAMPTZ NOT NULL,
    origin TEXT NOT NULL CHECK (origin IN ('nvd_window', 'kev', 'legacy_kev'))
);
CREATE TABLE tracking_runs (
    run_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('enrollment', 'daily')),
    cohort_id UUID REFERENCES tracking_cohorts,
    run_date DATE NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed', 'interrupted')),
    error_type TEXT,
    CHECK ((kind = 'enrollment') = (cohort_id IS NOT NULL))
);
CREATE UNIQUE INDEX tracking_one_enrollment ON tracking_runs(cohort_id) WHERE kind = 'enrollment';
CREATE UNIQUE INDEX tracking_one_daily_date ON tracking_runs(run_date) WHERE kind = 'daily';
CREATE TABLE tracking_attempts (
    attempt_id UUID PRIMARY KEY,
    run_id BIGINT NOT NULL REFERENCES tracking_runs,
    stage TEXT NOT NULL CHECK (stage IN ('census', 'discovery', 'plan', 'epss', 'nvd', 'final_kev')),
    requested_ids JSONB NOT NULL CHECK (jsonb_typeof(requested_ids) = 'array'),
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed', 'interrupted')),
    error_type TEXT,
    UNIQUE (attempt_id, run_id, stage)
);
CREATE TABLE tracking_requests (
    request_id UUID PRIMARY KEY,
    attempt_id UUID NOT NULL REFERENCES tracking_attempts,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    source_url TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    UNIQUE (attempt_id, ordinal)
);
CREATE TABLE tracking_responses (
    request_id UUID PRIMARY KEY REFERENCES tracking_requests,
    received_at TIMESTAMPTZ NOT NULL,
    status_code INTEGER NOT NULL CHECK (status_code BETWEEN 100 AND 599),
    body_sha256 TEXT NOT NULL CHECK (body_sha256 ~ '^[a-f0-9]{64}$'),
    -- Exact public success-response bytes, including malformed 2xx responses.
    -- Error response bodies and all HTTP headers are deliberately omitted.
    body_base64 TEXT,
    CHECK ((status_code BETWEEN 200 AND 299) = (body_base64 IS NOT NULL))
);
CREATE TABLE tracking_observations (
    observation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    attempt_id UUID NOT NULL REFERENCES tracking_attempts,
    source TEXT NOT NULL CHECK (source IN ('kev', 'nvd', 'epss')),
    cve_id TEXT NOT NULL REFERENCES tracking_registry,
    state TEXT NOT NULL CHECK (state IN ('observed', 'missing')),
    captured_at TIMESTAMPTZ NOT NULL,
    available_at TIMESTAMPTZ NOT NULL,
    source_url TEXT NOT NULL,
    observation JSONB,
    observation_sha256 TEXT,
    raw_sha256 TEXT,
    UNIQUE (attempt_id, cve_id),
    CHECK (available_at >= captured_at),
    CHECK (
        (state = 'missing' AND observation IS NULL
         AND observation_sha256 IS NULL AND raw_sha256 IS NULL)
        OR (state = 'observed' AND observation IS NOT NULL
            AND observation_sha256 IS NOT NULL AND raw_sha256 IS NOT NULL
            AND jsonb_typeof(observation) = 'object'
            AND observation_sha256 ~ '^[a-f0-9]{64}$'
            AND raw_sha256 ~ '^[a-f0-9]{64}$')
    )
);
CREATE INDEX tracking_cve_history ON tracking_observations(cve_id, source, available_at);
CREATE TABLE tracking_checkpoints (
    run_id BIGINT NOT NULL REFERENCES tracking_runs,
    stage TEXT NOT NULL,
    attempt_id UUID NOT NULL UNIQUE REFERENCES tracking_attempts,
    available_at TIMESTAMPTZ NOT NULL,
    metadata JSONB NOT NULL CHECK (jsonb_typeof(metadata) = 'object'),
    PRIMARY KEY (run_id, stage),
    FOREIGN KEY (attempt_id, run_id, stage)
        REFERENCES tracking_attempts(attempt_id, run_id, stage)
);
CREATE TABLE tracking_run_members (
    run_id BIGINT NOT NULL REFERENCES tracking_runs,
    cve_id TEXT NOT NULL REFERENCES tracking_registry,
    PRIMARY KEY (run_id, cve_id)
);
CREATE TABLE tracking_memberships (
    cohort_id UUID NOT NULL REFERENCES tracking_cohorts,
    cve_id TEXT NOT NULL REFERENCES tracking_registry,
    census_observation_id BIGINT NOT NULL REFERENCES tracking_observations,
    baseline_attempt_id UUID NOT NULL REFERENCES tracking_attempts,
    baseline_at TIMESTAMPTZ NOT NULL,
    eligibility TEXT NOT NULL CHECK (eligibility IN ('eligible', 'excluded')),
    exclusion_reasons JSONB NOT NULL CHECK (jsonb_typeof(exclusion_reasons) = 'array'),
    PRIMARY KEY (cohort_id, cve_id)
);

-- Application-level history is append-only even for ordinary direct SQL writes.
-- Database administrators can disable triggers; these are not digital signatures.
CREATE FUNCTION tracking_reject_mutation() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Tracking history is append-only' USING ERRCODE = '55000';
END;
$$;
DO $$
DECLARE relation_name TEXT;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY[
        'tracking_cohorts', 'tracking_registry', 'tracking_requests',
        'tracking_responses', 'tracking_observations', 'tracking_checkpoints',
        'tracking_run_members', 'tracking_memberships'
    ] LOOP
        EXECUTE format('CREATE TRIGGER immutable_rows BEFORE UPDATE OR DELETE ON %I '
                       'FOR EACH ROW EXECUTE FUNCTION tracking_reject_mutation()', relation_name);
        EXECUTE format('CREATE TRIGGER immutable_truncate BEFORE TRUNCATE ON %I '
                       'FOR EACH STATEMENT EXECUTE FUNCTION tracking_reject_mutation()', relation_name);
    END LOOP;
END;
$$;
