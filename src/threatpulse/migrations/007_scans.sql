CREATE TABLE scan_imports (
    scan_id UUID PRIMARY KEY,
    imported_at TIMESTAMPTZ NOT NULL,
    scanner TEXT NOT NULL CHECK (scanner IN ('nessus','openvas','nmap')),
    format TEXT NOT NULL CHECK (format IN ('xml','csv')),
    filename TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    raw_bytes BYTEA NOT NULL CHECK (octet_length(raw_bytes) BETWEEN 1 AND 26214400),
    dataset JSONB NOT NULL CHECK (jsonb_typeof(dataset)='object'),
    dataset_sha256 TEXT NOT NULL,
    CHECK (encode(sha256(raw_bytes),'hex')=raw_sha256)
);
CREATE TABLE scan_assessments (
    assessment_id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scan_imports,
    decision_at TIMESTAMPTZ NOT NULL,
    dataset JSONB NOT NULL CHECK (jsonb_typeof(dataset)='object'),
    dataset_sha256 TEXT NOT NULL
);
CREATE INDEX scan_assessments_scan_date ON scan_assessments(scan_id,decision_at DESC);
CREATE FUNCTION scan_reject_mutation() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Scan history is append-only' USING ERRCODE='55000';
END;
$$;
CREATE TRIGGER immutable_rows BEFORE UPDATE OR DELETE ON scan_imports
FOR EACH ROW EXECUTE FUNCTION scan_reject_mutation();
CREATE TRIGGER immutable_truncate BEFORE TRUNCATE ON scan_imports
FOR EACH STATEMENT EXECUTE FUNCTION scan_reject_mutation();
CREATE TRIGGER immutable_rows BEFORE UPDATE OR DELETE ON scan_assessments
FOR EACH ROW EXECUTE FUNCTION scan_reject_mutation();
CREATE TRIGGER immutable_truncate BEFORE TRUNCATE ON scan_assessments
FOR EACH STATEMENT EXECUTE FUNCTION scan_reject_mutation();
