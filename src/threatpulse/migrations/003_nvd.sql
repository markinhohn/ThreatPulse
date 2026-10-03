CREATE TABLE nvd_enrichments (
    cve_id TEXT PRIMARY KEY REFERENCES vulnerabilities(cve_id),
    published_at TIMESTAMPTZ NOT NULL,
    modified_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL,
    description TEXT,
    reference_urls JSONB NOT NULL CHECK (jsonb_typeof(reference_urls) = 'array'),
    weaknesses JSONB NOT NULL CHECK (jsonb_typeof(weaknesses) = 'array'),
    cvss_metrics JSONB NOT NULL CHECK (jsonb_typeof(cvss_metrics) = 'array'),
    cvss_version TEXT CHECK (cvss_version IN ('2.0', '3.0', '3.1', '4.0')),
    cvss_source TEXT,
    base_score NUMERIC CHECK (base_score >= 0 AND base_score <= 10),
    severity TEXT CHECK (severity IN ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    attack_vector TEXT CHECK (
        attack_vector IN ('NETWORK', 'ADJACENT_NETWORK', 'LOCAL', 'PHYSICAL')
    ),
    source_url TEXT NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL,
    raw_record JSONB NOT NULL CHECK (jsonb_typeof(raw_record) = 'object'),
    CHECK (
        (cvss_version IS NULL AND cvss_source IS NULL AND base_score IS NULL
         AND severity IS NULL AND attack_vector IS NULL)
        OR
        (cvss_version IS NOT NULL AND cvss_source IS NOT NULL AND base_score IS NOT NULL
         AND severity IS NOT NULL AND attack_vector IS NOT NULL)
    )
);
