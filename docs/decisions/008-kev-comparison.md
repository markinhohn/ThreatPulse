# Decision: frozen NVD publication cohorts for KEV/non-KEV comparison

Use all NVD CVEs in a user-selected, half-open UTC publication window of at most
120 days. Classify both cohorts inside that same interval, rather than comparing
the whole historic KEV catalog to the first NVD page. Request every page with no
KEV filter. Reject over-cap windows rather than silently truncating them. Reuse
NVD's authenticated/public pacing, retries, header-only keys, parser, and CVSS
validation. Preserve raw source records and request provenance.

Fetch CISA after NVD collection and freeze its full membership identifier list
and timestamp. CISA-present non-rejected CVEs are KEV. Absent CVEs without NVD
CISA metadata are non-KEV; absence is not proof of no exploitation. Quarantine
positive NVD/CISA disagreements and rejected records, preserving and counting
them for audit. Retain unscored and awaiting-analysis CVEs to make missingness
visible. Enrich the union of eligible groups through one explicitly dated EPSS
collection. Validate that observed and missing identifiers partition the union
exactly and that all returned score dates match the study definition.

Keep study data separate from the current vulnerability/dashboard cohort using
migration 5's comparison_studies table. Insert a complete validated JSONB study
atomically, with a UUID and definition. No partial collection is stored and no
existing study is overwritten. Use the shared ingestion session lock throughout
collection and persistence. Retries refetch the complete study; report failures
after persistence recover by study ID. Read stored studies without migrations
or writes. Existing daily and manual ingestion semantics remain applicable to
their existing tables.

Produce standalone HTML with explicit coverage, scored-group-normalized EPSS
and version-specific CVSS histograms, descriptive summaries, median differences,
and selection limitations. Export full CSV data, original source JSON, analysis
JSON, SVG/PNG figures, and a checksum/version manifest. Canonical JSON keeps
replay hashes stable across JSONB roundtrips. Missing scores, absent groups, and
unavailable differences remain unknown. Do not pool CVSS versions or introduce
significance tests, causal claims, or prioritization weights.

Document cohort age, exposure/vendor confounding, unknown exploitation among
non-KEV records, source disagreement, historical membership versus score date,
analysis maturity, score coverage, EPSS model revisions, bounded in-memory
collection, and upstream pagination limitations. Publication-window cohorts
are defined samples, not representative controls or prediction-validation sets.

Validation covers full NVD paging, UTC boundaries, duplicate/partial/changed
pages, cap rejection, later-page failures, classification/exclusions, same-date
union requests, coverage partitions, zero/100% scores, version separation,
normalized denominators, empty groups, database roundtrip, duplicate-ID rejection,
no dashboard contamination, upgrade preservation, CLI overlap/failure, offline
replay, deterministic SVGs, escaped HTML, hashes, and exclusive destinations.
The synthetic preview demonstrates behavior only; live findings require a
configured database and access to the three official sources.
