# Decision: enrich stored CVEs with dated FIRST EPSS observations

## Purpose and source

KEV records identify known exploitation but do not estimate future exploitation
probability. FIRST publishes EPSS estimates for exploitation over the next 30
days, plus relative percentiles. Use its official public API:
<https://api.first.org/data/v1/epss>. Reference documentation:
<https://www.first.org/epss/api>.

We request only CVEs already stored in ThreatPulse instead of downloading all
scored vulnerabilities. This keeps the initial integration aligned with the KEV
workflow. No API credentials are needed. The initial cloud request was blocked
by the proxy; an additive `api.first.org` network allowance was saved, preserving
existing allowed domains. Subsequent live collection succeeded.

## Collection contract

CVE filters are chunked at 1,200 characters, below FIRST's 2,000-character
filter limit and small enough for encoded request URLs retained as provenance.
Each chunk requests a limit equal to its CVE count. We reject a total count
different from the returned rows or a nonzero offset rather than silently losing
scores to pagination. Unknown CVEs can be omitted by FIRST and are reported
explicitly; missing scores are not zero and do not delete prior observations.

The first returned observation pins the score date for subsequent chunks unless
the caller supplies a historical date. Every returned score must match that
date and a requested CVE. Duplicate and malformed records fail the entire batch.
The collector gathers all observations before storage; later HTTP failures do
not leave partially enriched batches. TLS checks stay enabled, timeouts are
explicit, and retries remain a scheduler/caller responsibility.

## Storage and history

Migration 2 adds `epss_observations` with a foreign key to vulnerabilities and a
composite primary key `(cve_id, score_date)`. Decimal values and PostgreSQL
NUMERIC preserve the source precision, with application and database bounds of
0 through 1. Score date, ingestion timestamp, request URL, and raw JSONB records
are stored separately. Same-date reruns update rather than duplicate; later or
earlier dates retain separate observations. An advisory lock serializes EPSS
writers and the whole batch is committed atomically.

This is EPSS history, not general vulnerability or KEV snapshot history. It
does not schedule ingestion, backfill all dates, version same-date corrections,
or record a model-version identifier. Future trend analysis should account for
model changes and data coverage before interpreting score changes.

## Validation

Offline HTTP tests cover exact decimal parsing, missing data, chunking, date
pinning, invalid values, incomplete envelopes, duplicate/unrequested CVEs, HTTP
failures, malformed JSON, and a failure after a successful earlier chunk.
Real PostgreSQL tests cover same-date deduplication, score corrections,
multi-date history, database range checks, foreign-key rollback, and upgrading
migration 1 with existing KEV data preserved.

All 83 tests passed with real PostgreSQL enabled and no skips. Lint, formatting,
source and wheel builds passed; the wheel includes migration 2. Live current-date
ingestion processed 1,733 CVEs and a second run kept the count at 1,733. A request
for the preceding score date stored 1,732 observations and explicitly reported
`CVE-2026-104286` missing. Database queries confirmed two retained dates, no
duplicate CVE/date keys, no fabricated historical score for that CVE, and its
current-date observation preserved. Historical coverage can differ from current
coverage, so identical row counts across dates are not a readiness requirement.
