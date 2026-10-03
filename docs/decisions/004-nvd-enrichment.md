# Decision: add official NVD enrichment without overwriting KEV data

## Purpose and source

KEV supplies known exploitation and EPSS estimates probability; NVD adds
vulnerability severity and technical context. Use the official NVD CVE API 2.0:
<https://services.nvd.nist.gov/rest/json/cves/2.0>. Reference documentation:
<https://nvd.nist.gov/developers/vulnerabilities> and
<https://nvd.nist.gov/developers/start-here>.

The initial API request was blocked by the environment proxy. Network allowances
for `services.nvd.nist.gov` and documentation host `nvd.nist.gov` were saved
additively, alongside an `NVD_API_KEY` secret requirement restricted to the API
hostname. Network access to the API subsequently worked. The documentation host
continued to return HTTP 403 during setup; live API responses and deterministic
tests verified the parameters actually used.

## Efficient requests and rate limits

Our initial stored CVEs come from KEV, so NVD's `hasKev` filter is much more
efficient than one request per stored CVE. Fetch pages of up to 2,000 results,
filter to stored targets, then look up unmatched CVEs with `cveId`. This also
supports future non-KEV stored targets without assuming that NVD's KEV membership
is identical to CISA's latest publication. Follow pagination, reject incomplete
pages or changed total counts, and fail the entire collection on invalid target
records or request failure. Missing CVEs remain explicit, never invented.

With a configured API key, request starts are spaced 0.65 seconds apart, below
50 requests per 30 seconds with a small safety margin. Without one, use 6.1
seconds for the 5-per-30-second public limit. Retry attempts are paced too.
There is no concurrent request fan-out; the page strategy removes most of the
time cost rather than spending quota on individual lookups. Rate coordination
with other processes or clients sharing the key/IP remains the operator's
responsibility. Three bounded retries handle transient failures, respecting
Retry-After and stopping for long cooldowns. Authentication failures never
trigger an automatic fallback to unauthenticated requests.

The key is read from `NVD_API_KEY` and sent only in the `apiKey` header. It is
never stored in raw data, URLs, documentation, or error messages. TLS checks
remain enabled.

## Models and metric selection

Retain NVD publication/modification timestamps, status, English description,
references, weaknesses, and all supported CVSS source metrics. Source timestamps
without an offset are interpreted as UTC, following NVD's timestamp convention.
Raw JSONB retains other details, including affected CPE configurations. CVSS
2.0/3.0/3.1/4.0 vectors are checked using the `cvss` library against reported
base score, severity, and attack vector; v4 base calculations exclude optional
threat/environmental modifiers. Missing scores remain unknown (NULL).

Choose the newest CVSS version, then Primary within that version, followed by a
stable source/vector tie-break. This is a display default, not a risk score or a
claim that scores across versions are interchangeable. Retain all metrics for
later analysis and alternative selection policies. Unknown future metric groups
remain in raw JSON but are not used for scoring until supported explicitly.

Live parsing required two compatibility adjustments: retain valid non-HTTP
reference URLs such as legacy FTP advisories, and normalize CVSS 3/4 `ADJACENT`
to the same `ADJACENT_NETWORK` label used for CVSS 2. Original values stay in raw
records. Regression tests cover both adjustments.

## PostgreSQL behavior

Migration 3 adds a CVE-keyed `nvd_enrichments` table with a foreign key to stored
vulnerabilities. All metrics are retained as JSONB; preferred score, version,
source, severity, and attack vector also have queryable columns. CVSS base scores
use NUMERIC, and range/nullability constraints reinforce the model contract.

Upserts refresh the latest snapshot without duplicating rows or changing KEV
vendor/product/description values. Older modification timestamps cannot replace
newer snapshots. If a newer snapshot no longer contains CVSS metrics, its chosen
score columns become NULL. Absent CVEs do not delete existing snapshots. A
transaction and advisory lock serialize NVD writes; any database failure rolls
back the whole batch. Processed count means handled records, including older
snapshots not applied. This step does not create NVD history, flatten CPE
applicability logic, or implement scoring and a dashboard.

## Validation

Tests cover supported CVSS versions, malformed vectors, inconsistent score and
severity, missing scores, source selection, legacy references, UTC dates,
paginated bulk requests, fallback lookups, key headers and environment injection,
authenticated rolling-window pacing, timeouts, HTTP failures, retry bounds,
Retry-After, malformed envelopes, duplicate CVEs, and partial-batch failure.
Real PostgreSQL tests cover repeat ingestion, updates, raw provenance, missing
scores, stale snapshot protection, constraints, foreign-key rollback, and
migration upgrades preserving KEV and EPSS records.

All 129 tests passed with real PostgreSQL integration enabled and no skips.
Ruff lint and formatting checks passed, and source/wheel builds succeeded with
migration 3 present in the wheel. Live API collection and the documented CLI
enriched all 1,733 stored CVEs with no missing records. Repeated writes kept
exactly 1,733 distinct NVD rows, preserving existing KEV and EPSS counts.
The selected CVSS versions were 3.0 for 4 CVEs, 3.1 for 1,631, and 4.0 for 98.

These live checks used public-rate access. The running machine still had no
`NVD_API_KEY`, and configuration metadata reported no saved binding at the last
check, despite the user's attempt to provide it. Authenticated header injection
and pacing are verified by offline tests; live authenticated access remains
pending secure binding/runtime injection. No key value was inspected or copied.
