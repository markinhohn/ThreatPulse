# Decision: reproducible exploratory report with explicit date and cohort semantics

Add `python -m threatpulse.exploration` as a read-only CLI report exporter, leaving
the interactive dashboard unchanged. A standalone HTML report, CSV tables,
Matplotlib SVG/PNG figures, source JSON, analysis JSON, and checksum/version
manifest allow review and replay without a live database or network. Matplotlib
is a direct, locked dependency for portable standalone figures.

Use one REPEATABLE READ, READ ONLY PostgreSQL transaction for current CVE/NVD/KEV
attributes and all stored EPSS history. Querying the dashboard's independent
loaders would permit changing cohorts during concurrent ingestion. Do not run
migrations or collect data as a side effect of exploratory analysis.

Choose one common EPSS date (latest recorded by default) for distributions and
CVSS associations. This makes coverage and missingness explicit; per-CVE latest
scores would mix dates. Keep preferred CVSS versions separate. Calculate Pearson
and average-rank Spearman coefficients descriptively, suppressing them when
fewer than three complete pairs or a constant score series prevents meaningful
calculation. Three observations is a computation minimum only. Inferential
statistics and prioritization weights remain out of scope.

Historical comparisons use exact endpoint pairs, earliest/latest by default,
with explicit matched, earlier-only, later-only, and absent counts. Calculate
deltas with Decimal before conversion to display floats. Keep missing scores
unknown, report zero scores accurately, avoid filling gaps, and do not infer
Threat Velocity or exploitation. Export full changes, while the report displays
the first 20 in descending signed-change order.

Snapshots from the daily runner are observations, not a historical census of
non-KEV vulnerabilities. This initial exploration uses current attributes with
EPSS history; it does not fabricate historical CVSS/KEV cohorts or a KEV/non-KEV
control group. Document selection bias, EPSS model changes, source freshness,
current metric semantics, and in-memory scalability.

Validate exported input with Pydantic, including unique CVEs, unique CVE/date
observations, finite bounded scores, timezone-aware timestamps, and foreign
cohort references. Exclusive output directories prevent clobbering an earlier
export. Escape source labels and table text in HTML; omit credentials and raw
source payloads from analysis exports. Preserve input capture time on replay and
record selected dates, package versions, and artifact hashes for reproducibility.

Tests cover known positive/negative associations, constant scores, missing pairs,
zero scores, endpoint changes and coverage, empty/single-date datasets, invalid
inputs/dates, offline replay, unchanged deterministic SVGs, escaped labels,
exclusive destinations, and read-only repeatable-read behavior under concurrent
writes. The synthetic preview illustrates behavior only; actual findings require
an installed database populated with collected source data.
