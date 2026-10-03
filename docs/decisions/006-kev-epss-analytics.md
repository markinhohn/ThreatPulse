# Decision: add descriptive KEV and EPSS analytics with explicit coverage

## Scope

Build on the read-only Streamlit dashboard with dedicated KEV and EPSS tabs.
KEV counts use only stored KEV entries, grouped by source vendor label and by
vendor/product pair. Show top-ten charts and full tables. Pairing products with
vendors avoids conflating products with the same name. No alias normalization,
market-share adjustment, asset prevalence, or implied risk ranking is applied.

EPSS distribution and CVSS comparisons use each stored CVE's latest available
EPSS observation. This is a per-CVE latest view, not necessarily one common
score date. Probability and percentile remain distinct; these charts plot
probability. Missing scores never become zero. Fixed-width 10-point bins include
their lower bound, exclude the upper bound, and include 100% in the final bin.

The scatter plot uses complete score pairs from one preferred CVSS version at a
time. Default to the most represented version, retain fixed 0–10 and 0–100%
axes, and provide hover details. Altair is declared as a direct dependency
because the app imports it directly for chart encodings. Do not pool versions,
infer correlation, or introduce an undocumented prioritization formula.

## Dated changes and coverage

Use a parameterized full outer join between two selected observation dates.
Retain CVEs observed on only one date for coverage counts, while calculating
changes only for matched observations. A CVE absent on both dates is counted
relative to the stored dataset loaded for this dashboard rerun. Observations
inserted for new CVEs during that rerun are outside that cohort until refresh.

Compute differences with Decimal before converting to display floats:
`(later - earlier) * 100` is a percentage-point change. Show increases, decreases,
unchanged counts, and the full matched table ordered by signed change. Do not
fill missing observations from other dates, replace missing values with zero,
interpolate gaps, or convert differences to percent growth. Require at least two
recorded dates and enforce that the later date follows the earlier one.

These are descriptive changes rather than Threat Velocity: no time normalization,
model-change correction, or statistically validated alert threshold exists yet.
The current collection is KEV-based and does not support KEV versus non-KEV
analysis or claims about all CVEs. Current KEV membership and CVSS enrichment are
not historical attributes, and EPSS model-version history is not yet captured.

## Integration and limitations

Keep analytics independent of explorer filters. Extract explorer rendering into
its own function so an empty search result returns from that view without
preventing other tabs from rendering. Analytics queries remain read-only,
database errors use credential-free messages, and no new schema or ingestion
process is needed. The UI reads dates and two-date observations from PostgreSQL.

The initial dataset fits the existing in-memory dashboard workflow. Larger
cohorts will need query-side aggregation, pagination, and appropriate chart data
limits. Multiple queries can observe ingestion at slightly different times;
there is no dashboard-wide snapshot or automatic polling.

## Validation

Calculation tests cover zero, exact bin boundaries, 100%, missing EPSS, vendor
and product counts, non-KEV exclusions, version-specific pairs, positive/negative
changes, unchanged zero scores, and one-sided coverage. PostgreSQL tests cover
actual dates, exact-date pairing, one-sided observations, and invalid date order.
Streamlit tests cover analytics tabs, coverage captions, signed differences,
single-date messaging, and analytics visibility when explorer filters match no
records. Live validation checks count reconciliation and history coverage using
the existing collected dataset.

All 144 tests passed with real PostgreSQL enabled and no skips. Lint, formatting,
diff checks, source/wheel builds, and packaged analytics modules were verified.
Live vendor/product counts and EPSS bins reconciled to 1,733 stored CVEs. The
two-date comparison returned 1,732 matched observations, zero earlier-only,
and one later-only CVE. All four tabs rendered without errors, and the running
Streamlit service passed its health check. Interactive tests also verify later
date options update when the earlier selection changes, and all-missing EPSS
data displays as unknown rather than zero scores.
