# 012 — Quality-gated, replayable Threat Velocity

Status: implemented.

Implement policy v0.1's descriptive EPSS median pairwise slope over a trailing
seven-day interval, inclusive of eight possible source dates. Use elapsed
calendar days and exact rational arithmetic for eligibility; export rounded
display rates, endpoint changes, adjacent intervals, coverage, missing dates,
and every failed gate. Zero remains valid and missing data remains unknown.
The signal does not assign priorities or claim calibrated exploitation risk.

Require five observed dates, a four-day span, maximum adjacent gap of two days,
fresh latest probability at least 1%, endpoint rise at least five percentage
points, and slope at least 0.5 percentage points per day. An eligible rise is
consumed by the baseline engine for P3-to-P2 promotion. There are no automatic
trend downgrades. Thresholds remain provisional policy choices.

Model comparability is an explicit bounded review declaration with source-date
coverage, evidence, reviewer, and timestamp. Empty/unknown registries, gaps,
model boundaries, and post-decision reviews disable promotion. Do not infer
model identity from score stability or trim a boundary out of the chosen window.
Reject ambiguous overlapping regimes. These declarations are auditable operator
assertions rather than automatic provider verification.

Latest EPSS tables do not preserve same-date revisions; legacy collection times
do not establish immutable availability. Conservatively freeze database rows as
available at export completion and imported trend rows at their recorded capture.
Only independently validated capture inputs can assert earlier availability.
Exclude post-decision values and flag invalid future source dates. This adds no
schema migration and does not substitute for the planned longitudinal ML store.

Support database, frozen velocity input, and existing trend-export workflows.
Read PostgreSQL in REPEATABLE READ, READ ONLY without collection/migrations.
Publish standalone HTML, CSV/JSON, SVG/PNG, policy/source hashes, and a code/package
manifest. Preserve decision time and registry in replay inputs/metadata; require
a new output directory. Test arithmetic, thresholds, coverage, model/availability
gates, unknowns, empty reports, database isolation, and identical replay artifacts.

The baseline prioritization engine is implemented in [decision 013](013-baseline-priority-engine.md).
Dashboard integration, prospective
threshold validation, immutable non-KEV history, and local ML training remain
separate roadmap tasks. See [the usage guide](../threat-velocity.md).
