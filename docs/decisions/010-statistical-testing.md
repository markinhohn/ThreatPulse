# 010 — Exploratory inference on frozen comparison studies

Status: accepted.

Use the existing frozen publication-window study as the analysis unit and keep
the descriptive comparison workflow separate. A dedicated read-only command
loads either source.json or one PostgreSQL study UUID, without new collection,
migration, or persistence. NumPy and SciPy are direct locked dependencies.

Predefine five two-sided rank endpoints: one exact-date EPSS comparison and one
for each preferred CVSS version. Require 20 scored CVEs per group by default
and pooled variation; preserve missingness, exclusions, and other-version counts.
The configurable threshold is a guardrail rather than a formal power calculation.
Classify and validate cohorts using the existing comparison rules.

Calibrate midpoint-rank Mann-Whitney U by exact label partitions when feasible,
otherwise seeded Monte Carlo with plus-one correction. This avoids inappropriate
normal or untied-exact approximations for highly tied/discrete CVSS values.
Report median differences, probability superiority, and Cliff's delta with
independent within-group percentile bootstrap intervals. Score-level counts and
bounded batches avoid quadratic pair arrays. Suppress and explain degenerate
intervals rather than presenting them as certainty.

Apply Holm to the fixed five-test family, retaining unavailable endpoints as
p=1 for correction but unknown in output. Keep nominal confidence intervals
explicitly separate from familywise p-value control. Additional windows/plans
are outside this family. Do not equate non-rejection with equivalence or
rejection with causation, practical importance, or representative population risk.

Export frozen source, settings, hypotheses, complete CSV/JSON, standalone HTML,
SVG/PNG effects, and a version/hash manifest. Stable ordering, explicit per-test
seeds, sorted metadata, and timestamp-free figures support exact offline replay
in the same environment. An exported plan is not external preregistration.

Independence, exchangeability, sample selection, missingness, timing, and evidence
overlap remain unresolved observational assumptions. The census's observed
differences are fixed; p-values and bootstrap intervals are model-based. Real
interpretation requires suitably sized live studies and an explicit research
design. Prioritization methodology and Threat Velocity remain separate work.
