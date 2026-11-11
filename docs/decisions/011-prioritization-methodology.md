# 011 — Transparent prioritization policy and prospective ML design

Status: accepted design; defaults require prospective evaluation.

Implementation follow-up: [decision 012](012-threat-velocity.md) records the
completed Threat Velocity contract, and [decision 013](013-baseline-priority-engine.md)
records the completed baseline engine. Policy defaults still require prospective
evaluation.

Complete Phase 4's methodology as a versioned decision specification before
implementing Threat Velocity or the engine. Use intelligence review tiers and
ordered rules rather than a weighted sum of incompatible severity/probability
scales. Confirmed current/historical CISA evidence supports P1; fresh EPSS and
validated CVSS categories support lower tiers. Unknown data remains explicit,
source conflicts and severe unknown-probability cases receive review floors,
and proposed downgrades require recorded review. Retain provenance and replayable
inputs. Asset applicability and remediation deadlines remain separate context.

Document freshness, boundaries, zero versus missing, rejected/conflicting records,
version changes, optional quality-gated trend promotion, and synthetic cases.
The policy reference is documentation, not configuration consumed by a deployed
engine. The proposed median pairwise EPSS slope and promotion thresholds form
the next Threat Velocity implementation contract, with coverage and model-regime
comparability gates. No current statistical result validates policy weights or
thresholds.

Add an explicit ML track without making the baseline engine wait for training.
Its target is first observed KEV inclusion over 30 days for currently non-KEV
CVEs, a listing proxy rather than general exploitation probability. A defined
NVD publication cohort needs separate immutable longitudinal storage, available-at
features, complete follow-up, censored unknowns, and mature labels. Existing
KEV-centric history and frozen comparison cohorts are insufficient by themselves.

Specify chronological CVE-separated splits, label-availability separation,
training-only preprocessing/calibration, logistic regression and gradient boosting
experiments, EPSS/rule baselines, capacity-aware ranking metrics, calibration,
and predeclared adoption gates. Models stay advisory until temporal validation,
public model cards, and baseline fallback are complete. Publish coverage,
reproduction artifacts, unsupported domains, and source reuse terms alongside
public results. Model failure to improve on baselines is a useful finding.

The next implementation remains Threat Velocity, followed by the baseline
prioritization engine. Longitudinal cohort collection can start in parallel as
its own milestone. Training, validation, publication, model integration, and
monitoring remain unchecked until implemented and evidenced.
