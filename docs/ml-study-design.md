# ML study design v0.1

Status: accepted prospective design. No local classifier, longitudinal non-KEV
collector, feature builder, or model-serving path is implemented by this task.
The existing frozen comparison studies and KEV-based daily history are useful
research inputs, but do not provide the complete longitudinal training set.

## Research question and target

Among CVEs outside KEV at a recorded prediction boundary, can a learned model
improve the identification of **first observed KEV inclusions within 30 days**
over EPSS ranking and the transparent prioritization baseline?

The target is a catalog-listing proxy. It is not a direct observation of attacks,
the true exploitation start date, or the EPSS probability of exploitation.
KEV selection, disclosure/reporting delays, catalog corrections, and overlapping
exploitation evidence in EPSS affect it. A negative label means no observed
qualifying KEV inclusion under complete follow-up, not proof of no exploitation.
Source `dateAdded` is audit metadata, not a retrospectively substituted event time.

Confirmed KEV CVEs continue to receive baseline P1 and are outside this prediction
population. The learned score cannot override that evidence. Record the target
as `kev_inclusion_30d_v1` in datasets, predictions, reports, and the public model
card. Do not label it as an EPSS score or general exploitation probability.

## Cohort enrollment and collection milestone

1. Define a half-open UTC NVD publication interval, within the existing
   collector's 1–120-day limit. Collect its entire paginated census, rejecting
   over-cap windows rather than taking the first page. The original definition,
   cap, enrollment capture, and source responses are frozen.
2. Register unique CVEs in a separate longitudinal cohort registry. Deduplicate
   overlapping windows. Keep enrollment history, including exclusions; do not
   select controls by low EPSS, favorable CVSS, or later outcome.
3. Exclude Rejected CVEs, already confirmed current/historical KEV CVEs, and
   unconfirmed positive exploitation/source-conflict records from prediction
   eligibility. Confirm absence using a complete baseline CISA snapshot. Record
   the exclusion and source facts instead of silently losing the CVE.
4. Retain eligible CVEs with missing EPSS/CVSS. Record attempted requests, failures,
   explicit missing responses, timestamps, and source coverage. Missingness can
   become a feature; it must not silently select a complete-case control group.
5. Observe each enrolled CVE daily, retaining immutable source versions and full
   CISA catalog captures through the prediction horizon and label-latency window.
   Current-table upserts alone are insufficient for this dataset.

This is a defined publication cohort, not a representative random sample of all
CVEs. Record source/vendor/age/analysis-status coverage and selection effects.
Historical NVD metrics fetched now cannot become features for an old prediction
date. Backdated daily run labels do not reconstruct past KEV membership.

The upcoming collector should use the existing source validation, bounded
requests, pacing, shared ingestion lock, source checkpoints, and atomic recovery
patterns. It needs its own cohort/observation storage; inserting every non-KEV
CVE into the existing KEV dashboard tables would change their meaning. A failed
or missing source is a recorded coverage state, not a fabricated observation.
Source checkpoints remain recoverable without overwriting prior versions.

## Dataset contract and prediction boundary

The primary v0.1 experiment uses **one index prediction per CVE**, avoiding
daily correlated samples inflating training/evaluation counts. Retain subsequent
daily observations for outcome ascertainment, monitoring, and separately planned
experiments; they are not independent primary examples.

Index at the first scheduled eligible decision after enrollment. Fetch/validate
feature sources first, then capture the complete CISA catalog used to establish
baseline absence. Assign the decision boundary `t0` to that final validated
snapshot availability time. Every feature version must have been available by
t0. This ordering is part of the new prospective workflow, not an assumption
about the existing KEV-first daily runner. Missing feature values are allowed.

| Dataset field | Required meaning |
| --- | --- |
| `dataset_version`, `cohort_id`, `sample_id`, `cve_id` | Stable identity, definition, and deduplication; CVE ID is not a model feature |
| `prediction_at` | Aware UTC t0, with validated baseline catalog absence |
| `baseline_catalog_id`, `cohort_definition` | Full catalog source/hash and NVD publication interval/cap |
| `feature_schema_version`, `policy_version` | Frozen preprocessing inputs and baseline rule definition |
| `observation_ids`, `source_urls`, `raw_sha256` | Immutable input versions and provenance, without credentials |
| `source_score_date`, `captured_at`, `available_at` | Distinguish score validity, source capture, and feature availability |
| `feature_values`, `missing_indicators`, `coverage_flags` | Numeric/categorical values, unknowns, freshness, and history completeness |
| `horizon_end` | t0 + 30 days |
| `label`, `label_state`, `label_available_at` | 1, 0, or null; mature, pending, censored-gap, censored-boundary, or excluded/corrected |
| `outcome_snapshot_ids`, `event_interval`, `followup_coverage` | Evidence supporting or censoring the label |
| `split_id`, `split_role` | Frozen chronological training/validation/test membership |

Samples, feature snapshots, outcome evidence, and later revisions are versioned.
Repeated EPSS ingestion currently updates rows for the same CVE/date; freeze
the value actually known at t0 rather than using a later overwrite. Later
backfilled observations cannot retroactively enter a previously frozen sample.
The export must support offline replay from raw/normalized observations and
record package/code/configuration hashes.

## Outcome labels and maturity

Use trusted complete catalog captures and capture/availability times, retaining
the interval `(last confirmed absence, first confirmed presence]`. These are
observations of listing, not measurements of exploitation timing.

- **Positive (1):** a first qualifying inclusion is observed by horizon_end,
  and its absence-to-presence interval lies after t0 and within the horizon.
- **Negative (0):** no qualifying inclusion is observed, follow-up catalog
  coverage is complete, and a trusted absence snapshot at/after horizon_end
  is available within two days. Report it as no observed inclusion.
- **Pending:** the horizon plus label-latency window has not matured.
- **Censored:** a missing/invalid catalog, an adjacent capture gap exceeding
  48 hours, unresolved source correction, rejection, or an inclusion interval
  straddling the horizon prevents an unambiguous primary label.

Require complete follow-up through the horizon for both positive and negative
primary samples. Preserve observed positive evidence even when the sample is
censored; it still matters operationally. Neither pending nor censored records
become zero labels, and neither should be silently dropped from coverage reports.

Finalize the primary label after t0 + 32 days so both classes have the same
maximum follow-up/latency opportunity. Keep label_available_at for training
cutoffs. If the first presence is after the horizon and the preceding absence
is before it, censor the boundary rather than guessing from dateAdded. An absent
capture beyond the horizon cannot rule out brief inclusion/removal between
captures; document that observation limit.

Synthetic examples: a day-12 inclusion with intact 32-day monitoring is positive;
no inclusion with intact monitoring and a day-31 absence is negative; a day-29
absence followed by day-31 presence is boundary-censored; a four-day outage is
gap-censored; a day-20 sample is still pending. No historical comparison fixture
can substitute for that follow-up protocol.

## Features and model candidates

All features use immutable versions available at t0:

- EPSS probability and optionally its percentile as a separately named feature.
- Preferred CVSS version-specific values, severity, attack vector, and analysis
  status. Preserve version/source; do not pretend raw scores across versions
  are interchangeable.
- Days since NVD publication as known at t0; no CVE-identifier year shortcut.
- Prior EPSS changes, rate, coverage, freshness, and model-regime comparability
  from a fixed trailing window. Missing history remains unknown with indicators.
- Structured technical attributes already recorded by NVD, plus missingness
  indicators. Vendor/product features are optional ablation experiments with
  explicit cardinality and subgroup checks.

Exclude identifiers, future KEV status, CISA dateAdded/due dates, later NVD
revisions, future EPSS, and all outcome-derived fields. Current KEV status is
constant absence in the eligible cohort and is not a predictive feature.
Do not use source URLs/record IDs as accidental identifier features.

Use scikit-learn Pipeline/ColumnTransformer so imputers, encoders, scaling,
feature selection, and probability calibration fit only on training data.
Start with interpretable logistic regression; compare a gradient boosting
classifier after that baseline works. Tune on chronological validation data.
Keep raw EPSS ranking as a baseline; for probability comparisons, fit an EPSS-only
logistic/calibration baseline on training data because raw EPSS predicts a
different outcome. A statistical association is not a learned causal weight.

## Temporal validation and adoption gates

Freeze the experimental plan before examining the final holdout:

1. Use nonoverlapping chronological enrollment blocks for train, validation,
   and one later untouched test cohort. Each CVE has one primary sample and
   one split, including across overlapping publication windows.
2. Allow only training labels available before the next split starts. The
   horizon/latency implies at least a 32-day separation between the last training
   prediction and the next block; analogous separation applies to validation
   used for tuning/calibration before the final test.
3. Fit preprocessing and choose model/hyperparameters/calibration on train and
   validation. Evaluate the chosen candidate once on the final holdout. Additional
   attempts require a new later holdout and a versioned experiment plan.
4. Compare the same eligible CVEs and outcome horizon across learned predictions,
   raw EPSS ranking, and the policy-tier baseline. The benchmark tie-break is
   fresh EPSS descending within tiers, then CVE ID; unknown EPSS sorts after
   scored CVEs in its tier and is disclosed separately, not imputed as zero.
   UNDETERMINED follows ranked tiers for this research benchmark, with its size
   and outcomes reported separately. Raw EPSS also places unknown scores last,
   using CVE ID for ties. These are benchmark ranking conventions, not calibrated
   policy risk scores or changes to the public data-review queue.

The primary review budget is the top `ceil(0.01 * eligible_CVEs)` per held-out
enrollment batch, a reproducible capacity of ten per thousand. Report recall
and precision at that budget, average precision/PR-AUC with the implementation
named, and score coverage. Report Brier score and reliability plots for model
probabilities against the calibrated EPSS-only baseline. Overall accuracy is
insufficient when future KEV inclusions are rare. Include age, vendor, missingness,
and source-version strata; flag small strata rather than implying reliable results.

Initial guardrails require at least 100 positive training labels, 50 positive
validation labels, and 30 positive final-test labels, with both classes in every
split. These are provisional reporting minima, not a power calculation. Estimate
event prevalence and a meaningful improvement before freezing enrollment windows
and conducting a power/precision assessment. If the dataset cannot support that
design, publish descriptive research and keep the baseline operational.

Adoption requires an untouched temporal holdout with positive simultaneous
lower bounds for incremental recall at the primary budget against **both**
ranking baselines, plus no worse held-out Brier score than the calibrated
EPSS-only baseline. The two recall comparisons form one declared family:
use paired bootstrap resamples of matched CVEs within enrollment batches,
recomputing each ranking/budget, with 97.5% one-sided lower bounds for each
difference (the 2.5th percentile). This Bonferroni allocation targets nominal
95% family coverage; bootstrap approximation and CVE dependence limit the claim.
Predeclare the seed, at least 10,000 resamples, and interval procedure; validate
coverage under plausible sparse-event/dependence simulations before claiming
the gate passed. If batch-level dependence prevents adequate precision, keep
the model experimental. The existing cross-sectional statistics command does
not implement this new evaluation protocol.

A failure is a valid research result, not a reason to change the holdout or pick
a favorable seed. Publish meaningful effect sizes, uncertainty, baseline results,
and subgroup/coverage caveats even if the model is not adopted.

## Engine integration and public usefulness

The [baseline engine](prioritization.md) is implemented independently. Model integration waits for valid
data, mature labels, temporal evaluation, a versioned model/preprocessor artifact,
and a public model card. Its initial role is **advisory**, separately displaying
probability of the KEV-listing proxy and a research ranking. It cannot demote
confirmed KEV, invent scores for out-of-domain inputs, or suppress quality flags.
Model downtime/version incompatibility uses the transparent baseline fallback.

The model card must state target/horizon, eligible cohort, feature availability,
training/validation/test dates, label censoring and maturity, source attribution
and reuse terms, metrics/baselines, uncertainty, subgroup limitations, intended
use, unsupported populations, artifact/configuration hashes, and reproduction
commands. Supply synthetic/publicly redistributable dataset examples; do not
include environment credentials or future private asset inventories.

Monitor input missingness/freshness, distribution shift, calibration once labels
mature, source/model regime changes, and prediction availability. Publish coverage
alongside any ranking. A changed source or performance failure requires review
before reactivating model advice; maintain a reproducible baseline result.
Operational predictions for older/repeated CVEs are an additional deployment
domain beyond the primary first-enrollment experiment and require prospective
evaluation before treating their scores as validated probabilities.

The roadmap explicitly separates cohort tracking, dataset construction, training,
validation, experiment/model publication, advisory integration, and monitoring.
Collection is the next roadmap task after the implemented baseline engine.
Training needs mature labels; integration needs both accepted model evidence and
a working baseline. See [the prioritization methodology](prioritization-methodology.md)
and [decision 011](decisions/011-prioritization-methodology.md).
