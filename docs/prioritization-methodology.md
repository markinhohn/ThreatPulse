# Prioritization methodology v0.1

Status: implemented baseline with provisional policy defaults. The
[engine guide](prioritization.md) covers evaluation, review records, and replay;
[Threat Velocity](threat-velocity.md) implements the trend contract below.
Local ML models remain planned.
[The policy reference](examples/prioritization-policy-v0.1.json) and
[worked scenarios](examples/prioritization-scenarios-v0.1.json) are documentation
artifacts. The engine implements and tests those versioned rules, then exports
its executable policy; it does not load these JSON files as runtime configuration.

## Purpose and scope

Assign explainable **intelligence review tiers** to CVEs using public evidence.
A tier expresses which intelligence deserves attention; it is not a probability
of compromise, a calibrated risk score, or an organization-specific remediation
deadline. Applicability, compensating controls, asset exposure, and business
criticality belong to the later asset-aware workflow. CISA required actions and
due dates remain source facts with their applicability preserved.

The baseline uses ordered rules rather than a weighted sum. KEV establishes
reported exploitation evidence, EPSS estimates exploitation in the next 30 days,
and CVSS describes technical severity. Their scales have different meanings.
Correlations or statistically significant differences do not supply validated
weights. The default thresholds below are explicit policy choices requiring
prospective evaluation and versioned revision; they are not inferred from our
synthetic reports or endorsed by the source providers.

The 1% and 10% EPSS boundaries create readable bands separated by an order of
magnitude; they are not fitted optimal cutoffs. The two-calendar-day EPSS buffer
allows daily publication/retrieval delays. The 48-hour catalog-absence limit
requires recent negative evidence, while seven-day NVD revalidation accommodates
slower-changing technical metadata. These operational defaults must be assessed
against refresh reliability, review capacity, and prospective outcomes. The
severe-CVSS/unknown-EPSS floor requests data review rather than claiming elevated
measured exploitation probability.

## Inputs and source validity

Every decision records an aware UTC `decision_at`, policy version, source
capture times/identifiers, and the evidence actually available by that time.
Nominal ingestion run dates are not evidence availability times. The historical
reports and current dashboard are not sufficient alone to reconstruct this
decision input: the dashboard's retained KEV entries do not prove current
catalog membership, and latest NVD/EPSS rows may have been overwritten.

| Signal | Accepted evidence | Meaning and default freshness |
| --- | --- | --- |
| Confirmed KEV | Validated CISA entry with source and capture provenance | Current or historical confirmed inclusion establishes reported exploitation; it has no automatic expiry |
| Current KEV absence | Complete validated CISA catalog, CVE absent | Snapshot captured no more than 48 hours before the decision; absence never proves no exploitation |
| EPSS | Validated probability, exact source score date, capture time | Source date is 0–2 UTC calendar days old and capture is no later than the decision |
| CVSS | Validated preferred metric, version, source/type, severity, capture time | NVD was fetched no more than seven days before the decision; source `modified_at` can be much older |
| Historical trend | Dated EPSS observations with adequate coverage and comparability | Optional, quality-gated promotion described below; no interpolation |

Both EPSS and CVSS also require valid provenance and no future timestamps.
Freshness boundaries are inclusive. A future date, malformed record, failed
source validation, or unsupported metric makes the affected input unknown.
EPSS is stored as a fraction: 0.10 is 10%, and 0 is a valid score. Percentile
is relative position and is **not** an input to probability thresholds.

Preferred CVSS selection follows ingestion: newest version, then Primary, then
deterministic source/vector order. Use its validated severity label and retain
the version/source. `HIGH` or `CRITICAL` constitutes the severe category here.
This is an explicit categorical policy approximation across CVSS versions,
not numerical pooling or a claim that versions measure identical severity.
A source or preferred-version change remains visible and cannot silently justify
a downgrade. Missing CVSS never becomes a zero score.

Historical CISA evidence remains valid reported-exploitation evidence when a
new catalog omits a CVE. Flag the membership change for review; only an audited
source correction can withdraw the evidence. Positive NVD CISA metadata alone
is unconfirmed evidence; a CISA/NVD disagreement requires source review. The
comparison study's conflict exclusions remain unchanged by this policy.

An exploitation/source conflict here means contradictory catalog membership,
positive exploitation metadata, or record validity (such as Rejected versus
confirmed KEV). Different published CVSS metrics, a preferred-version change,
or high severity with low EPSS are not exploitation contradictions. Preserve
those metric differences and flag preference changes separately.

## Baseline tiers and ordered rules

| Tier | Meaning |
| --- | --- |
| P1 | Reported exploitation: validate applicability and review first |
| P2 | Elevated evidence or a significant unresolved-data concern: focused review |
| P3 | Moderate probability evidence or severe technical consequences: planned review |
| P4 | Lower current intelligence signals with complete fresh evidence: routine monitoring |
| UNDETERMINED | Evidence cannot support a baseline tier; show in the data-review queue |
| OUT_OF_SCOPE | Rejected CVE with no contradictory exploitation evidence; preserve the source record |

Evaluate the following rules in order, taking the first match. Then apply trend
promotion, data-review floors, and the downgrade rule. Probabilities must be
fresh/valid, and severe CVSS must be fresh/valid for the corresponding rule.

| Rule | Condition | Candidate | Reason code |
| --- | --- | --- | --- |
| R0 | NVD status Rejected, with no confirmed/unconfirmed positive exploitation evidence or source conflict | OUT_OF_SCOPE | REJECTED_RECORD |
| R1 | Confirmed current or historical CISA inclusion | P1 | CONFIRMED_KEV |
| R2 | EPSS at least 0.10 | P2 | EPSS_HIGH |
| R3 | EPSS at least 0.01 and severe CVSS | P2 | SEVERITY_AND_EPSS |
| R4 | EPSS at least 0.01 | P3 | EPSS_ELEVATED |
| R5 | Severe CVSS | P3 | HIGH_SEVERITY |
| R6 | EPSS below 0.01, CVSS NONE/LOW/MEDIUM, fresh complete catalog absence, no source conflict | P4 | LOWER_SIGNALS_COMPLETE |
| R7 | No preceding match | UNDETERMINED | INSUFFICIENT_EVIDENCE |

Thus a high EPSS signal can support P2 with unknown CVSS, while a low EPSS
score alone cannot support P4 with unknown CVSS or catalog coverage. A Rejected
record that also has confirmed KEV evidence stays P1 with a conflict flag;
unconfirmed positive evidence/conflicting sources receive the P2 review floor.
Do not use a Rejected record's technical metrics as valid CVSS evidence.

No numerical combined score is published. Show tiers with the reasons, input
values, source versions/dates, and data-quality flags. A stable CVE-identifier
display order within a tier is a tie-break, not an additional risk estimate.
Show UNDETERMINED separately; it must not be treated as P4 or hidden by default.

## Missing, stale, and conflicting evidence

| Situation | Action |
| --- | --- |
| Confirmed KEV with missing/stale EPSS or CVSS | Keep P1; flag inputs requiring refresh |
| Fresh severe CVSS with unknown EPSS | Raise the candidate to at least P2 for data review, reason SEVERITY_WITH_UNKNOWN_EPSS |
| Unconfirmed positive exploitation evidence or contradictory membership/record-validity sources | Raise to at least P2, flag EXPLOITATION_CONFLICT, and retain both sources |
| Strong fresh EPSS with missing CVSS | Assign its supported tier; flag unknown severity for review |
| Unknown current catalog coverage | Flag KEV_COVERAGE_UNKNOWN; permit supported P2/P3 signals, but prohibit P4 |
| Missing/stale/invalid optional trend history | No trend promotion; disclose the coverage limitation without invalidating fresh point scores |
| A candidate would lower a previously published P1–P4 tier, including OUT_OF_SCOPE/UNDETERMINED | Keep the previous tier effective; expose the proposed change and require recorded reviewer acknowledgement |

These are independent quality flags, not probabilities. `needs_review` is true
for an unknown required signal, exploitation/source conflict, historical membership
removal, preferred CVSS metric change, or blocked downgrade. Optional trend
unavailability alone is informational. A non-conflicting OUT_OF_SCOPE record
does not require EPSS/CVSS to support a ranking decision.
Missing EPSS does not imply low exploitation probability. Stale values remain
visible as historical evidence, but do not satisfy fresh-score thresholds.

Record `candidate_tier` after all floors/promotions, `effective_tier` after
the downgrade guard, and reason/quality codes. A stronger candidate can take
effect without waiting for a downgrade review. An unresolved source conflict
cannot be dismissed by a lower model score. Policy changes are versioned;
recomputation must preserve the prior decision for audit.

The reference examples use quality codes `EPSS_UNKNOWN`, `CVSS_UNKNOWN`,
`KEV_COVERAGE_UNKNOWN`, `KEV_MEMBERSHIP_CHANGED`, `EXPLOITATION_CONFLICT`,
`CVSS_PREFERENCE_CHANGED`, and `DOWNGRADE_REVIEW_REQUIRED`. Retain the detailed
missing/stale/invalid cause alongside an unknown code. Trend ineligibility is
reported separately with its reason. An eligible promotion adds `TREND_RISING`.
Record every applicable floor reason even when stronger evidence already supports
a higher tier. A downgrade acknowledgement must identify the reviewer, time,
policy, input version, and approved candidate; a matching valid record permits
that candidate to take effect. The synthetic JSON represents this validated
acknowledgement as a normalized boolean, not a real review authorization.

## Threat Velocity contract

The implemented calculation provides a descriptive rate from a trailing
seven-day EPSS window and an eligible rising signal for the baseline engine.
The window spans source dates from `latest_date - 7`
through `latest_date`, inclusive. Use only observations captured by the decision.

A promotion-eligible `rising` signal requires all of:

- A fresh latest EPSS score of at least 0.01.
- At least five observed dates, spanning at least four calendar days.
- Gaps between adjacent used dates no greater than two days.
- Known comparable model regime; a boundary or unknown comparability disables
  automated promotion. Descriptive trends may still be shown with that warning.
- Endpoint change at least five percentage points and median pairwise slope
  at least 0.5 percentage points per calendar day.

For distinct source dates i < j, pairwise slope is
`100 * (EPSS[j] - EPSS[i]) / elapsed_calendar_days`. The median of those slopes
limits sensitivity to one endpoint. Zero probabilities remain valid, missing
dates stay missing, and relative percentage growth is not substituted for
percentage points. The thresholds are provisional and are not a forecast.
Current EPSS storage does not establish model-regime comparability. The
implementation requires a bounded, evidence-backed operator model review before
enabling the rising signal; unknown/boundary cases retain descriptive rates only.

A qualifying rise promotes P3 to P2. P1 stays P1; P2 stays P2. An unavailable
or falling trend never automatically lowers a tier. Membership/source conflicts
still receive their review flags. Export the window, observations, model-regime
basis, slope, endpoint change, gaps, and eligibility reason. This descriptive
Threat Velocity differs from the later learned prediction of future KEV inclusion.

## Worked examples

These are synthetic normalized inputs. Fresh point data and trusted current
catalog absence are assumed unless an exception is stated. The linked JSON
contains these cases, additional boundaries/review cases, input quality states,
and expected candidates/effective tiers. Top-level overrides replace the
corresponding default field; quality states are normalized source-validation
outcomes, not raw API payloads. Its separate timestamp checks cover freshness.

| Case | Inputs | Candidate / effective | Explanation |
| --- | --- | --- | --- |
| Confirmed current KEV | EPSS/CVSS unknown | P1 / P1 | Known evidence dominates, with quality flags |
| Historical KEV omitted today | EPSS 0.002, LOW CVSS | P1 / P1 | Removal alone does not erase exploitation evidence |
| High probability | EPSS 0.10, MEDIUM CVSS | P2 / P2 | Inclusive high-EPSS boundary |
| Severe and elevated | EPSS 0.01, HIGH CVSS | P2 / P2 | Inclusive severity/probability boundary |
| Elevated probability | EPSS 0.01, MEDIUM CVSS | P3 / P3 | Probability evidence without severe consequences |
| Severe, low probability | EPSS 0.001, HIGH CVSS | P3 / P3 | Low probability does not erase severe consequences |
| Lower complete signals | EPSS 0, LOW CVSS | P4 / P4 | Zero is valid; required data is present/fresh |
| High percentile only | EPSS 0.005, percentile 0.99, LOW CVSS | P4 / P4 | Percentile is not probability |
| Severe, stale EPSS | Old score 0.002, fresh HIGH CVSS | P2 / P2 | Unknown EPSS triggers a data-review floor |
| Low probability, unknown CVSS | EPSS 0.001 | UNDETERMINED / UNDETERMINED | Cannot establish lower complete signals |
| Low scores, catalog unavailable | EPSS 0.001, LOW CVSS | UNDETERMINED / UNDETERMINED | Current membership coverage is unknown |
| Positive NVD/CISA conflict | Low EPSS/CVSS, unconfirmed NVD evidence | P2 / P2 | Focused source review rather than assumed non-KEV |
| Eligible rising trend | EPSS 0.06, MEDIUM CVSS, eligible rise | P2 / P2 | P3 promoted one tier |
| Trend gap/model regime unknown | Same current point scores, ineligible history | P3 / P3 | Fresh scores remain useful; no promotion |
| Future EPSS timestamp | Value 0.80, LOW CVSS | UNDETERMINED / UNDETERMINED | Unavailable-at-decision data is not accepted |
| Proposed downgrade | Fresh low complete signals, prior P2 | P4 / P2 | Retain prior tier pending recorded review |
| Rejected only | No positive/conflicting exploitation evidence | OUT_OF_SCOPE / OUT_OF_SCOPE | Preserve record, remove from new baseline candidates |
| Rejected plus confirmed KEV | Valid historical CISA evidence | P1 / P1 | Preserve known evidence and flag contradiction |

Freshness examples at synthetic `decision_at=2026-01-10T12:00:00Z`: an EPSS
score dated January 8 is two UTC calendar days old and accepted if captured by
the decision; January 7 is stale; January 11 is future/invalid. A NVD capture
at January 3, 12:00Z is exactly seven days old and accepted, even if its
`modified_at` is years old. January 3, 11:59Z is stale. CISA absence captured
January 8, 12:00Z is accepted; January 8, 11:59Z is stale. Policy decisions
normalize audit times to UTC rather than local display dates.

## Validation, public outputs, and ML role

The engine tests cover threshold/freshness boundaries, zero versus
missing values, retained KEV evidence, conflicts, rejected records, version
changes, historical availability, trend eligibility, and blocked downgrades.
Decisions replay from a frozen input/definition with policy/source hashes.
The [synthetic demo](../tests/fixtures/priority_dataset.json) exercises all six
queues; [the guide](prioritization.md) describes what a tier can and cannot imply.

Evaluate tier coverage, data-review volume, stability, prospective future KEV
capture, and source/vendor/age differences before claiming practical improvement.
Real utility requires asset-aware applicability and operator feedback. There is
no validated weight or performance claim attached to v0.1. False urgency,
limited source coverage, delayed KEV listing, model changes, and dependence
between CVEs remain limitations. Confirmed KEV is also not proof of exposure
or compromise in any specific installation.

[The ML study design](ml-study-design.md) defines a separate experiment on
currently non-KEV CVEs: predict first observed KEV inclusion over 30 days, using
only information available at prediction time. A validated learned score may
become advisory input after temporal evaluation against EPSS and this baseline.
It cannot erase confirmed KEV evidence, hide missingness, or replace the baseline
when the model is unavailable/outside its validated domain. Its outcome is a
listing proxy, not the EPSS exploitation probability. The future model card must
state that distinction and document training/evaluation data and limitations.

See [decision 011](decisions/011-prioritization-methodology.md) for the design
choice and roadmap dependencies, and [decision 013](decisions/013-baseline-priority-engine.md)
for the implementation. The next roadmap task is the defined NVD non-KEV cohort
with immutable daily history. Model training still requires mature outcome labels.
