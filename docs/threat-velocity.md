# Threat Velocity

Threat Velocity reports how a CVE's EPSS probability changes across source dates.
It exports descriptive rates and a separate quality-gated `rising_signal` for
the future priority engine. It does not assign priority tiers or train a model.
Thresholds implement [policy v0.1](prioritization-methodology.md) and remain
provisional operational choices.

## Run and replay

With a migrated database and `DATABASE_URL` configured:

```bash
uv run --locked python -m threatpulse.velocity --output data/velocity
```

The command uses a single REPEATABLE READ, READ ONLY transaction and never
collects data or migrates tables. Its frozen cohort contains all stored CVEs,
including those with no EPSS history; comparison-study cohorts remain separate.
The database cohort has historically been populated from KEV and is not a
representative sample of public vulnerabilities. See [daily ingestion](scheduling.md)
for collecting history. All history is loaded into memory.

A synthetic demo contains a valid rise, a three-day gap, a model boundary,
zero probabilities, an entirely unscored CVE, and stale scores:

```bash
uv run --locked python -m threatpulse.velocity \
  --input tests/fixtures/velocity_dataset.json --output data/velocity-demo
```

Scores, model declarations, and audit identities in this fixture are invented;
they do not attest actual FIRST model dates or demonstrate research performance.

Replay without database or network access:

```bash
uv run --locked python -m threatpulse.velocity \
  --input data/velocity/source.json --output data/velocity-replay
```

The default decision is the frozen capture time, normalized to UTC. An explicit
`--decision-at 2026-01-10T12:00:00Z` must include an offset and cannot follow the
export. Use the original `analysis.json`/`manifest.json` decision when replaying
a custom decision. Output directories must be new. Use the same code/policy
version, locked packages, Python, fonts, and plotting environment for identical
bytes. In cloud sessions with a read-only home directory, configure writable
`MPLCONFIGDIR` and `XDG_CACHE_HOME` as described in [the trend guide](trends.md).

Existing trend `source.json` exports are also accepted:

```bash
uv run --locked python -m threatpulse.velocity \
  --input data/trends/source.json --output data/velocity-from-trends
```

## Rates, calendar coverage, and freshness

For each CVE, select the latest validated score available by the decision, then
use the inclusive source-date window `[latest - 7 days, latest]`: **eight**
possible calendar dates. Every CVE keeps its own latest date and freshness;
a stale CVE is not anchored to another CVE's newer score. Data outside this
window cannot influence its rates.

- Endpoint change: `100 * (last_probability - first_probability)` percentage points.
- Endpoint-average rate: endpoint change divided by elapsed calendar days.
- Median pairwise slope: median of `100 * (p[j] - p[i]) / elapsed_days` for every
  distinct pair of used dates; this is the primary Threat Velocity rate.
- Adjacent intervals: both source dates, elapsed/missing days, change, daily rate,
  and model comparability.

Exact rational arithmetic determines thresholds; only display/export numbers
are converted to floats. For example, a probability change from 0.01 to 0.07
over four days is six percentage points and 1.5 percentage points per day.
EPSS zero is valid, percentile is metadata, and a missing score never becomes
zero. Missing dates remain explicit; there is no interpolation or carry-forward.
Fewer than two observed dates produce null rates.

A `rising_signal` requires **all** of:

1. At least five observed dates, spanning at least four days.
2. No adjacent gap above two calendar days.
3. Latest EPSS at least 0.01 and no more than two UTC calendar days old.
4. Endpoint increase at least five percentage points and median slope at least
   0.5 percentage points per day.
5. One reviewed comparable model regime covering the entire observed span.
6. No invalid future source dates captured by the decision.

Boundaries are inclusive. The report retains leading/intermediate missing dates,
coverage fraction, maximum gap, freshness, descriptive direction, and every
failed eligibility reason. A positive descriptive rate alone does not authorize
promotion. The future engine can use eligible rises for P3 → P2; falling or
unavailable history never authorizes an automatic downgrade.

## Model-comparability review

The default model registry is empty. Neither score continuity, percentiles,
API version, nor a calendar date establishes a shared EPSS model regime.
Rates are still calculated, but `MODEL_REGIME_UNKNOWN` prevents promotion.

Supply a versioned operator-reviewed registry with `--model-regimes REGISTRY_JSON`.
It replaces any registry embedded in the input, and the chosen declarations
are frozen into the resulting `source.json`. Minimal safe configuration:

```json
{"schema_version": 1, "regimes": []}
```

Each populated entry requires `regime_id`, inclusive `score_date_start` and
`score_date_end`, aware `reviewed_at`, `reviewer`, `evidence_url`, and `evidence`.
Use documented FIRST model/version information and an explicit audit of the
covered score dates. Do not copy the fixture's synthetic regimes into live
configuration. A review cannot attest dates after its own UTC review date;
there are no indefinitely open ranges. To extend coverage, review the new dates
and version the registry with its evidence. Overlapping intervals, duplicate
IDs, reversed ranges, and blank evidence are rejected.

Only reviews available at the decision count. Coverage must include every
calendar date from the first used observation to the last, even dates without
scores. An unknown interval produces `MODEL_REGIME_UNKNOWN`; a fully covered
span containing different regimes produces `MODEL_REGIME_BOUNDARY`. The engine
never drops earlier observations just to obtain a favorable single-regime window.
Cross-regime rates remain descriptive and flagged. Registry declarations are
auditable operator assertions, not automatic verification by FIRST.

## Availability and historical limitations

Canonical inputs are `VelocityDataset` objects with `dataset_kind=threat_velocity`
and `schema_version=1`. Each EPSS observation retains the existing source URL,
raw record, probability/percentile, source date, and ingestion timestamp, adding
`available_at` and `availability_basis`.

Existing database rows can be overwritten for a previously stored CVE/date.
Their ingestion timestamps alone cannot prove the contents of an earlier version;
older collectors also stamped the batch before all requests completed. Database
exports conservatively set availability to export completion (`database_export`),
while imported trend exports use their recorded capture (`history_export`).
Such rows support decisions at that frozen export, not reconstruction of an
earlier state. A later overwrite is preserved in a new export rather than
silently substituted into a previous `source.json`.

For independently frozen capture records, `validated_capture` requires an
evidence-backed availability timestamp after collection/validation. Availability
cannot precede ingestion. Values after the decision are excluded, regardless
of how old their source date is. A future source date already available at the
decision is invalid and blocks that CVE's promotion. The export retains excluded
observations and their reasons. This workflow does not claim immutable storage
of all EPSS revisions or solve the separate longitudinal ML dataset milestone.

## Exported artifacts

- `report.html`: standalone summary, deterministic chart/CVE previews, methods,
  and limitations, with no network requirements.
- `source.json`: frozen cohort, all EPSS observations, availability basis, and
  selected model-review declarations.
- `policy.json`: method/policy versions and complete eligibility thresholds.
- `analysis.json`: decision time, source/policy hashes, full cohort results,
  used observations, intervals, and coverage/reason counts.
- `velocity.csv`: one row per cohort CVE, including missing-data cases.
- `observations.csv`: every used observation with source/availability provenance.
- `intervals.csv`: adjacent-date changes and rates, retaining gaps/comparability.
- `threat-velocity.svg` and `.png`: rate distributions and up to five CVE histories.
- `manifest.json`: decision, Python/package versions, code hashes, and SHA-256
  hashes of all other artifacts. Nested CSV values use sorted JSON; null rates
  remain empty, distinct from zero. Empty reports keep full CSV column schemas.

Chart sampling uses observed-date count then CVE ID, without choosing the steepest
rise. Probability lines break at missing dates; unknown/cross-regime histories
use unconnected markers. The full exports are authoritative. No reported change
establishes observed attacks, causation, or calibrated vulnerability risk.

See [decision 012](decisions/012-threat-velocity.md) for implementation choices.
The next roadmap task is the baseline prioritization engine; Streamlit integration
remains the separate dashboard visualization milestone.
