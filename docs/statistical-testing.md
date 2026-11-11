# Statistical comparison of KEV and non-KEV studies

This workflow adds exploratory inference to a frozen
[publication-window comparison study](comparison.md). It uses the same captured
group membership and exact EPSS date, keeping preferred CVSS versions separate.
It reads existing studies and never collects data, migrates, or writes to the
database. The descriptive comparison report remains available separately.

## Define the plan before looking at results

Five endpoints form a fixed family:

1. EPSS on the study's exact common score date.
2. Preferred CVSS 2.0 base score.
3. Preferred CVSS 3.0 base score.
4. Preferred CVSS 3.1 base score.
5. Preferred CVSS 4.0 base score.

For each endpoint, the null assumes equal scored-value distributions under
exchangeable KEV/non-KEV labels. The alternative is a two-sided rank difference,
calibrated using Mann-Whitney U. This is not solely a test of medians and does
not detect every possible distribution difference. Both groups must refer to
unique CVEs in the same frozen publication window. The source validator enforces
complete eligible membership/EPSS coverage partitions and one score date.
Rejected records and positive NVD/CISA conflicts remain excluded and counted.

Default settings require **20 scored CVEs per group for each endpoint**, with
pooled score variation. Missing metric values and other preferred CVSS versions
do not meet that endpoint's sample requirement. This threshold is a reporting
guardrail, not a power calculation or assurance of reliable inference. Before
collecting real data, choose a defensible window, date, minimum sample, alpha,
and resampling budget. Do not lower thresholds after seeing results to obtain
a rejection. Formal planning should specify a meaningful effect, desired power,
and the dependence/missingness assumptions; the tool does not estimate power.

The default plan uses alpha 0.05, 9,999 permutations, 9,999 bootstrap resamples,
and seed 20261009. These settings are exported in `plan.json`. Each endpoint and
resampling purpose receives a deterministic seed derived from that seed.
Exporting a plan records the analysis settings; it is not external preregistration.

## Run from frozen files or PostgreSQL

After collecting a study using the existing comparison command:

```bash
uv sync --locked
uv run --locked python -m threatpulse.statistics \
  --input data/kev-comparison/source.json --output data/statistical-comparison
```

Alternatively, use a persisted study UUID with `DATABASE_URL` configured:

```bash
uv run --locked python -m threatpulse.statistics \
  --study-id STUDY_UUID --output data/statistical-comparison-db
```

The database path uses a REPEATABLE READ, READ ONLY transaction and loads the
already frozen JSONB study. No source access or API key is needed. In the managed
cloud environment, use the saved `run.py` wrapper to supply the configured
database URL. For read-only home directories, configure writable plotting caches:

```bash
export MPLCONFIGDIR=/tmp/threatpulse-mpl-cache
export XDG_CACHE_HOME=/tmp/threatpulse-cache
```

Optional settings are explicit and validated:

```bash
uv run --locked python -m threatpulse.statistics \
  --input data/kev-comparison/source.json --output data/statistical-custom \
  --minimum-group-size 30 --alpha 0.05 --permutations 19999 \
  --bootstrap-resamples 19999 --seed 20261009
```

Minimum sample size cannot be below three. Resampling budgets range from 999
to 100,000 each. Lowering the sample requirement does not remove small-sample
limitations. All output directories must be new. Insufficient, absent, and
constant-score groups remain valid report inputs, with unavailable inference.

## Tests, effects, and confidence intervals

The statistic is Mann-Whitney U using pooled midpoint ranks. Ties are retained.
When the number of distinct group partitions fits the permutation budget,
SciPy enumerates all partitions. Otherwise it draws the configured number using
seeded PCG64 random generation. Two-sided p-values are twice the smaller tail,
capped at one. Monte Carlo uses SciPy's conservative plus-one correction, so
randomized p-values are never reported as zero. The report records exact versus
Monte Carlo, resamples used, seeds, and minimum attainable two-sided p-value.
Monte Carlo results have simulation uncertainty; interpret borderline decisions
with that limitation and avoid selecting seeds based on the answer.

Effects always compare **KEV minus non-KEV**:

- Median difference: EPSS in percentage points, CVSS in same-version points.
- Probability superiority: `P(KEV > non-KEV) + 0.5 * P(tie)`.
- Cliff's delta: `P(KEV > non-KEV) - P(KEV < non-KEV)`, or twice superiority
  minus one, ranging from -1 to 1. Positive values indicate higher KEV scores.

Within each group, the bootstrap independently resamples its empirical score
distribution. Percentile intervals use linear quantiles at alpha/2 and
1-alpha/2 for the median difference and Cliff's delta. The default nominal
confidence is 95%. Score-level multinomial counts provide the same resampling
distribution without quadratic CVE-pair arrays; bounded batches limit memory.
Double-precision numerical values are used for ranking and interval calculations.

Bootstrap intervals may be inaccurate with small/discrete samples or rare tails.
Complete separation can produce a delta interval of [1, 1] even when population
uncertainty is unknown. Collapsed intervals are therefore suppressed, with an
explicit warning. Point estimates and valid noncollapsed intervals remain
available. Unknown intervals do not become zero-width error bars.

## Multiple comparisons and coverage

Holm adjusts p-values across all five planned endpoints. Unavailable tests
participate as p=1 in correction, while their displayed p-values and decisions
remain unknown. Family size never shrinks based on observed data availability.
The decision field rejects the exchangeable-distribution null only when the
Holm-adjusted p-value is at most the configured alpha. A failure to reject does
not establish equality or equivalence, and a rejection does not establish a
meaningful operational effect.

The confidence intervals are **nominal and not simultaneous or multiplicity
adjusted**. Holm applies to p-values, not interval coverage. Running multiple
windows/dates/plans or additional tests introduces a broader family that this
single-study correction does not cover. Account for it in the research design.

Group coverage includes cohort totals, scored/missing CVSS and EPSS, and complete
pairs. Each endpoint further partitions both groups into selected scored CVEs,
unknown metric values, and other preferred CVSS versions, with the cohort total
as denominator. No scores are imputed. A scored-subset result does not establish
the same behavior for unscored CVEs. Default insufficient tests can still show
descriptive median differences and delta, but receive no p-values or intervals.

## Artifacts and offline replay

The standalone `report.html` contains findings, coverage, tests, confidence
intervals, effect charts, and assumptions. Exports include:

- `source.json`: complete frozen comparison study and source provenance.
- `plan.json`, `hypotheses.json`: settings and the fixed hypothesis family.
- `analysis.json`, `tests.csv`: full statistics, seeds, endpoint coverage,
  statuses, unavailable reasons, and interval warnings.
- `coverage.csv`, `cohorts.csv`: group coverage and all CVEs, including exclusions.
- SVG/PNG figures: Cliff's delta and separate-unit median differences.
- `manifest.json`: Python/package versions, study definition, plan, code hashes,
  and SHA-256 checksums for every other artifact.

Replay the exact plan without a database or network:

```bash
uv run --locked python -m threatpulse.statistics \
  --input data/statistical-comparison/source.json \
  --plan data/statistical-comparison/plan.json --output data/statistical-replay
```

`--plan` cannot be combined with individual setting overrides. Keep the same
code and `uv.lock`. Nested CSV fields use sorted JSON; SVG IDs use a fixed salt
and figures omit generation timestamps. Exact numerical and image replay also
depends on the recorded library versions, Python, RNG, fonts, and plotting
environment. Source records, exported files, and logs exclude API headers and
database credentials. Destinations under `data/` remain ignored by Git.

The existing tiny synthetic comparison fixture cannot meet the default sample
requirement. For a demonstration only, explicitly lower the threshold:

```bash
uv run --locked python -m threatpulse.statistics \
  --input tests/fixtures/comparison_study.json --minimum-group-size 3 \
  --output data/statistical-demo
```

This exercises exact tests and intervals, with undersized versions unavailable.
It is not a real vulnerability finding. A default run on the same fixture shows
all inference unavailable. Real results require a suitably sized frozen study;
the development database currently contains no live studies.

## Interpretation and research limits

The publication window is an observational census, not random assignment or a
representative sample. The observed score differences are fixed; inference is
model-based under hypothetical exchangeable labels or independent within-group
sampling, not uncertainty about this census's known scores. CVEs can cluster by
vendor, product, campaign, or underlying flaw; unique identifiers do not ensure
independence. Missingness, exposure, age, analysis maturity, CISA selection, and
EPSS revisions can dominate results. These assumptions are not established by
sample-size thresholds, permutation calibration, or multiplicity correction.

Captured CISA membership may differ from membership on the historical EPSS date.
KEV labels and EPSS may share exploitation evidence, so this is not independent
prediction-model validation. No causal, predictive-accuracy, population-risk,
or prioritization-weight claims follow from rejection. Read the effect sizes,
coverage, and limitations together. See [the statistical decision](decisions/010-statistical-testing.md)
and [SciPy's permutation-test documentation](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.permutation_test.html).
