# Reproducible exploratory analysis

Generate a report after configuring DATABASE_URL and populating the database as
explained in [development](development.md) and [scheduling](scheduling.md):

```bash
uv sync --locked
uv run --locked python -m threatpulse.exploration --output data/exploration
```

Open `data/exploration/report.html` in a browser. It is a standalone file with
embedded SVG charts and needs no server or Internet access. The report reads
existing data; it neither migrates nor ingests. At least migration 3 must exist.
All queries use a single PostgreSQL repeatable-read, read-only transaction, so
concurrent ingestion cannot produce inconsistent report inputs.

The default score date is the latest date with any stored EPSS observation.
Comparisons use that exact date, not each CVE's latest score. This can expose
low coverage when only a subset was ingested on the latest date. Missing scores
stay unknown. Choose a particular recorded date and historical endpoints with:

```bash
uv run --locked python -m threatpulse.exploration \
  --output data/exploration-selected \
  --score-date 2026-01-02 --earlier 2026-01-01 --later 2026-01-02
```

The dates must exist in the stored observations. Supply both endpoints, with
`earlier < later`. If omitted, history compares the earliest and latest recorded
dates. Score comparison and change comparison dates may be chosen independently.
Empty data and a single recorded date produce a report with explicit unavailable
results. They do not fabricate scores, historical changes, or correlations.

## What the report contains

- Coverage: stored CVEs and KEV entries, NVD enrichment, available CVSS/EPSS
  scores, missing scores, and complete pairs on the chosen EPSS date.
- Score summaries: count, minimum, 25th percentile, median, 75th percentile,
  maximum, and mean. Quantiles use linear interpolation. EPSS summary values
  are fractions from 0 to 1; figures show probability percentages.
- Distributions: EPSS in fixed ten-percentage-point bins and preferred CVSS
  base scores in one-point bins for each version. Histogram bins include the
  lower bound, exclude the upper bound, and include the maximum in the last bin.
- Relationships: separate scatter plots, complete-pair counts, Pearson r and
  Spearman rho for each preferred CVSS version. Average ranks handle ties.
  Fewer than three pairs or a constant score series yields an unavailable
  coefficient with a reason, rather than a zero correlation.
- History: observation coverage for every recorded date, exact-endpoint matched
  changes, one-sided/missing coverage, increase/decrease/unchanged counts, a
  change distribution, and the first 20 CVEs ordered by signed change. Full
  matched data is exported to CSV. Differences are percentage points; 10% to
  20% is +10 points. Missing dates and CVEs are never interpolated or zero-filled.
- Findings: concise descriptions calculated from these tables, followed by
  methods and limitations. This is exploratory analysis, not a risk score.

## Reproduce and share

The output directory must be new; existing output is never overwritten.
Choose a new destination for each run. Each export contains:

| File | Purpose |
| --- | --- |
| `report.html` | Standalone report with tables and embedded figures |
| `source.json` | Validated input dataset with capture and source timestamps |
| `analysis.json` | Computed coverage, summaries, coefficients, and changes |
| `vulnerabilities.csv` | Full cohort with scores on the selected date |
| `epss-observations.csv` | All stored EPSS observations used as input |
| `relationships.csv` | Version-specific association and CVSS summary data |
| `history-coverage.csv` | Observed and missing CVEs per recorded date |
| `changes.csv` | Complete matched endpoint changes |
| `*.svg`, `*.png` | Exportable figures |
| `manifest.json` | Python/package versions, analysis code hash, selected dates, artifact hashes |

Replay the captured data offline, without DATABASE_URL or API credentials:

```bash
uv run --locked python -m threatpulse.exploration \
  --input data/exploration/source.json --output data/exploration-replay
```

If the original report used explicit dates, pass those same dates from
`manifest.json` on replay. Use the same code revision and `uv.lock`. On the same
locked stack the analysis and SVG output are deterministic; different font or
platform versions may affect rendered figures. source.json contains normalized
analysis fields, dates, and timestamps; it does not contain connection details,
API keys, descriptions, or raw source JSON. Generated exports under `data/` are
ignored by Git.

A synthetic preview can be generated without a database:

```bash
uv run --locked python -m threatpulse.exploration \
  --input tests/fixtures/exploration_dataset.json \
  --output data/exploration-preview
```

This fixture is explicitly labeled synthetic and is only a demonstration of
report behavior. Its numbers are not findings about real vulnerabilities.

## Interpret the results

The dataset is selected through KEV ingestion. It cannot establish relationships
for all CVEs or support a representative KEV/non-KEV comparison. Latest KEV tables
retain absent records, so stored KEV entries are not necessarily today's source
membership. Vendor/product names remain as published, without alias merging.

The NVD score is each CVE's current preferred metric, not its score at the EPSS
observation date. CVSS versions are kept separate. Daily snapshot tables are not
used to reconstruct historical CVSS/KEV cohorts. The report includes NVD source
and ingestion timestamps in the input export for provenance.

CVSS measures severity; EPSS estimates exploitation probability over 30 days.
Neither correlation nor a score increase proves actual exploitation, causation,
or a validated prioritization weight. The minimum of three pairs is a calculation
rule, not a statistical reliability threshold. No p-values, confidence intervals,
or population significance claims are calculated. Statistical testing remains a
separate roadmap task.

EPSS comparisons cover exact matched endpoints. The stored CVE cohort can include
CVEs first ingested after an earlier endpoint; coverage makes those absences
visible. Model revisions can change scores. Changes are not divided by elapsed
time and do not implement Threat Velocity. The history coverage figure plots only
recorded dates; it does not imply observations on intervening dates. The exporter
loads the cohort and EPSS history into memory, appropriate for the current KEV
scope; broader datasets will need bounded export or database-side aggregation.

Run all tests with TEST_DATABASE_URL set to a development database to verify
read-only snapshot isolation as well as calculation and offline replay tests.
