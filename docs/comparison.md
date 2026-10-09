# KEV versus non-KEV comparison studies

A study collects **all NVD CVEs published in a defined UTC interval**, classifies
them using a freshly fetched CISA KEV catalog, and requests one explicit EPSS
score date for both groups. This is a defined publication cohort, not a random
or representative sample of all vulnerabilities.

## Collect and compare

Configure DATABASE_URL, install the locked dependencies, and allow HTTPS to
`services.nvd.nist.gov`, `raw.githubusercontent.com`, and `api.first.org` as
explained in [development](development.md). NVD_API_KEY is optional; using one
retains the existing authenticated pacing. Python does not load `.env`.

```bash
uv sync --locked
uv run --locked python -m threatpulse.comparison collect \
  --published-start 2026-09-01 --published-end 2026-10-01 \
  --score-date 2026-10-08 --max-records 10000 \
  --output data/kev-comparison
```

Open `data/kev-comparison/report.html`. The command prints the persisted study ID.
The start date is inclusive and the end date is exclusive, both at midnight UTC.
The window must be 1–120 days, matching NVD's API limit. The collector queries
publication dates without a KEV filter, requests all pages, validates every CVE,
and rejects duplicates, out-of-window records, changed totals, incomplete pages,
and HTTP failures. A window over max-records fails as a whole: it never truncates
to a first-page sample. Narrow the window or deliberately increase the cap.

The selected score date must be supported by FIRST. All eligible KEV and non-KEV
CVEs are sent together to the existing bounded EPSS collector. Each request
chunk explicitly uses the selected date. Missing responses are retained as
unknown, and date mismatches or incomplete responses reject the whole study.
Choosing an EPSS date before some CVEs were published can yield missing scores;
choose a date after the publication interval for a useful comparison.

## Group definitions

| Classification | Rule |
| --- | --- |
| `kev` | Non-rejected NVD CVE present in the captured CISA catalog |
| `non_kev` | Non-rejected CVE absent from that catalog and without positive NVD CISA metadata |
| `excluded_kev_conflict` | CVE absent from CISA but with positive NVD CISA metadata |
| `excluded_rejected` | NVD analysis status is Rejected |

Rejected records take precedence over other labels. Positive NVD metadata means
any populated `cisaExploitAdd`, `cisaActionDue`, `cisaRequiredAction`, or
`cisaVulnerabilityName` field. Conflicts are quarantined because source updates
or removals can make membership ambiguous. Excluded records are not sent for
EPSS; all are retained in the exported cohort table and frozen source data for
audit. CVEs awaiting analysis remain eligible with unknown CVSS if appropriate.

CISA is fetched after NVD collection. Its exact identifier list, capture timestamp,
and source URL are preserved. Only catalog members inside the NVD publication
window form the KEV group. The non-KEV label means absence of catalog evidence,
not proof that exploitation has never occurred. Membership is current at capture;
it is not reconstructed as of a historical EPSS score date.

## Results and denominators

The report presents group sizes, CVSS coverage, same-date EPSS coverage, missing
counts, and complete-pair counts. Descriptive summaries report n, min, quartiles,
median, max, and mean. Quantiles use linear interpolation.

EPSS distributions use ten-percentage-point bins. CVSS distributions use one-point
bins and keep preferred versions 2.0, 3.0, 3.1, and 4.0 separate. Both histograms
include the lower bound, exclude the upper bound, and include the maximum in the
last bin. Bar heights are percentages **of scored CVEs within each group**;
counts and scoring denominators are exported. No-score groups have no plotted
distribution, and their percentages are unknown rather than zero.

Median differences are KEV minus non-KEV. EPSS differences are percentage points;
CVSS differences use the same version and CVSS points. Both groups must contain
scores for a difference to be reported. These are descriptive comparisons,
without significance tests or prioritization weights. EPSS summary values and
CSV scores use fractions 0–1; charts use percentages. Percentile is exported
separately and is not interpreted as exploitation probability.

## Frozen storage and offline replay

Migration 5 adds `comparison_studies`, separate from the current KEV tables. A
fully validated study is inserted atomically as JSONB with its publication window,
EPSS date, UUID, and creation time. Existing ingestion and dashboard tables retain
their current cohorts. Repeated collection creates a new study; duplicate study
IDs cannot overwrite data. The daily runner does not refresh frozen studies.

Collection holds the same PostgreSQL session advisory lock as the storage CLI
through all API requests and persistence. Overlapping commands fail before
collection begins. NVD pacing and bounded retries are reused. Other clients
sharing the key or public egress address must still coordinate separately.

A failed source fetch creates no partially collected study. Correct the failure
and rerun the complete collection. If rendering fails after persistence, use the
printed study ID to regenerate the report without refetching:

```bash
uv run --locked python -m threatpulse.comparison report \
  --study-id STUDY_UUID --output data/kev-comparison-recovered
```

Stored-study replay reads in a read-only transaction and does not migrate.
All report destinations must be new directories. Inspect persisted studies with:

```sql
SELECT study_id, created_at, published_start, published_end, score_date
FROM comparison_studies ORDER BY created_at DESC;
```

Each report exports:

| File | Contents |
| --- | --- |
| `report.html` | Standalone report with embedded SVG charts and selection limits |
| `source.json` | Full frozen definition, membership snapshot, NVD records, and EPSS batch |
| `analysis.json` | Computed classification, coverage, summaries, distributions, differences |
| `cohorts.csv` | Every window CVE, including exclusions and available scores |
| `coverage.csv` | Group sizes and missingness |
| `summaries.csv` | EPSS and version-specific CVSS statistics |
| `distributions.csv` | Bin counts, scoring denominators, and normalized percentages |
| `median-differences.csv` | KEV-minus-non-KEV differences and contributing sample sizes |
| `*.svg`, `*.png` | Standalone figures |
| `manifest.json` | Selected definition, Python/package versions, code and artifact hashes |

The source export retains original source JSON and provenance, without API keys
or connection details. Canonical sorted JSON keeps replay hashes stable after a
PostgreSQL JSONB roundtrip. Keep the same code and uv.lock for reproduction.
Replay offline without DATABASE_URL or network:

```bash
uv run --locked python -m threatpulse.comparison report \
  --input data/kev-comparison/source.json --output data/kev-comparison-replay
```

For a demonstration without a configured source environment:

```bash
uv run --locked python -m threatpulse.comparison report \
  --input tests/fixtures/comparison_study.json --output data/comparison-preview
```

The fixture is explicitly labeled synthetic. Its distributions do not constitute
real vulnerability findings. Exports under data/ are ignored by Git.

## Selection bias and limits

Both groups share a publication interval, which narrows age differences but does
not match them on vendor, product, exposure, installed prevalence, analysis
maturity, or exploitation opportunity. Recent windows may contain few or no KEV
CVEs. Window selection, catalog selection, NVD coverage, and score availability
can dominate observed differences; small groups do not support generalization.

NVD's publication timestamp is not discovery time or CVE identifier year. Its
fetched preferred CVSS score is not necessarily the score at the EPSS observation
date. Missing scores are unknown and can be missing differently between groups.
The CISA snapshot is not a historical KEV census at the score date. EPSS model
revisions can affect scores. KEV records represent known exploitation, making
membership unsuitable as an independent, unbiased prediction-validation outcome.
No causal, population-significance, or operational-risk claims follow from these
plots. Statistical testing remains a separate roadmap task.

NVD does not supply transactional pagination. Stable totals and duplicate checks
detect common changes but cannot rule out equal-sized substitutions during a
fetch. Source timestamps and raw records are retained. All records are loaded
into memory, bounded by the explicit cap; large cohorts need a different export
strategy. The Streamlit dashboard continues to display its existing stored cohort;
comparison studies are accessed through this report workflow.
