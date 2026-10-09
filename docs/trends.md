# Vulnerability trend analysis

The report describes stored KEV catalog captures, preferred NVD CVSS changes,
and EPSS history across multiple source score dates. It reads existing data;
it does not run migrations, call external APIs, or change ingestion state.
KEV/non-KEV comparison studies are separate and do not enter this cohort.

## Collect and export

Configure `DATABASE_URL`, migrate, and build history using the
[daily ingestion and recovery workflow](scheduling.md). Repeating a successful
day is a no-op. At least two committed captures of each source are needed to
observe snapshot changes. Manual KEV/NVD ingestion updates current tables but
does not create historical snapshots. Manual dated EPSS ingestion does add
score-date history:

```bash
uv run --locked python -m threatpulse.storage ingest-daily
uv run --locked python -m threatpulse.storage ingest-epss --date 2026-10-01
uv run --locked python -m threatpulse.storage ingest-epss --date 2026-10-02
uv run --locked python -m threatpulse.storage ingest-epss --date 2026-10-03
uv run --locked python -m threatpulse.trends --output data/trends
```

Choose dates supported by FIRST. Historical EPSS collection is subject to source
availability and uses the currently stored CVEs, rather than a reconstructed
historical cohort. Backdating `ingest-daily --date` requests historical EPSS but
fetches current KEV/NVD data; it cannot reconstruct past KEV/NVD snapshots.

Optional bounds are inclusive:

```bash
uv run --locked python -m threatpulse.trends \
  --start-date 2026-10-01 --end-date 2026-10-09 --output data/trends-october
```

Each bound defaults independently to the earliest/latest available history date.
KEV/NVD dates use UTC source checkpoint completion times; EPSS uses source score
dates, including dates of committed all-missing EPSS steps. With no history, the
default is the UTC export date. Empty and single-capture windows remain valid;
they report insufficient history rather than invented changes. A maximum of
3660 calendar days bounds report size. All stored history is loaded into memory.
The first capture *within the selected window* is always a baseline.

In the managed cloud environment, use the saved `run.py` wrapper to supply
`DATABASE_URL` from the configured PostgreSQL password. For read-only home
directories, configure writable plotting caches:

```bash
export MPLCONFIGDIR=/tmp/threatpulse-mpl-cache
export XDG_CACHE_HOME=/tmp/threatpulse-cache
```

## KEV and NVD semantics

KEV additions/removals are set differences between adjacent committed full
catalog captures. The initial capture counts no additions. Each event includes
both checkpoint times, run IDs, CISA's declared `dateAdded`, vendor/product,
and a reappearance flag relative to the selected window. An observed addition
only establishes that membership changed somewhere in the capture interval;
it does not establish when exploitation began. Repeated appearances count as
separate events. Removals are included because the latest KEV tables retain
absent entries and cannot establish historical catalog membership.

NVD comparisons use only the intersection of CVEs fetched in adjacent committed
captures. Earlier-only/later-only counts and missing-request counts describe
coverage, not severity changes. The report keeps fetched historical records
even if the latest-table freshness guard rejected a stale write, and flags
`modified_at` regressions. A missing intermediate capture does not reconstruct
or interpolate an NVD observation. Pair rows contain both modification times,
analysis statuses, preferred metrics, and the comparison classification.

Preferred CVSS selection uses the same existing rule as ingestion: newest
supported version, then Primary, then deterministic source/vector ordering.
Numeric score deltas and severity label changes require matching CVSS version,
source, and metric type; neither status may be Rejected, and modification time
must not regress. Version/source/type changes, metric additions/removals, and
unscored pairs remain explicit and receive no numeric delta. Changing a score
within one severity category is still a score change. Other stored CVSS metrics
remain available in `source.json`, but this workflow compares the preferred
metric rather than enumerating every source metric revision.

Committed source checkpoints are included even when their overall run is
running, failed, or interrupted: daily recovery preserves those completed
transactions. Sort order uses source completion time and run ID, rather than
nominal run date or eventual overall completion. Retries can capture the three
sources on different days. The full export retains each record's fetch time.

## EPSS coverage and trends

The fixed denominator is all CVEs stored at export time, including CVEs without
any EPSS. For every calendar day, the report exports observed/missing counts,
coverage fraction, available-score median/quartiles, and committed daily-step
metadata. A whole missing date has null summaries. Gap tables give inclusive
ranges and lengths; per-CVE summaries give first/last dates, missing calendar
dates, and internal gaps. Zero is a valid probability and remains distinct
from a missing score.

Available-score summaries can change when scored membership changes. To help
assess that effect, the report also gives the median for a balanced panel:
CVEs observed on **every nonempty score date** in the selected window. This
panel excludes whole missing dates, uses no imputation, and may be small or
biased. Its members and exact dates are recorded. Calendar gaps still break
both plotted lines. A deterministic sample of up to five CVEs, chosen by most
observed dates and then CVE ID, illustrates individual histories; all CVEs'
observations and coverage are exported.

For every adjacent pair of nonempty score dates, matched CVEs receive
`(later - earlier) * 100` in **percentage points**. Earlier-only, later-only,
neither, increases/decreases/unchanged, elapsed days, and whole unobserved days
between the endpoints are retained. Changes across two days are not treated
as daily changes. Summaries use linear quantiles, without significance tests,
forecasts, or the planned Threat Velocity calculation.

Daily missing lists describe a particular API request. Other/manual writes may
later add scores, and an unrecorded date is not proof that FIRST lacked scores.
EPSS rows are keyed by CVE/date and can be overwritten on repeated ingestion;
this report freezes their values at export time, not all prior revisions.

## Artifacts and reproducibility

Outputs require a new directory, preventing accidental replacement:

- `report.html`: standalone findings, coverage, methods, and embedded SVG figures.
- `source.json`: frozen cohort, runs/checkpoints, full KEV/NVD observations, and
  EPSS records from one REPEATABLE READ, READ ONLY database transaction.
- `analysis.json`: computed results, selected bounds, and source hash.
- CSV files: captures, KEV events, NVD pairs/intervals, EPSS coverage/gaps,
  per-CVE series, matched changes/intervals, and selected EPSS observations.
- SVG/PNG charts: catalog captures/changes, NVD change counts, EPSS coverage,
  probability summaries, and individual histories when scores exist.
- `manifest.json`: Python/package versions, analysis code hashes, date bounds,
  and SHA-256 hashes of every other exported file.

Replay without a database or external API access:

```bash
uv run --locked python -m threatpulse.trends --input data/trends/source.json \
  --output data/trends-replay
```

If the original report supplied bounds, supply the same bounds when replaying;
the frozen export retains full history. Nested CSV metadata is serialized as
sorted JSON; charts use a fixed SVG hash salt and omit generation timestamps.
Identical sources/bounds with the same dependencies and plotting environment
produce identical artifacts. Use the project's locked dependencies; differing
Python, fonts, package versions, or plotting environments can change image bytes.
No connection URLs, credential values, or API headers are exported.

A clearly labeled synthetic example exercises three dates, a whole-date gap,
partial coverage, a zero EPSS score, KEV reappearance, a severity increase,
and CVSS source/version changes:

```bash
uv run --locked python -m threatpulse.trends \
  --input tests/fixtures/trend_dataset.json --output data/trends-demo
```

It demonstrates behavior and is not a real research finding. The development
database initially has no historical data; reporting capability does not imply
that a representative history has been collected.

## Interpretation limits

The stored cohort is KEV-based, with selection and survivorship bias. Coverage
on older dates may reflect CVE age or later enrollment, and vendor/product
labels are unnormalized. Collection timing and upstream edits can affect what
was observed; changes between captures are unobservable. CVSS is severity,
while EPSS is a probability estimate, not realized exploitation. Model revisions
can affect EPSS trends. Neither score changes nor KEV additions establish
causation or statistical significance. See [the design decision](decisions/009-trend-analysis.md).
