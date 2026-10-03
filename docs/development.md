# Python development

Install Python 3.12 and uv, then run these commands from the repository root:

```bash
uv sync --locked
uv run --locked pytest
uv run --locked ruff check .
uv run --locked ruff format --check .
```

`uv sync` installs the package in editable mode and includes development tools.
Application code belongs in `src/threatpulse/`; tests belong in `tests/`.
Pydantic validates the data models. There are no running services yet.

To add a dependency, use `uv add <package>` (or `uv add --dev <package>`
for a development tool), and commit both `pyproject.toml` and `uv.lock`.

In a cloud environment where the default uv cache is read-only, set a writable
cache before running the commands above:

```bash
export UV_CACHE_DIR=/tmp/threatpulse-uv-cache
export UV_LINK_MODE=copy
```

## Vulnerability data model

`Vulnerability` holds shared CVE attributes; `KevEntry` holds CISA remediation
fields and ingestion provenance. Parse one CISA catalog record with:

```python
from datetime import UTC, datetime

from threatpulse.models import parse_cisa_kev_record

vulnerability, kev_entry = parse_cisa_kev_record(
    record,  # One dictionary from the catalog's vulnerabilities array.
    source_url="https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
    ingested_at=datetime.now(UTC),
)
```

Invalid records raise `pydantic.ValidationError`. Required text is trimmed and
must be nonempty; CVE IDs use uppercase `CVE-YYYY-NNNN` with at least four
sequence digits. Dates must parse successfully. Ingestion timestamps must have
a timezone and are normalized to UTC. Ransomware use is `Known` or `Unknown`;
`Unknown` is not evidence that a vulnerability has never been used in ransomware.

The mapper retains a deep copy of the original record, including additional
source fields, without trimming its values. Notes are optional. Direct model
construction rejects unexpected fields to catch misspelled attributes. These
models do not fetch data or persist it; database uniqueness and history will be
implemented with storage.

## CISA KEV collector

Fetch and validate the official catalog:

```bash
uv run --locked python -m threatpulse.kev
```

Export normalized vulnerabilities, KEV observations, and original records:

```bash
mkdir -p data
uv run --locked python -m threatpulse.kev --output data/kev.json --timeout 30
```

The command prints the source URL and validated record count. Exports use a
new file; an existing destination is never overwritten. The `data/` directory
is ignored by Git. No database writes happen yet.

Requests retain TLS verification, follow redirects, and use a 30-second timeout
per network operation. Failures exit with status 1. Malformed JSON, invalid
records, empty catalogs, count mismatches, and duplicate CVEs reject the entire
batch rather than silently returning incomplete data. There are no automatic
retries; a caller or scheduler can rerun a failed collection.

The environment must allow HTTPS access to `raw.githubusercontent.com`. Tests use mock HTTP
responses and a synthetic CISA-format fixture, so they work without live access.

The collector reads CISA's official `cisagov/kev-data` GitHub publication.
The former `www.cisa.gov` endpoint returned an upstream HTTP 403 from this
cloud environment even after its network allowance was enabled. See
[the source decision](decisions/001-kev-catalog-source.md) for evidence,
tradeoffs, and the exact modifications.

## PostgreSQL development and ingestion

Docker Engine and Docker Compose are required. Python runs on the host for now;
the database runs in a PostgreSQL 17 container. From the repository root:

1. Copy `.env.example` to `.env` if `.env` does not already exist.
2. Replace `POSTGRES_PASSWORD` with your own local password.
3. Start PostgreSQL: `docker compose up -d --wait db`.
4. Export `DATABASE_URL` in your shell using your password and configured port.
   URL-encode special characters in the password. Do not commit credentials.

```bash
export DATABASE_URL='postgresql://threatpulse:YOUR_PASSWORD@127.0.0.1:5432/threatpulse'
uv sync --locked
uv run --locked python -m threatpulse.storage migrate
uv run --locked python -m threatpulse.storage ingest-kev
```

Compose loads `.env`; Python does not. Changing `.env` does not change a
password already stored in the database volume. The port binds only to loopback.
The named volume preserves data across container restarts and `docker compose
down`; `docker compose down -v` destroys the development database.

`ingest-kev` fetches and validates the full live catalog before database writes,
applies pending migrations, then upserts vulnerabilities and KEV entries in one
transaction. Its `processed` count means records handled, not new rows inserted.
The migration command is repeatable and does not fetch the catalog.

Verify stored counts and inspect a record without printing credentials:

```bash
docker compose exec db psql -U threatpulse -d threatpulse -c \
  'SELECT count(*) FROM vulnerabilities; SELECT count(*) FROM kev_entries;'
```

Run all tests with real database integration enabled:

```bash
export TEST_DATABASE_URL="$DATABASE_URL"
uv run --locked pytest
```

Integration tests create and drop isolated schemas in that database, so the
test user needs schema creation permission. Use a development database only.
Without `TEST_DATABASE_URL`, database tests are explicitly skipped; a passing
offline test run alone does not validate storage.

See [the storage decision](decisions/002-postgresql-ingestion.md) for transaction,
deduplication, migration, and retention choices.

## EPSS enrichment and score history

After KEV ingestion, enrich stored CVEs with FIRST's public EPSS API:

```bash
uv run --locked python -m threatpulse.storage ingest-epss
uv run --locked python -m threatpulse.storage ingest-epss --date 2026-01-01
```

Migration 2 adds `epss_observations` without replacing existing KEV data. The
command automatically migrates, reads stored CVEs, and requests scores in bounded
chunks. Without `--date`, the first returned score selects the latest available
date; subsequent requests explicitly use that date. An explicit date requests
historical scores subject to FIRST's coverage and retention limits.

EPSS estimates the probability of exploitation over the next 30 days;
percentile is its relative rank among scored vulnerabilities. Both are stored as
decimal fractions from 0 to 1, not percentages. The API's score date differs from
our UTC ingestion timestamp. Each observation retains the original source record
and the request URL, including its CVE filter and historical date when present.

The command prints requested and processed counts and a `missing` list. A missing
score is unknown, never an assumed zero, and existing observations are retained.
Repeated `(cve_id, score_date)` observations update the existing row. Different
dates add history. All fetched scores are validated before a single atomic write;
an HTTP failure, inconsistent date, invalid score, duplicate response, or partial
API page prevents any EPSS observations from being written.

Allow HTTPS access to `api.first.org`; no API key is required. Requests retain
TLS verification and have 30-second per-operation timeouts. There is no automatic
retry or daily scheduler. Run enrichment on each desired date to build history;
this does not automatically backfill dates or retain changes to KEV attributes.

Inspect coverage by date:

```bash
docker compose exec db psql -U threatpulse -d threatpulse -c \
  'SELECT score_date, count(*) FROM epss_observations GROUP BY score_date ORDER BY score_date;'
```

See [the EPSS decision](decisions/003-epss-enrichment.md) for the source,
batching, missing-data, precision, history, and validation choices.

## NVD severity and technical context

After ingesting KEV, run:

```bash
uv run --locked python -m threatpulse.storage ingest-nvd
# Optional small sample from the first stored CVEs, ordered by ID:
uv run --locked python -m threatpulse.storage ingest-nvd --limit 10
```

Allow HTTPS access to `services.nvd.nist.gov`. Configure `NVD_API_KEY` through
secure environment settings in the cloud, or export it securely in your local
shell. Do not paste keys into chat, commit them, or put them in a command URL.
Python does not load `.env`. The collector sends the key only in NVD's `apiKey`
header, and stored request URLs never include it.

The official API supports 50 requests per rolling 30 seconds with a valid key,
or 5 without one. Requests are spaced by at least 0.65 seconds in authenticated
mode and 6.1 seconds in public mode, counting retries. Only one collector should
run at a time; pacing is per process and cannot account for other clients sharing
your key or public egress IP. Avoid rapid repeated CLI launches. Transient network
errors and HTTP 429/500/502/503/504 receive at most three retries with backoff.
`Retry-After` is honored; cooldowns above 60 seconds stop the batch and ask for
a later retry. HTTP 401/403 fail immediately rather than silently discarding the
key. Requests retain TLS verification and 30-second per-operation timeouts.

To reduce API calls, collection first requests NVD's `hasKev` pages, up to 2,000
CVEs per page, then performs `cveId` lookups only for stored CVEs absent from
those pages. Only requested stored CVEs are persisted. `--limit` limits stored
targets; it does not change the size of the initial KEV page request.

Migration 3 stores the latest NVD snapshot separately from KEV attributes:
publication and modification timestamps, analysis status, English description,
reference URLs, CWE identifiers, all supported CVSS metrics, request provenance,
ingestion time, and original JSONB data (including affected CPE configurations).
CVSS versions 2.0, 3.0, 3.1, and 4.0 are supported. Vector syntax and base score,
severity, and attack-vector consistency are checked using the `cvss` package.
Legacy FTP references are preserved; reference URLs are metadata, not fetched.
The normalized adjacent-network attack vector is `ADJACENT_NETWORK` across versions.

The preferred CVSS metric selects the newest version, then `Primary` within that
version, then source/vector order for deterministic ties. All metrics remain
available for other choices. A CVE without CVSS data has NULL score/severity,
not zero. Missing CVEs are reported and existing stored snapshots are retained.
Repeated enrichment updates rather than duplicates. A snapshot older than the
stored `modified_at` cannot overwrite newer data. All fetched records are
validated before one atomic database write.

Show severity alongside latest available EPSS per CVE:

```sql
SELECT v.cve_id, v.vendor, v.product,
       n.cvss_version, n.base_score, n.severity, n.attack_vector,
       e.score_date, e.epss, e.percentile
FROM vulnerabilities v
LEFT JOIN nvd_enrichments n USING (cve_id)
LEFT JOIN LATERAL (
    SELECT score_date, epss, percentile
    FROM epss_observations
    WHERE cve_id = v.cve_id
    ORDER BY score_date DESC LIMIT 1
) e ON true
ORDER BY e.epss DESC NULLS LAST, v.cve_id
LIMIT 20;
```

The command reports requested/processed counts and missing CVEs. Database errors
omit connection details; NVD failures report safe HTTP/error categories. Real
PostgreSQL tests still require `TEST_DATABASE_URL`. See
[the NVD decision](decisions/004-nvd-enrichment.md) for rationale and validation.

## Streamlit dashboard

Start PostgreSQL, set `DATABASE_URL`, and install the locked dependencies as
described above. Apply migrations and ingest KEV first; EPSS and NVD enrichment
are optional for startup but populate the score displays. Then run from the
repository root:

```bash
uv run --locked streamlit run src/threatpulse/dashboard.py \
  --server.address=127.0.0.1 --server.port=8501 \
  --server.headless=true --browser.gatherUsageStats=false
```

On your own machine, open `localhost:8501` in your browser. Keep the terminal
running; Ctrl+C stops Streamlit without stopping PostgreSQL or deleting data.
Change the port flag if 8501 is already occupied. The cloud onboarding workspace
can run and validate the service internally; it does not provide a browser
preview link. A running process must be restarted in a new cloud task.

The **Overview** tab shows total stored CVEs, CVSS/EPSS coverage, severity counts,
and the range of latest available EPSS dates. The **Vulnerability explorer** tab
supports case-insensitive literal text search, vendor/severity filters, and a
minimum EPSS probability. Empty vendor/severity selections mean all values.
Searching a complete CVE identifier matches that CVE only; other searches
match literal text across the listed fields.
The **Include CVEs without EPSS** checkbox controls whether missing scores remain
visible independently of the probability threshold. Scores are displayed as
percentages; percentile is labeled separately from probability. Unknown CVSS
severity is `UNKNOWN`, and blank numeric scores are not treated as zero.

Choose a CVE to inspect CISA remediation, due date, ransomware campaign use,
NVD description/status/weaknesses, references, source timestamps, all CVSS source
metrics, and EPSS history. Each CVE uses its own latest stored EPSS observation,
so latest dates can differ. An EPSS chart shows probability over recorded dates;
missing dates are not backfilled. Overview totals always cover the whole stored
dataset, while table filters apply to the explorer.

The dashboard issues read-only transactions and never ingests data or runs
migrations. Reruns reload current data, and **Refresh data** triggers a rerun;
there is no background polling or shared query cache. Database failures show
actionable messages without connection credentials. No API key is needed to
browse previously collected data. The app currently reads the full table into
memory, appropriate for the initial KEV dataset; larger datasets will need
server-side filtering and pagination.

Run tests with `TEST_DATABASE_URL` set to a development database to exercise
dashboard queries and Streamlit interactions against isolated schemas. The
shared test fixture creates and drops those schemas without touching ingestion
data. See [the dashboard decision](decisions/005-streamlit-dashboard.md).
