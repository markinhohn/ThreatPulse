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
