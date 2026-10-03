# Decision: transactional CVE-keyed PostgreSQL ingestion

## Problem and choices

Scheduled KEV collection will repeatedly encounter the same CVEs and corrected
source records. Appending every fetch would duplicate vulnerabilities and inflate
dashboard counts. We use PostgreSQL primary keys on `cve_id` in both
`vulnerabilities` and `kev_entries`, with a foreign key connecting them.
`INSERT ... ON CONFLICT DO UPDATE` refreshes existing records and inserts new
CVEs. Database constraints enforce uniqueness even outside the ingestion API.

Psycopg 3 supplies parameterized SQL, transactions, and JSONB adaptation without
introducing an ORM for these two small tables. SQL migrations are packaged with
the Python library so the installed application can find them. Migration 1 is
applied transactionally and recorded in `schema_migrations`; an advisory lock
serializes migration runners. Applied migrations must not be edited; schema
changes require a new migration and runner update. A newer unknown migration
version fails explicitly.

## Atomicity and provenance

The collector validates the complete batch before connecting to the database.
Storage also rejects empty batches, duplicate CVEs, and mismatched model IDs.
Both tables are updated in one transaction. A failure in KEV storage rolls back
vulnerability changes too. A separate transaction-scoped advisory lock serializes
ingestions using this API, preventing concurrent batches from interleaving.

Raw source records are stored as JSONB, alongside source URL and timezone-aware
ingestion timestamp. JSONB preserves values, not original JSON byte formatting.
The last successfully written batch replaces existing observations; we do not
yet compare source publication times or retain historical snapshots. Repeated
ingestion keeps row counts stable but refreshes ingestion timestamps.

Absent CVEs are retained rather than silently deleted, because absence could
reflect source corrections or an incomplete upstream publication. Future catalog
membership tracking should make removal status explicit. EPSS history and
asset-aware scoring remain separate future models.

## Runtime and credentials

Compose provides PostgreSQL 17 with a health check, a persistent named volume,
and a loopback-only port. The major version is pinned; patch releases can change.
Python currently runs outside Docker. Local credentials belong in ignored `.env`
and shell configuration, never in source or saved setup instructions. The cloud
validation instance uses a generated local password, not a checked-in default.

## Validation

Real PostgreSQL tests use isolated temporary schemas to verify repeatable
migrations, repeated ingestion, updates, new CVEs, retention of absent CVEs,
foreign keys, uniqueness constraints, identifier checks, and full rollback when
the second table rejects an update. Offline tests do not substitute for these
checks. Live validation runs ingestion twice and compares stored row counts.

On October 3, 2026, all 56 tests passed with real PostgreSQL integration
enabled; none were skipped. Two live KEV ingestion runs each processed 1,733
records, leaving exactly 1,733 rows in each table. Ruff lint and formatting
checks passed. Both source and wheel distributions built successfully, and
the wheel was checked for the packaged migration SQL.
