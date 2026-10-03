"""Transactional PostgreSQL migrations and CVE-keyed KEV ingestion."""

import argparse
import json
import os
import sys
from importlib.resources import files

import psycopg
from psycopg.types.json import Jsonb

from threatpulse.kev import KevCatalog, KevCollectionError, collect_kev


def migrate(connection: psycopg.Connection) -> None:
    """Apply the initial packaged migration once, in a transaction."""
    with connection.transaction():
        connection.execute("SELECT pg_advisory_xact_lock(734915001)")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations "
            "(version INTEGER PRIMARY KEY, "
            "applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
        versions = {
            row[0]
            for row in connection.execute("SELECT version FROM schema_migrations")
        }
        if versions - {1}:
            raise ValueError("Database has migrations newer than this application")
        if 1 not in versions:
            sql = (
                files("threatpulse").joinpath("migrations/001_initial.sql").read_text()
            )
            connection.execute(sql)
            connection.execute("INSERT INTO schema_migrations (version) VALUES (1)")


def ingest_catalog(connection: psycopg.Connection, catalog: KevCatalog) -> int:
    """Upsert the entire batch atomically; return records processed, not inserted.

    Primary keys prevent duplicate CVEs across runs. All writers using this API
    are serialized to prevent concurrent batches from interleaving updates.
    """
    ids = [record.vulnerability.cve_id for record in catalog.records]
    if not ids or len(ids) != len(set(ids)):
        raise ValueError("Catalog must be nonempty and contain unique CVEs")
    if any(
        record.vulnerability.cve_id != record.kev.cve_id for record in catalog.records
    ):
        raise ValueError("Vulnerability and KEV identifiers must match")
    with connection.transaction():
        connection.execute("SELECT pg_advisory_xact_lock(734915002)")
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO vulnerabilities (cve_id, vendor, product, name, description)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    vendor = EXCLUDED.vendor, product = EXCLUDED.product,
                    name = EXCLUDED.name, description = EXCLUDED.description
                """,
                [
                    (v.cve_id, v.vendor, v.product, v.name, v.description)
                    for record in catalog.records
                    for v in [record.vulnerability]
                ],
            )
            cursor.executemany(
                """
                INSERT INTO kev_entries
                    (cve_id, date_added, required_action, due_date, ransomware_use,
                     notes, source_url, ingested_at, raw_record)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    date_added = EXCLUDED.date_added,
                    required_action = EXCLUDED.required_action,
                    due_date = EXCLUDED.due_date,
                    ransomware_use = EXCLUDED.ransomware_use,
                    notes = EXCLUDED.notes, source_url = EXCLUDED.source_url,
                    ingested_at = EXCLUDED.ingested_at, raw_record = EXCLUDED.raw_record
                """,
                [
                    (
                        k.cve_id,
                        k.date_added,
                        k.required_action,
                        k.due_date,
                        k.ransomware_use.value,
                        k.notes,
                        str(k.source_url),
                        k.ingested_at,
                        Jsonb(k.raw_record),
                    )
                    for record in catalog.records
                    for k in [record.kev]
                ],
            )
    return len(ids)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["migrate", "ingest-kev"])
    args = parser.parse_args(argv)
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print("Set DATABASE_URL before running this command.", file=sys.stderr)
        return 1
    try:
        # Fetch and validate before opening a transaction or modifying the database.
        catalog = collect_kev() if args.command == "ingest-kev" else None
        with psycopg.connect(
            database_url, autocommit=True, connect_timeout=10
        ) as connection:
            migrate(connection)
            count = ingest_catalog(connection, catalog) if catalog is not None else None
    except (psycopg.Error, KevCollectionError, ValueError) as exc:
        # Driver messages may contain connection details; never print the DSN.
        print(f"Database command failed ({type(exc).__name__}).", file=sys.stderr)
        return 1
    print(json.dumps({"command": args.command, "processed": count}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
