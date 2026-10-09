"""Transactional PostgreSQL migrations and CVE-keyed KEV ingestion."""

import argparse
import json
import os
import sys
from datetime import date
from importlib.resources import files

import psycopg
from psycopg.types.json import Jsonb

from threatpulse.epss import EpssBatch, EpssCollectionError, collect_epss
from threatpulse.kev import KevCatalog, KevCollectionError, collect_kev
from threatpulse.nvd import NvdBatch, NvdCollectionError, collect_nvd


def migrate(connection: psycopg.Connection) -> None:
    """Apply pending packaged migrations in one serialized transaction."""
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
        migrations = {
            1: "001_initial.sql",
            2: "002_epss.sql",
            3: "003_nvd.sql",
            4: "004_daily.sql",
            5: "005_comparison.sql",
        }
        if versions - migrations.keys():
            raise ValueError("Database has migrations newer than this application")
        for version, filename in migrations.items():
            if version not in versions:
                sql = (
                    files("threatpulse").joinpath(f"migrations/{filename}").read_text()
                )
                connection.execute(sql)
                connection.execute(
                    "INSERT INTO schema_migrations (version) VALUES (%s)", (version,)
                )


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


def ingest_epss(connection: psycopg.Connection, batch: EpssBatch) -> int:
    """Upsert same-date observations atomically, retaining other dates."""
    keys = [(o.cve_id, o.score_date) for o in batch.observations]
    if len(keys) != len(set(keys)):
        raise ValueError("EPSS batch contains duplicate CVE/date observations")
    with connection.transaction():
        connection.execute("SELECT pg_advisory_xact_lock(734915003)")
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO epss_observations
                    (cve_id, score_date, epss, percentile, source_url,
                     ingested_at, raw_record)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id, score_date) DO UPDATE SET
                    epss = EXCLUDED.epss, percentile = EXCLUDED.percentile,
                    source_url = EXCLUDED.source_url,
                    ingested_at = EXCLUDED.ingested_at, raw_record = EXCLUDED.raw_record
                """,
                [
                    (
                        o.cve_id,
                        o.score_date,
                        o.epss,
                        o.percentile,
                        str(o.source_url),
                        o.ingested_at,
                        Jsonb(o.raw_record),
                    )
                    for o in batch.observations
                ],
            )
    return len(keys)


def ingest_nvd(connection: psycopg.Connection, batch: NvdBatch) -> int:
    """Atomically replace the latest NVD snapshot, retaining KEV attributes."""
    ids = [r.cve_id for r in batch.records]
    if len(ids) != len(set(ids)):
        raise ValueError("NVD batch contains duplicate CVEs")
    values = []
    for record in batch.records:
        metric = record.preferred_cvss
        values.append(
            (
                record.cve_id,
                record.published_at,
                record.modified_at,
                record.status,
                record.description,
                Jsonb([str(url) for url in record.references]),
                Jsonb(record.weaknesses),
                Jsonb([m.model_dump(mode="json") for m in record.cvss_metrics]),
                metric.version if metric else None,
                metric.source if metric else None,
                metric.base_score if metric else None,
                metric.severity if metric else None,
                metric.attack_vector if metric else None,
                str(record.source_url),
                record.ingested_at,
                Jsonb(record.raw_record),
            )
        )
    with connection.transaction():
        connection.execute("SELECT pg_advisory_xact_lock(734915004)")
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO nvd_enrichments
                    (cve_id, published_at, modified_at, status, description,
                     reference_urls, weaknesses, cvss_metrics, cvss_version,
                     cvss_source, base_score, severity, attack_vector,
                     source_url, ingested_at, raw_record)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    published_at = EXCLUDED.published_at,
                    modified_at = EXCLUDED.modified_at, status = EXCLUDED.status,
                    description = EXCLUDED.description,
                    reference_urls = EXCLUDED.reference_urls,
                    weaknesses = EXCLUDED.weaknesses,
                    cvss_metrics = EXCLUDED.cvss_metrics,
                    cvss_version = EXCLUDED.cvss_version,
                    cvss_source = EXCLUDED.cvss_source,
                    base_score = EXCLUDED.base_score, severity = EXCLUDED.severity,
                    attack_vector = EXCLUDED.attack_vector,
                    source_url = EXCLUDED.source_url,
                    ingested_at = EXCLUDED.ingested_at,
                    raw_record = EXCLUDED.raw_record
                WHERE EXCLUDED.modified_at >= nvd_enrichments.modified_at
                """,
                values,
            )
    return len(ids)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=["migrate", "ingest-kev", "ingest-epss", "ingest-nvd", "ingest-daily"],
    )
    parser.add_argument(
        "--limit", type=int, help="Maximum stored CVEs to enrich with NVD"
    )
    parser.add_argument(
        "--date", type=date.fromisoformat, help="EPSS score date (YYYY-MM-DD)"
    )
    args = parser.parse_args(argv)
    if args.limit is not None and (args.command != "ingest-nvd" or args.limit <= 0):
        parser.error("--limit must be positive and used with ingest-nvd")
    if args.date and args.command not in {"ingest-epss", "ingest-daily"}:
        parser.error("--date is only supported for ingest-epss and ingest-daily")
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print("Set DATABASE_URL before running this command.", file=sys.stderr)
        return 1
    from threatpulse.daily import IngestionBusyError, ingestion_lock, run_daily

    try:
        with psycopg.connect(
            database_url, autocommit=True, connect_timeout=10
        ) as connection:
            migrate(connection)
            with ingestion_lock(connection):
                if args.command == "ingest-daily":
                    print(json.dumps(run_daily(connection, args.date)))
                    return 0
                catalog = collect_kev() if args.command == "ingest-kev" else None
                count = (
                    ingest_catalog(connection, catalog) if catalog is not None else None
                )
                if args.command in {"ingest-epss", "ingest-nvd"}:
                    ids = [
                        r[0]
                        for r in connection.execute(
                            "SELECT cve_id FROM vulnerabilities ORDER BY cve_id"
                        )
                    ]
                    if not ids:
                        raise ValueError("Ingest KEV before requesting EPSS enrichment")
                    if args.command == "ingest-epss":
                        batch = collect_epss(ids, score_date=args.date)
                        count = ingest_epss(connection, batch)
                    else:
                        ids = ids[: args.limit] if args.limit else ids
                        batch = collect_nvd(ids)
                        count = ingest_nvd(connection, batch)
                    print(
                        json.dumps(
                            {
                                "command": args.command,
                                "requested": len(ids),
                                "processed": count,
                                "missing": batch.missing_cves,
                            }
                        )
                    )
                    return 0
    except NvdCollectionError as exc:
        print(f"NVD collection failed: {exc}", file=sys.stderr)
        return 1
    except (
        IngestionBusyError,
        psycopg.Error,
        KevCollectionError,
        EpssCollectionError,
        ValueError,
    ) as exc:
        # Driver messages may contain connection details; never print the DSN.
        print(f"Database command failed ({type(exc).__name__}).", file=sys.stderr)
        return 1
    print(json.dumps({"command": args.command, "processed": count}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
