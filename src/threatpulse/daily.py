"""Checkpointed daily ingestion. Invoke through threatpulse.storage ingest-daily."""

from contextlib import contextmanager
from datetime import UTC, date, datetime

from psycopg.types.json import Jsonb

from threatpulse.epss import collect_epss
from threatpulse.kev import collect_kev
from threatpulse.nvd import collect_nvd
from threatpulse.storage import ingest_catalog, ingest_epss, ingest_nvd

# Session lock spans network requests and committed source transactions.
INGESTION_LOCK = 734915005


class IngestionBusyError(RuntimeError):
    """Another ingestion command holds the database-wide lock."""


@contextmanager
def ingestion_lock(connection):
    if not connection.execute(
        "SELECT pg_try_advisory_lock(%s)", (INGESTION_LOCK,)
    ).fetchone()[0]:
        raise IngestionBusyError("Another ingestion command is running")
    try:
        yield
    finally:
        connection.execute("SELECT pg_advisory_unlock(%s)", (INGESTION_LOCK,))


def run_daily(connection, run_date: date | None = None) -> dict:
    """Caller holds ingestion_lock on an autocommit connection.

    Retry an incomplete day's latest attempt, skipping committed steps. A crash
    leaves a running row; the next lock holder can safely mark it interrupted.
    """
    run_date = run_date or datetime.now(UTC).date()
    connection.execute(
        "UPDATE ingestion_runs SET status = 'interrupted', finished_at = now(), "
        "error_type = 'ProcessInterrupted' WHERE status = 'running'"
    )
    previous = connection.execute(
        "SELECT id, status FROM ingestion_runs WHERE run_date = %s "
        "ORDER BY id DESC LIMIT 1",
        (run_date,),
    ).fetchone()
    if previous and previous[1] == "succeeded":
        return {"run_id": previous[0], "status": "already_succeeded"}
    # Reuse committed checkpoints, preserving the attempt's original snapshots.
    if previous:
        run_id = previous[0]
        connection.execute(
            "UPDATE ingestion_runs SET status = 'running', finished_at = NULL, "
            "error_type = NULL WHERE id = %s",
            (run_id,),
        )
    else:
        run_id = connection.execute(
            "INSERT INTO ingestion_runs (run_date, status) VALUES (%s, 'running') "
            "RETURNING id",
            (run_date,),
        ).fetchone()[0]
    try:
        completed = {
            r[0]
            for r in connection.execute(
                "SELECT source FROM ingestion_steps WHERE run_id = %s", (run_id,)
            )
        }
        for source in ("kev", "epss", "nvd"):
            if source in completed:
                continue
            ids = [
                r[0]
                for r in connection.execute(
                    "SELECT cve_id FROM vulnerabilities ORDER BY cve_id"
                )
            ]
            if source == "kev":
                batch = collect_kev()
            elif source == "epss":
                batch = collect_epss(ids, score_date=run_date)
            else:
                batch = collect_nvd(ids)
            with connection.transaction():
                if source == "kev":
                    count = ingest_catalog(connection, batch)
                    snapshots = [
                        (
                            run_id,
                            r.vulnerability.cve_id,
                            Jsonb(r.model_dump(mode="json")),
                        )
                        for r in batch.records
                    ]
                    with connection.cursor() as cursor:
                        cursor.executemany(
                            "INSERT INTO kev_snapshots VALUES (%s, %s, %s)", snapshots
                        )
                elif source == "epss":
                    count = ingest_epss(connection, batch)
                else:
                    count = ingest_nvd(connection, batch)
                    with connection.cursor() as cursor:
                        cursor.executemany(
                            "INSERT INTO nvd_snapshots VALUES (%s, %s, %s)",
                            [
                                (run_id, r.cve_id, Jsonb(r.model_dump(mode="json")))
                                for r in batch.records
                            ],
                        )
                connection.execute(
                    "INSERT INTO ingestion_steps (run_id, source, processed, "
                    "missing_cves) VALUES (%s, %s, %s, %s)",
                    (
                        run_id,
                        source,
                        count,
                        Jsonb([] if source == "kev" else batch.missing_cves),
                    ),
                )
        connection.execute(
            "UPDATE ingestion_runs SET status = 'succeeded', finished_at = now() "
            "WHERE id = %s",
            (run_id,),
        )
    except Exception as exc:
        # Store only the category: driver/HTTP messages may contain secrets.
        connection.execute(
            "UPDATE ingestion_runs SET status = 'failed', finished_at = now(), "
            "error_type = %s WHERE id = %s",
            (type(exc).__name__, run_id),
        )
        raise
    return {"run_id": run_id, "status": "succeeded"}
