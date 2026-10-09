"""Daily recovery, history, and concurrency against isolated PostgreSQL schemas."""

from datetime import date

import psycopg
import pytest
from tests.test_storage import catalog as catalog_fixture
from tests.test_storage import epss_batch as epss_fixture
from tests.test_storage import nvd_batch as nvd_fixture

from threatpulse.daily import IngestionBusyError, ingestion_lock, run_daily
from threatpulse.epss import EpssCollectionError
from threatpulse.storage import migrate

catalog = catalog_fixture
epss_batch = epss_fixture
nvd_batch = nvd_fixture


def collectors(monkeypatch, catalog, epss_batch, nvd_batch):
    monkeypatch.setattr("threatpulse.daily.collect_kev", lambda: catalog)
    monkeypatch.setattr("threatpulse.daily.collect_epss", lambda *a, **k: epss_batch)
    monkeypatch.setattr("threatpulse.daily.collect_nvd", lambda *a, **k: nvd_batch)


def test_daily_history_and_idempotence(
    connection, monkeypatch, catalog, epss_batch, nvd_batch
):
    migrate(connection)
    collectors(monkeypatch, catalog, epss_batch, nvd_batch)
    with ingestion_lock(connection):
        first = run_daily(connection, date(2026, 1, 1))
        assert run_daily(connection, date(2026, 1, 1))["status"] == "already_succeeded"
        catalog.records[0].kev.required_action = "Changed action"
        run_daily(connection, date(2026, 1, 2))
    assert connection.execute("SELECT count(*) FROM ingestion_steps").fetchone() == (6,)
    assert connection.execute("SELECT count(*) FROM nvd_snapshots").fetchone() == (2,)
    observation = connection.execute(
        "SELECT observation FROM kev_snapshots WHERE run_id = %s", (first["run_id"],)
    ).fetchone()[0]
    assert observation["kev"]["required_action"] != "Changed action"


def test_failure_resumes_committed_step(
    connection, monkeypatch, catalog, epss_batch, nvd_batch
):
    migrate(connection)
    collectors(monkeypatch, catalog, epss_batch, nvd_batch)

    def fail(*args, **kwargs):
        raise EpssCollectionError("Synthetic failure")

    monkeypatch.setattr("threatpulse.daily.collect_epss", fail)
    with ingestion_lock(connection):
        with pytest.raises(EpssCollectionError):
            run_daily(connection, date(2026, 1, 1))
        assert connection.execute("SELECT status FROM ingestion_runs").fetchone() == (
            "failed",
        )
        monkeypatch.setattr("threatpulse.daily.collect_kev", fail)
        monkeypatch.setattr(
            "threatpulse.daily.collect_epss", lambda *a, **k: epss_batch
        )
        assert run_daily(connection, date(2026, 1, 1))["status"] == "succeeded"
    assert connection.execute("SELECT count(*) FROM kev_snapshots").fetchone() == (1,)


def test_overlap_and_release(connection):
    with psycopg.connect(connection.info.dsn, autocommit=True) as other:
        with ingestion_lock(connection):
            with pytest.raises(IngestionBusyError), ingestion_lock(other):
                pass
        with ingestion_lock(other):
            pass


def test_interrupted_run_recovered(
    connection, monkeypatch, catalog, epss_batch, nvd_batch
):
    migrate(connection)
    collectors(monkeypatch, catalog, epss_batch, nvd_batch)
    connection.execute(
        "INSERT INTO ingestion_runs (run_date, status) VALUES ('2025-12-31', 'running')"
    )
    with ingestion_lock(connection):
        run_daily(connection, date(2026, 1, 1))
    assert connection.execute(
        "SELECT status FROM ingestion_runs ORDER BY id"
    ).fetchall() == [("interrupted",), ("succeeded",)]


def test_snapshot_failure_rolls_back_source_and_checkpoint(
    connection, monkeypatch, catalog, epss_batch, nvd_batch
):
    migrate(connection)
    collectors(monkeypatch, catalog, epss_batch, nvd_batch)
    connection.execute(
        "ALTER TABLE kev_snapshots ADD CONSTRAINT reject_snapshot CHECK (false)"
    )
    with ingestion_lock(connection):
        with pytest.raises(psycopg.errors.CheckViolation):
            run_daily(connection, date(2026, 1, 1))
    assert connection.execute("SELECT count(*) FROM vulnerabilities").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM ingestion_steps").fetchone() == (0,)
    assert connection.execute("SELECT status FROM ingestion_runs").fetchone() == (
        "failed",
    )
