"""Real PostgreSQL tests; each test uses a fresh, isolated schema."""

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql

from threatpulse.kev import CISA_KEV_URL, CollectedVulnerability, KevCatalog
from threatpulse.models import parse_cisa_kev_record
from threatpulse.storage import ingest_catalog, main, migrate


@pytest.fixture
def connection():
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set TEST_DATABASE_URL to run real PostgreSQL integration tests")
    schema = "test_" + uuid4().hex
    with psycopg.connect(url, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        try:
            connection.execute(
                sql.SQL("SET search_path TO {}").format(sql.Identifier(schema))
            )
            yield connection
        finally:
            connection.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema))
            )


@pytest.fixture
def catalog():
    record = json.loads(
        (Path(__file__).parent / "fixtures" / "cisa_kev_record.json").read_text()
    )
    vulnerability, entry = parse_cisa_kev_record(
        record, source_url=CISA_KEV_URL, ingested_at=datetime(2026, 1, 1, tzinfo=UTC)
    )
    return KevCatalog(
        records=[CollectedVulnerability(vulnerability=vulnerability, kev=entry)]
    )


def test_migration_is_repeatable(connection):
    migrate(connection)
    migrate(connection)
    assert connection.execute("SELECT version FROM schema_migrations").fetchall() == [
        (1,)
    ]


def test_repeat_ingestion_updates_without_duplicates(connection, catalog):
    migrate(connection)
    assert ingest_catalog(connection, catalog) == 1
    assert ingest_catalog(connection, catalog) == 1
    assert connection.execute("SELECT count(*) FROM vulnerabilities").fetchone() == (1,)
    assert connection.execute("SELECT count(*) FROM kev_entries").fetchone() == (1,)
    catalog.records[0].vulnerability.description = "Updated description"
    catalog.records[0].kev.required_action = "Updated action"
    catalog.records[0].kev.raw_record["requiredAction"] = "Updated action"
    ingest_catalog(connection, catalog)
    assert connection.execute("SELECT description FROM vulnerabilities").fetchone() == (
        "Updated description",
    )
    action, raw, source, timestamp = connection.execute(
        "SELECT required_action, raw_record, source_url, ingested_at FROM kev_entries"
    ).fetchone()
    assert action == raw["requiredAction"] == "Updated action"
    assert source == CISA_KEV_URL
    assert timestamp == catalog.records[0].kev.ingested_at


def test_failed_batch_rolls_back_both_tables(connection, catalog):
    migrate(connection)
    ingest_catalog(connection, catalog)
    catalog.records[0].vulnerability.description = "Must roll back"
    connection.execute(
        "ALTER TABLE kev_entries ADD CONSTRAINT reject_action "
        "CHECK (required_action <> 'Rejected action')"
    )
    catalog.records[0].kev.required_action = "Rejected action"
    with pytest.raises(psycopg.errors.CheckViolation):
        ingest_catalog(connection, catalog)
    assert connection.execute("SELECT description FROM vulnerabilities").fetchone() != (
        "Must roll back",
    )
    assert connection.execute("SELECT count(*) FROM kev_entries").fetchone() == (1,)


def test_foreign_key_and_unique_constraints(connection, catalog):
    migrate(connection)
    ingest_catalog(connection, catalog)
    with pytest.raises(psycopg.errors.UniqueViolation), connection.transaction():
        connection.execute("INSERT INTO vulnerabilities SELECT * FROM vulnerabilities")
    with pytest.raises(psycopg.errors.ForeignKeyViolation), connection.transaction():
        connection.execute("DELETE FROM vulnerabilities")


def test_new_cve_inserted_and_absent_cve_retained(connection, catalog):
    migrate(connection)
    ingest_catalog(connection, catalog)
    newer = catalog.model_copy(deep=True)
    newer.records[0].vulnerability.cve_id = "CVE-2026-12345"
    newer.records[0].kev.cve_id = "CVE-2026-12345"
    newer.records[0].kev.raw_record["cveID"] = "CVE-2026-12345"
    ingest_catalog(connection, newer)
    ingest_catalog(connection, newer)
    assert connection.execute("SELECT count(*) FROM vulnerabilities").fetchone() == (2,)
    assert connection.execute("SELECT count(*) FROM kev_entries").fetchone() == (2,)


def test_reject_duplicate_and_mismatched_batches(connection, catalog):
    migrate(connection)
    catalog.records.append(catalog.records[0])
    with pytest.raises(ValueError, match="unique"):
        ingest_catalog(connection, catalog)
    catalog.records.pop()
    catalog.records[0].kev.cve_id = "CVE-2026-12345"
    with pytest.raises(ValueError, match="match"):
        ingest_catalog(connection, catalog)
    assert connection.execute("SELECT count(*) FROM vulnerabilities").fetchone() == (0,)


def test_cli_requires_database_url(monkeypatch, capsys):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert main(["migrate"]) == 1
    assert "Set DATABASE_URL" in capsys.readouterr().err
