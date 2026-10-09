"""Frozen cohort classification, same-date collection, persistence, and replay."""

import hashlib
import json
import os
from datetime import date
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from pydantic import ValidationError

from threatpulse.comparison import (
    ComparisonStudy,
    classify,
    collect_study,
    load_study,
    main,
    save_study,
)
from threatpulse.comparison_report import analyze, write_report
from threatpulse.nvd import NvdBatch
from threatpulse.storage import migrate

FIXTURE = Path(__file__).parent / "fixtures" / "comparison_study.json"


@pytest.fixture
def study():
    return ComparisonStudy.model_validate_json(FIXTURE.read_text())


def test_membership_exclusions_and_coverage(study):
    result = analyze(study)
    assert result["nvd_window_count"] == 12
    assert result["exclusions"] == {"excluded_rejected": 1, "excluded_kev_conflict": 1}
    for coverage in result["coverage"]:
        assert coverage == {
            "group": coverage["group"],
            "cves": 5,
            "cvss_scored": 4,
            "missing_cvss": 1,
            "epss_scored": 4,
            "missing_epss": 1,
            "complete_pairs": 4,
        }
    assert classify(study.nvd_records[0], set(study.kev_ids)) == "kev"
    assert classify(study.nvd_records[4], set(study.kev_ids)) == "non_kev"
    assert (
        classify(study.nvd_records[11], set(study.kev_ids)) == "excluded_kev_conflict"
    )


def test_zero_values_bins_denominators_and_version_separation(study):
    result = analyze(study)
    for group in ("kev", "non_kev"):
        bins = [
            r
            for r in result["distributions"]
            if r["metric"] == "epss" and r["group"] == group
        ]
        assert sum(r["count"] for r in bins) == 4
        assert sum(r["percent_of_scored"] for r in bins) == pytest.approx(100)
        assert bins[0]["count"] >= 1  # Zero is scored, distinct from missing.
    summaries = [r for r in result["summaries"] if r["metric"] == "cvss"]
    assert {r["n"] for r in summaries if r["cvss_version"] == "2.0"} == {1}
    assert {r["n"] for r in summaries if r["cvss_version"] == "3.1"} == {3}
    assert {r["n"] for r in summaries if r["cvss_version"] == "4.0"} == {0}
    delta = result["median_differences"][0]
    assert delta["median_difference"] == pytest.approx(59.45)
    assert delta["difference_unit"] == "percentage points"


def test_one_hundred_percent_final_bin(study):
    study.epss.observations[0].epss = Decimal(1)
    bins = [
        r
        for r in analyze(study)["distributions"]
        if r["group"] == "kev" and r["metric"] == "epss"
    ]
    assert bins[-1]["count"] == 1
    assert sum(r["count"] for r in bins) == 4


def test_empty_group_never_becomes_zero_distribution(study):
    study.kev_ids = [r.cve_id for r in study.nvd_records if r.status != "Rejected"]
    # Conflict becomes eligible KEV when CISA lists it; its missing score is explicit.
    study.epss.missing_cves.append(study.nvd_records[-1].cve_id)
    result = analyze(study)
    assert result["coverage"][1]["cves"] == 0
    assert all(
        r["percent_of_scored"] is None
        for r in result["distributions"]
        if r["group"] == "non_kev"
    )
    assert all(r["median_difference"] is None for r in result["median_differences"])


@pytest.mark.parametrize(
    "mutation",
    [
        "dates",
        "duplicate",
        "partial",
        "foreign",
        "double_missing",
        "rejected_score",
        "window",
    ],
)
def test_invalid_study_rejected(study, mutation):
    data = study.model_dump(mode="json")
    if mutation == "dates":
        data["epss"]["observations"][0]["score_date"] = "2026-02-01"
    elif mutation == "duplicate":
        data["nvd_records"].append(data["nvd_records"][0])
    elif mutation == "partial":
        data["epss"]["missing_cves"] = []
    elif mutation == "foreign":
        data["epss"]["missing_cves"].append("CVE-2026-9999")
    elif mutation == "double_missing":
        data["epss"]["missing_cves"].append(data["epss"]["observations"][0]["cve_id"])
    elif mutation == "rejected_score":
        data["epss"]["missing_cves"].append("CVE-2026-1010")
    else:
        data["definition"]["published_end"] = "2026-01-03"
    with pytest.raises(ValidationError):
        ComparisonStudy.model_validate(data)


def test_collects_union_with_one_explicit_score_date(study, monkeypatch):
    # Use the fixture's full catalog through a small mocked interface.
    from types import SimpleNamespace

    catalog = SimpleNamespace(
        records=[
            SimpleNamespace(
                kev=SimpleNamespace(cve_id=cve, ingested_at=study.kev_snapshot_at)
            )
            for cve in study.kev_ids
        ]
    )
    calls = []

    def nvd(start, end, **kwargs):
        assert (start, end) == (date(2026, 1, 1), date(2026, 2, 1))
        return NvdBatch(records=study.nvd_records, missing_cves=[])

    def epss(ids, *, score_date):
        calls.append((ids, score_date))
        return study.epss

    monkeypatch.setattr("threatpulse.comparison.collect_nvd_window", nvd)
    monkeypatch.setattr("threatpulse.comparison.collect_kev", lambda: catalog)
    monkeypatch.setattr("threatpulse.comparison.collect_epss", epss)
    collected = collect_study(study.definition)
    assert len(calls) == 1 and calls[0][1] == study.definition.score_date
    assert set(calls[0][0]) == {r.cve_id for r in study.nvd_records[:10]}
    assert collected.epss == study.epss


def test_frozen_database_roundtrip_and_no_dashboard_contamination(connection, study):
    migrate(connection)
    save_study(connection, study)
    assert load_study(connection, study.study_id) == study
    for name in (
        "vulnerabilities",
        "kev_entries",
        "nvd_enrichments",
        "epss_observations",
    ):
        assert connection.execute(f"SELECT count(*) FROM {name}").fetchone() == (0,)
    with pytest.raises(psycopg.errors.UniqueViolation):
        save_study(connection, study)
    assert load_study(connection, study.study_id) == study
    with pytest.raises(ValueError):
        load_study(connection, uuid4())


def test_invalid_study_cannot_be_persisted(connection, study):
    migrate(connection)
    study.epss.missing_cves = []
    with pytest.raises(ValidationError):
        save_study(connection, study)
    assert connection.execute("SELECT count(*) FROM comparison_studies").fetchone() == (
        0,
    )


def test_report_replay_hashes_and_escaped_text(study, tmp_path):
    study.label = '<script>alert("fixture")</script>'
    first = write_report(study, tmp_path / "first")
    replay = ComparisonStudy.model_validate_json(
        (tmp_path / "first/source.json").read_text()
    )
    second = write_report(replay, tmp_path / "second")
    assert first == second
    assert (tmp_path / "first/epss-distribution.svg").read_bytes() == (
        tmp_path / "second/epss-distribution.svg"
    ).read_bytes()
    manifest = json.loads((tmp_path / "first/manifest.json").read_text())
    for name, digest in manifest["files_sha256"].items():
        assert (
            hashlib.sha256((tmp_path / "first" / name).read_bytes()).hexdigest()
            == digest
        )
    text = (tmp_path / "first/report.html").read_text()
    assert "<script>" not in text and "&lt;script&gt;" in text
    assert "<svg" in text and "scored CVEs" in text
    with pytest.raises(FileExistsError):
        write_report(study, tmp_path / "first")


def test_cli_missing_database_and_offline_replay(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert (
        main(
            [
                "collect",
                "--published-start",
                "2026-01-01",
                "--published-end",
                "2026-02-01",
                "--score-date",
                "2026-02-02",
                "--output",
                str(tmp_path / "no-db"),
            ]
        )
        == 1
    )
    assert "Set DATABASE_URL" in capsys.readouterr().err
    assert (
        main(["report", "--input", str(FIXTURE), "--output", str(tmp_path / "report")])
        == 0
    )
    assert json.loads(capsys.readouterr().out)["study_id"]
    assert (
        main(["report", "--input", str(FIXTURE), "--output", str(tmp_path / "report")])
        == 1
    )


@pytest.fixture
def cli_database(connection, monkeypatch):
    from psycopg import sql

    original_connect = psycopg.connect
    schema = connection.execute("SELECT current_schema()").fetchone()[0]

    def isolated_connect(*args, **kwargs):
        conn = original_connect(*args, **kwargs)
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        return conn

    # Connection.info.dsn omits passwords needed for a new session.
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr("threatpulse.comparison.psycopg.connect", isolated_connect)
    return connection


def collect_args(output):
    return [
        "collect",
        "--published-start",
        "2026-01-01",
        "--published-end",
        "2026-02-01",
        "--score-date",
        "2026-02-02",
        "--output",
        str(output),
    ]


def test_cli_collect_persist_and_database_replay(
    cli_database, study, monkeypatch, tmp_path
):
    def collect(definition):
        assert definition == study.definition
        return study

    monkeypatch.setattr("threatpulse.comparison.collect_study", collect)
    assert main(collect_args(tmp_path / "collected")) == 0
    assert load_study(cli_database, study.study_id) == study
    assert (
        main(
            [
                "report",
                "--study-id",
                str(study.study_id),
                "--output",
                str(tmp_path / "replayed"),
            ]
        )
        == 0
    )
    assert (tmp_path / "collected/analysis.json").read_bytes() == (
        tmp_path / "replayed/analysis.json"
    ).read_bytes()


def test_cli_overlap_prevents_network_collection(cli_database, monkeypatch, tmp_path):
    from threatpulse.daily import ingestion_lock

    def unexpected(definition):
        pytest.fail("Collection must not begin while another ingestion holds the lock")

    monkeypatch.setattr("threatpulse.comparison.collect_study", unexpected)
    with ingestion_lock(cli_database):
        assert main(collect_args(tmp_path / "blocked")) == 1
    assert not (tmp_path / "blocked").exists()
    assert cli_database.execute(
        "SELECT count(*) FROM comparison_studies"
    ).fetchone() == (0,)


def test_cli_failed_collection_creates_no_study(
    cli_database, monkeypatch, tmp_path, capsys
):
    from threatpulse.epss import EpssCollectionError

    def failed(definition):
        raise EpssCollectionError("Secret-like diagnostic must not be printed")

    monkeypatch.setattr("threatpulse.comparison.collect_study", failed)
    assert main(collect_args(tmp_path / "failed")) == 1
    error = capsys.readouterr().err
    assert "EpssCollectionError" in error and "Secret-like" not in error
    assert cli_database.execute(
        "SELECT count(*) FROM comparison_studies"
    ).fetchone() == (0,)
    assert not (tmp_path / "failed").exists()


def test_upgrade_from_four_preserves_daily_runs(connection):
    from importlib.resources import files

    for filename in ("001_initial.sql", "002_epss.sql", "003_nvd.sql", "004_daily.sql"):
        connection.execute(
            files("threatpulse").joinpath(f"migrations/{filename}").read_text()
        )
    connection.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY)")
    connection.execute("INSERT INTO schema_migrations VALUES (1), (2), (3), (4)")
    connection.execute(
        "INSERT INTO ingestion_runs (run_date, status) "
        "VALUES ('2026-01-01', 'succeeded')"
    )
    migrate(connection)
    assert connection.execute("SELECT status FROM ingestion_runs").fetchone() == (
        "succeeded",
    )
    assert connection.execute("SELECT count(*) FROM comparison_studies").fetchone() == (
        0,
    )
