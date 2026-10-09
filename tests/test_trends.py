"""Trend semantics, missingness, offline replay, and real snapshot queries."""

import hashlib
import json
import os
from datetime import UTC, date, datetime
from pathlib import Path

import psycopg
import pytest
from psycopg.types.json import Jsonb
from pydantic import ValidationError

from threatpulse.epss import EpssBatch
from threatpulse.kev import KevCatalog
from threatpulse.storage import ingest_catalog, ingest_epss, migrate
from threatpulse.trend_report import write_report
from threatpulse.trends import TrendDataset, analyze, main, read_dataset

FIXTURE = Path(__file__).parent / "fixtures" / "trend_dataset.json"
A, B, C, D = [f"CVE-2026-{1001 + i}" for i in range(4)]


@pytest.fixture
def dataset():
    return TrendDataset.model_validate_json(FIXTURE.read_text())


def test_kev_baseline_addition_removal_and_reappearance(dataset):
    result = analyze(dataset)["kev"]
    assert [c["added"] for c in result["captures"]] == [None, 1, 1]
    assert [c["removed"] for c in result["captures"]] == [None, 1, 0]
    assert [(e["cve_id"], e["kind"], e["reappearance"]) for e in result["events"]] == [
        (C, "added", False),
        (B, "removed", False),
        (B, "added", True),
    ]
    assert result["events"][0]["cisa_date_added"] == "2026-01-01"
    assert result["captures"][1]["run_status"] == "failed"


def test_source_chronology_uses_checkpoint_not_nominal_run_date(dataset):
    dataset.runs[1].run_date = date(2020, 1, 1)
    result = analyze(dataset, date(2026, 1, 1), date(2026, 1, 4))
    assert [c["run_id"] for c in result["kev"]["captures"]] == [1, 2, 3]
    assert [c["run_id"] for c in result["nvd"]["captures"]] == [1, 2, 3]


def test_window_first_capture_is_baseline(dataset):
    result = analyze(dataset, date(2026, 1, 2), date(2026, 1, 4))
    assert result["kev"]["captures"][0]["added"] is None
    assert result["kev"]["events"][0]["reappearance"] is False
    assert result["nvd"]["intervals"][0]["earlier_run_id"] == 2


def test_nvd_overlap_and_version_source_changes(dataset):
    result = analyze(dataset)["nvd"]
    first, second = result["intervals"]
    assert (first["matched"], first["earlier_only"], first["later_only"]) == (1, 1, 1)
    assert first["severity_changed"] == first["score_changed"] == 1
    assert result["pairs"][0]["score_change"] == 4.5
    assert result["pairs"][0]["earlier_metric"]["severity"] == "MEDIUM"
    assert result["pairs"][0]["later_metric"]["severity"] == "CRITICAL"
    assert second["matched"] == second["noncomparable"] == 2
    assert second["comparable"] == 0
    assert second["kind_counts"] == {"source_changed": 1, "version_changed": 1}
    assert all(p["score_change"] is None for p in result["pairs"][1:])


@pytest.mark.parametrize(
    "case",
    [
        "regression",
        "rejected",
        "metric_removed",
        "metric_added",
        "unscored",
        "unchanged",
        "metric_type_changed",
    ],
)
def test_nvd_noncomparable_and_unchanged_semantics(dataset, case):
    before = dataset.nvd_snapshots[0].observation
    after = dataset.nvd_snapshots[2].observation
    if case == "regression":
        after.modified_at = datetime(2025, 1, 1, tzinfo=UTC)
    elif case == "rejected":
        after.status = "Rejected"
    elif case in ("metric_removed", "unscored"):
        after.cvss_metrics = []
    elif case == "metric_type_changed":
        after.cvss_metrics[0].metric_type = "Secondary"
    if case in ("metric_added", "unscored"):
        before.cvss_metrics = []
    if case == "unchanged":
        after.cvss_metrics = before.cvss_metrics
    pair = analyze(dataset)["nvd"]["pairs"][0]
    if case == "unchanged":
        assert pair["comparable"] is True
        assert pair["score_change"] == 0
        assert pair["severity_changed"] is False
    else:
        assert pair["comparable"] is False
        assert pair["score_change"] is None
        assert pair["severity_changed"] is None
    if case == "regression":
        assert pair["modified_at_regressed"] is True
    elif case != "rejected":
        assert pair["kind"] == case


def test_nvd_stale_snapshot_count_is_not_latest_write_count(dataset):
    next(s for s in dataset.steps if s.source == "nvd" and s.run_id == 2).processed = 0
    validated = TrendDataset.model_validate_json(dataset.model_dump_json())
    capture = analyze(validated)["nvd"]["captures"][1]
    assert capture["observed"] == 2
    assert capture["latest_rows_written"] == 0


def test_epss_calendar_gaps_zero_scores_and_balanced_panel(dataset):
    result = analyze(dataset)["epss"]
    assert [r["observed"] for r in result["coverage"]] == [2, 2, 0, 3]
    assert [r["median_epss"] for r in result["coverage"]] == [0.4, 0.5, None, 0.6]
    assert [r["panel_median_epss"] for r in result["coverage"]] == [0, 0.1, None, 0.2]
    assert result["balanced_panel_cves"] == 1
    assert result["recorded_dates"] == 3
    assert result["gaps"] == [
        {"start_date": "2026-01-03", "end_date": "2026-01-03", "days": 1}
    ]
    series = {s["cve_id"]: s for s in result["series"]}
    assert series[A]["internal_gap_days"] == 1
    assert series[B]["internal_gap_days"] == 2
    assert series[D]["observed_dates"] == 0
    assert series[D]["missing_calendar_dates"] == 4


def test_epss_matched_changes_keep_missingness_and_elapsed_days(dataset):
    first, second = analyze(dataset)["epss"]["intervals"]
    assert (
        first["matched"],
        first["earlier_only"],
        first["later_only"],
        first["neither"],
    ) == (1, 1, 1, 1)
    assert first["change_pp_median"] == 10
    assert second["matched"] == 2
    assert second["change_pp_median"] == -10
    assert second["elapsed_days"] == 2
    assert second["unobserved_days_between"] == 1


def test_all_missing_date_with_completed_checkpoint(dataset):
    dataset.epss_observations = [
        e for e in dataset.epss_observations if e.score_date != date(2026, 1, 2)
    ]
    next(
        s for s in dataset.steps if s.source == "epss" and s.run_id == 2
    ).missing_cves = dataset.cohort.copy()
    coverage = analyze(dataset)["epss"]["coverage"][1]
    assert coverage["completed_daily_steps"] == 1
    assert coverage["checkpoint_missing_cves"] == 4
    assert coverage["median_epss"] is None


def test_empty_and_single_date_history(dataset):
    empty = TrendDataset(
        captured_at=dataset.captured_at,
        cohort=[],
        runs=[],
        steps=[],
        kev_snapshots=[],
        nvd_snapshots=[],
        epss_observations=[],
    )
    result = analyze(empty)
    assert result["cohort_cves"] == 0
    assert result["epss"]["balanced_panel_cves"] == 0
    assert result["epss"]["coverage"][0]["coverage_fraction"] is None
    single = analyze(dataset, date(2026, 1, 1), date(2026, 1, 1))
    assert single["epss"]["intervals"] == []
    assert single["kev"]["events"] == []
    assert single["nvd"]["pairs"] == []


@pytest.mark.parametrize(
    "start,end",
    [(date(2026, 1, 4), date(2026, 1, 1)), (date(2000, 1, 1), date(2026, 1, 1))],
)
def test_invalid_window(dataset, start, end):
    with pytest.raises(ValueError):
        analyze(dataset, start, end)


@pytest.mark.parametrize(
    "case",
    [
        "cohort",
        "run",
        "step",
        "snapshot",
        "epss",
        "orphan",
        "missing_snapshot",
        "count",
    ],
)
def test_invalid_export_is_rejected(dataset, case):
    data = dataset.model_dump(mode="json")
    if case in ("cohort", "run", "step", "snapshot", "epss"):
        key = {
            "cohort": "cohort",
            "run": "runs",
            "step": "steps",
            "snapshot": "nvd_snapshots",
            "epss": "epss_observations",
        }[case]
        data[key].append(data[key][0])
    elif case == "orphan":
        data["nvd_snapshots"][0]["run_id"] = 999
    elif case == "missing_snapshot":
        data["steps"][1]["missing_cves"].append(A)
    else:
        data["steps"][0]["processed"] = 99
    with pytest.raises(ValidationError):
        TrendDataset.model_validate(data)


def test_report_replay_and_artifact_integrity(dataset, tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    dataset.label = 'Synthetic <script>alert("x")</script>'
    expected = write_report(dataset, first)
    restored = TrendDataset.model_validate_json((first / "source.json").read_text())
    assert write_report(restored, second) == expected
    manifest = json.loads((first / "manifest.json").read_text())
    for name, digest in manifest["files_sha256"].items():
        assert hashlib.sha256((first / name).read_bytes()).hexdigest() == digest
        assert (first / name).read_bytes() == (second / name).read_bytes()
    assert len(list(first.glob("*.png"))) == 5
    document = (first / "report.html").read_text()
    assert "<script>" not in document
    assert "&lt;script&gt;" in document
    assert "Insufficient captures" not in document
    with pytest.raises(FileExistsError):
        write_report(dataset, first)


def test_cli_missing_url_invalid_input_and_redacted_error(
    monkeypatch, capsys, tmp_path
):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert main(["--output", str(tmp_path / "missing")]) == 1
    assert "Set DATABASE_URL" in capsys.readouterr().err
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"password":"must-not-appear"}')
    assert main(["--input", str(invalid), "--output", str(tmp_path / "invalid")]) == 1
    assert "must-not-appear" not in capsys.readouterr().err


def seed_history(connection, dataset):
    migrate(connection)
    records = {s.observation.kev.cve_id: s.observation for s in dataset.kev_snapshots}
    extra = records[A].model_copy(deep=True)
    extra.vulnerability.cve_id = extra.kev.cve_id = D
    ingest_catalog(connection, KevCatalog(records=[*records.values(), extra]))
    ingest_epss(
        connection, EpssBatch(observations=dataset.epss_observations, missing_cves=[])
    )
    for run in dataset.runs:
        connection.execute(
            "INSERT INTO ingestion_runs "
            "(id, run_date, started_at, finished_at, status) "
            "OVERRIDING SYSTEM VALUE VALUES (%s,%s,%s,%s,%s)",
            (run.id, run.run_date, run.started_at, run.finished_at, run.status),
        )
    for step in dataset.steps:
        connection.execute(
            "INSERT INTO ingestion_steps "
            "(run_id, source, processed, missing_cves, finished_at) "
            "VALUES (%s,%s,%s,%s,%s)",
            (
                step.run_id,
                step.source,
                step.processed,
                Jsonb(step.missing_cves),
                step.finished_at,
            ),
        )
    for table, snapshots in (
        ("kev_snapshots", dataset.kev_snapshots),
        ("nvd_snapshots", dataset.nvd_snapshots),
    ):
        for snapshot in snapshots:
            record = snapshot.observation
            cve = record.kev.cve_id if table == "kev_snapshots" else record.cve_id
            connection.execute(
                f"INSERT INTO {table} VALUES (%s,%s,%s)",
                (snapshot.run_id, cve, Jsonb(record.model_dump(mode="json"))),
            )


def test_postgres_reads_historical_snapshots_without_latest_nvd(connection, dataset):
    seed_history(connection, dataset)
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        actual = read_dataset(connection)
        assert connection.execute(
            "SELECT count(*) FROM nvd_enrichments"
        ).fetchone() == (0,)
        result = analyze(actual, date(2026, 1, 1), date(2026, 1, 4))
    assert result["kev"] == analyze(dataset)["kev"]
    assert result["nvd"] == analyze(dataset)["nvd"]
    assert result["epss"] == analyze(dataset)["epss"]


def test_database_cli_uses_consistent_readonly_transaction(
    connection, dataset, monkeypatch, tmp_path
):
    seed_history(connection, dataset)
    original_connect, original_read = psycopg.connect, read_dataset
    schema = connection.execute("SELECT current_schema()").fetchone()[0]
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])

    def connect(*args, **kwargs):
        return original_connect(*args, **kwargs, options=f"-c search_path={schema}")

    def read(conn):
        assert conn.execute("SHOW transaction_read_only").fetchone() == ("on",)
        assert conn.execute("SHOW transaction_isolation").fetchone() == (
            "repeatable read",
        )
        return original_read(conn)

    monkeypatch.setattr("threatpulse.trends.psycopg.connect", connect)
    monkeypatch.setattr("threatpulse.trends.read_dataset", read)
    assert main(["--output", str(tmp_path / "db")]) == 0
    assert connection.execute("SELECT count(*) FROM ingestion_runs").fetchone() == (3,)
