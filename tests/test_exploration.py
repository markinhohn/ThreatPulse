"""Check exact-date cohort semantics, correlations, replay, and database reads."""

import json
import os
from datetime import date
from pathlib import Path

import psycopg
import pytest
from psycopg import sql
from pydantic import ValidationError
from tests.test_storage import catalog as catalog_fixture
from tests.test_storage import epss_batch as epss_fixture
from tests.test_storage import nvd_batch as nvd_fixture

from threatpulse.exploration import Dataset, analyze, main, read_dataset, write_report
from threatpulse.storage import ingest_catalog, ingest_epss, ingest_nvd, migrate

catalog = catalog_fixture
epss_batch = epss_fixture
nvd_batch = nvd_fixture
FIXTURE = Path(__file__).parent / "fixtures" / "exploration_dataset.json"


@pytest.fixture
def dataset():
    return Dataset.model_validate_json(FIXTURE.read_text())


def test_exact_date_coverage_and_version_specific_associations(dataset):
    result = analyze(dataset)
    assert result["score_date"] == "2026-01-02"
    assert result["coverage"] == {
        "stored_cves": 12,
        "stored_kev_entries": 12,
        "nvd_enriched": 10,
        "cvss_scored": 10,
        "missing_cvss": 2,
        "epss_scored": 10,
        "missing_epss": 2,
        "complete_pairs": 9,
    }
    versions = {r["cvss_version"]: r for r in result["relationships"]}
    assert versions["3.1"]["pearson_r"] == pytest.approx(1)
    assert versions["3.1"]["spearman_rho"] == pytest.approx(1)
    assert versions["4.0"]["pearson_r"] == pytest.approx(-1)
    assert versions["2.0"]["pearson_r"] is None
    assert versions["2.0"]["unavailable_reason"] == "Constant score series"
    assert versions["3.0"]["missing_epss"] == 1
    assert result["epss_summary"]["min"] == 0
    earlier = analyze(dataset, score_date=date(2026, 1, 1))
    assert earlier["relationships"][1]["paired"] == 1


def test_exact_endpoint_changes_and_coverage(dataset):
    result = analyze(dataset)
    comparison = result["comparison"]
    assert comparison["matched"] == 9
    assert comparison["earlier_only"] == comparison["later_only"] == 1
    assert comparison["neither"] == 1
    assert comparison["increased"] == 3
    assert comparison["decreased"] == 1
    assert comparison["unchanged"] == 5
    assert result["changes"][0]["change_pp"] == 30
    assert result["changes"][-1]["change_pp"] == -10
    assert result["history_coverage"] == [
        {"score_date": "2026-01-01", "observed": 10, "missing": 2},
        {"score_date": "2026-01-02", "observed": 10, "missing": 2},
    ]


@pytest.mark.parametrize(
    "options",
    [
        {"score_date": date(2025, 1, 1)},
        {"earlier": date(2026, 1, 1)},
        {"earlier": date(2026, 1, 2), "later": date(2026, 1, 1)},
    ],
)
def test_invalid_date_selection(dataset, options):
    with pytest.raises(ValueError):
        analyze(dataset, **options)


def test_empty_and_single_date_data(dataset):
    empty = dataset.model_copy(update={"vulnerabilities": [], "epss_observations": []})
    result = analyze(empty)
    assert result["epss_summary"]["median"] is None
    assert result["comparison"]["earlier"] is None
    dataset.epss_observations = [
        e for e in dataset.epss_observations if e.score_date == date(2026, 1, 1)
    ]
    assert analyze(dataset)["changes"] == []


@pytest.mark.parametrize("mutation", ["duplicate", "foreign", "range"])
def test_replay_validation(dataset, mutation):
    data = dataset.model_dump(mode="json")
    if mutation == "duplicate":
        data["epss_observations"].append(data["epss_observations"][0])
    elif mutation == "foreign":
        data["epss_observations"][0]["cve_id"] = "CVE-2026-9999"
    else:
        data["epss_observations"][0]["epss"] = "NaN"
    with pytest.raises(ValidationError):
        Dataset.model_validate(data)


def test_report_replay_escape_and_no_overwrite(dataset, tmp_path):
    dataset.label = '<script>alert("fixture")</script>'
    first = write_report(dataset, tmp_path / "first")
    replay = Dataset.model_validate_json((tmp_path / "first/source.json").read_text())
    second = write_report(replay, tmp_path / "second")
    assert first == second
    assert (tmp_path / "first/analysis.json").read_bytes() == (
        tmp_path / "second/analysis.json"
    ).read_bytes()
    assert (tmp_path / "first/epss-distribution.svg").read_bytes() == (
        tmp_path / "second/epss-distribution.svg"
    ).read_bytes()
    text = (tmp_path / "first/report.html").read_text()
    assert "<script>" not in text and "&lt;script&gt;" in text
    assert "<svg" in text and "source SHA-256" in text
    with pytest.raises(FileExistsError):
        write_report(dataset, tmp_path / "first")


def test_cli_offline_and_missing_configuration(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert main(["--output", str(tmp_path / "no-db")]) == 1
    assert "Set DATABASE_URL" in capsys.readouterr().err
    assert main(["--input", str(FIXTURE), "--output", str(tmp_path / "report")]) == 0
    assert json.loads(capsys.readouterr().out)["report"].endswith("report.html")
    assert main(["--input", str(FIXTURE), "--output", str(tmp_path / "report")]) == 1


def test_read_only_snapshot(connection, catalog, epss_batch, nvd_batch):
    migrate(connection)
    ingest_catalog(connection, catalog)
    ingest_epss(connection, epss_batch)
    ingest_nvd(connection, nvd_batch)
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        initial = read_dataset(connection)
        assert len(initial.vulnerabilities) == len(initial.epss_observations) == 1
        assert initial.vulnerabilities[0].base_score is not None
        # A concurrent writer cannot change the report's database snapshot.
        schema = connection.execute("SELECT current_schema()").fetchone()[0]
        with psycopg.connect(os.environ["TEST_DATABASE_URL"], autocommit=True) as other:
            other.execute(
                sql.SQL("SET search_path TO {}").format(sql.Identifier(schema))
            )
            other.execute("DELETE FROM epss_observations")
        assert read_dataset(connection).epss_observations == initial.epss_observations
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            connection.execute("DELETE FROM epss_observations")


def test_spearman_ties_use_average_ranks(dataset):
    from decimal import Decimal

    selected = [v for v in dataset.vulnerabilities if v.cvss_version == "3.1"]
    for cve, score in zip(selected, ("1", "1", "2"), strict=True):
        cve.base_score = Decimal(score)
    relationship = next(
        r for r in analyze(dataset)["relationships"] if r["cvss_version"] == "3.1"
    )
    assert relationship["spearman_rho"] == pytest.approx(3**0.5 / 2)
