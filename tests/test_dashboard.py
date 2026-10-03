"""Dashboard interaction and PostgreSQL query integration tests."""

import json
import os
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path

import psycopg
import pytest
from psycopg.conninfo import make_conninfo
from streamlit.testing.v1 import AppTest

from threatpulse.dashboard_data import (
    filter_vulnerabilities,
    load_cve_details,
    load_epss_comparison,
    load_epss_dates,
    load_vulnerabilities,
)
from threatpulse.epss import EPSS_URL, EpssBatch, EpssObservation
from threatpulse.kev import CISA_KEV_URL, CollectedVulnerability, KevCatalog
from threatpulse.models import parse_cisa_kev_record
from threatpulse.nvd import NVD_URL, NvdBatch, parse_nvd_record
from threatpulse.storage import ingest_catalog, ingest_epss, ingest_nvd, migrate

APP = str(Path(__file__).parents[1] / "src" / "threatpulse" / "dashboard.py")


class RedactedDsn(str):
    """Keep credentials out of pytest fixture/local-variable diagnostics."""

    def __repr__(self):
        return "<redacted database connection>"


@pytest.fixture
def dashboard_url(connection):
    migrate(connection)
    fixture_dir = Path(__file__).parent / "fixtures"
    raw = json.loads((fixture_dir / "cisa_kev_record.json").read_text())
    v, k = parse_cisa_kev_record(
        raw, source_url=CISA_KEV_URL, ingested_at=datetime(2026, 1, 1, tzinfo=UTC)
    )
    second_v = v.model_copy(
        update={
            "cve_id": "CVE-2026-12345",
            "vendor": "Other",
            "product": "Other product",
            "name": "Other vulnerability",
            "description": "Different test record",
        }
    )
    second_k = k.model_copy(update={"cve_id": second_v.cve_id})
    ingest_catalog(
        connection,
        KevCatalog(
            records=[
                CollectedVulnerability(vulnerability=v, kev=k),
                CollectedVulnerability(vulnerability=second_v, kev=second_k),
            ]
        ),
    )
    nvd = parse_nvd_record(
        json.loads((fixture_dir / "nvd_cve.json").read_text()),
        source_url=NVD_URL,
        ingested_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    ingest_nvd(connection, NvdBatch(records=[nvd], missing_cves=[]))
    observations = [
        EpssObservation(
            cve_id=v.cve_id,
            score_date=day,
            epss=score,
            percentile=Decimal("0.99"),
            source_url=EPSS_URL,
            ingested_at=datetime(2026, 1, 3, tzinfo=UTC),
            raw_record={},
        )
        for day, score in [
            (date(2026, 1, 1), Decimal("0.9")),
            (date(2026, 1, 2), Decimal("0.8")),
        ]
    ]
    ingest_epss(connection, EpssBatch(observations=observations, missing_cves=[]))
    schema = connection.execute("SELECT current_schema()").fetchone()[0]
    return RedactedDsn(
        make_conninfo(
            os.environ["TEST_DATABASE_URL"], options=f"-csearch_path={schema}"
        )
    )


def test_latest_scores_missing_enrichment_and_detail_queries(dashboard_url):
    rows = load_vulnerabilities(dashboard_url)
    assert len(rows) == 2
    assert rows[0]["epss"] == Decimal("0.8")
    assert rows[0]["score_date"] == date(2026, 1, 2)
    assert rows[1]["epss"] is None and rows[1]["severity"] is None
    details = load_cve_details(dashboard_url, rows[0]["cve_id"])
    assert len(details["epss_history"]) == 2
    assert details["required_action"]
    assert details["reference_urls"] == ["https://example.com/advisory"]
    assert load_cve_details(dashboard_url, "CVE-2026-99999") is None
    assert load_cve_details(dashboard_url, "' OR 1=1 --") is None


def test_filters_keep_unknown_scores_distinct(dashboard_url):
    rows = load_vulnerabilities(dashboard_url)
    assert len(filter_vulnerabilities(rows, search="apache")) == 1
    assert (
        len(filter_vulnerabilities(rows, vendors=["Other"], severities=["UNKNOWN"]))
        == 1
    )
    assert (
        len(filter_vulnerabilities(rows, min_epss=0.85, include_missing_epss=False))
        == 0
    )
    assert (
        len(filter_vulnerabilities(rows, min_epss=0.85, include_missing_epss=True)) == 1
    )
    assert len(filter_vulnerabilities(rows, search="[")) == 0
    with pytest.raises(ValueError):
        filter_vulnerabilities(rows, min_epss=2)


def test_exact_cve_search_ignores_mentions_in_other_descriptions(dashboard_url):
    rows = load_vulnerabilities(dashboard_url)
    rows[1]["description"] = "Related to CVE-2021-44228"
    result = filter_vulnerabilities(rows, search="cve-2021-44228")
    assert len(result) == 1 and result[0]["cve_id"] == "CVE-2021-44228"


def test_dashboard_real_database_and_interactions(dashboard_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", dashboard_url)
    app = AppTest.from_file(APP, default_timeout=20).run()
    assert not app.exception and not app.error
    assert app.metric[0].value == "2"
    assert app.metric[1].value == "1/2"
    assert app.metric[2].value == "1/2"
    assert len(app.dataframe[0].value) == 2
    assert app.dataframe[0].value.iloc[0]["EPSS (%)"] == 80.0
    app.text_input[0].set_value("Other").run()
    assert not app.exception
    assert len(app.dataframe[0].value) == 1
    assert any("No EPSS observations" in info.value for info in app.info)
    app.text_input[0].set_value("no-match").run()
    assert any("No vulnerabilities match" in info.value for info in app.info)
    app.text_input[0].set_value("").run()
    app.checkbox[0].uncheck().run()
    app.slider[0].set_value(85.0).run()
    assert any("No vulnerabilities match" in info.value for info in app.info)


def test_dashboard_missing_configuration(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    app = AppTest.from_file(APP).run()
    assert not app.exception
    assert "Set DATABASE_URL" in app.error[0].value


def test_analytics_dates_coverage_and_interactions(dashboard_url, monkeypatch):
    dates = load_epss_dates(dashboard_url)
    assert dates == [date(2026, 1, 1), date(2026, 1, 2)]
    compared = load_epss_comparison(dashboard_url, *dates)
    assert len(compared) == 1
    assert compared[0]["before"] == Decimal("0.9")
    assert compared[0]["after"] == Decimal("0.8")
    with pytest.raises(ValueError):
        load_epss_comparison(dashboard_url, dates[1], dates[0])
    monkeypatch.setenv("DATABASE_URL", dashboard_url)
    app = AppTest.from_file(APP, default_timeout=20).run()
    assert not app.exception and not app.error
    assert [tab.label for tab in app.tabs] == [
        "Overview",
        "Vulnerability explorer",
        "KEV analytics",
        "EPSS analytics",
    ]
    changes = app.dataframe[-1].value
    assert len(changes) == 1
    assert changes.iloc[0]["Change (percentage points)"] == -10.0
    assert any("1 stored CVEs are absent" in caption.value for caption in app.caption)
    app.text_input[0].set_value("no-match").run()
    assert not app.exception
    assert app.dataframe[-1].value.iloc[0]["Change (percentage points)"] == -10.0


def test_analytics_handles_one_sided_observations(dashboard_url, connection):
    connection.execute(
        "INSERT INTO epss_observations "
        "SELECT 'CVE-2026-12345', score_date, epss, percentile, "
        "source_url, ingested_at, raw_record "
        "FROM epss_observations WHERE score_date = '2026-01-02'"
    )
    rows = load_epss_comparison(dashboard_url, date(2026, 1, 1), date(2026, 1, 2))
    assert len(rows) == 2
    missing = next(row for row in rows if row["cve_id"] == "CVE-2026-12345")
    assert missing["before"] is None
    assert missing["after"] == Decimal("0.8")


def test_analytics_requires_two_dates(dashboard_url, connection, monkeypatch):
    connection.execute("DELETE FROM epss_observations WHERE score_date = '2026-01-01'")
    monkeypatch.setenv("DATABASE_URL", dashboard_url)
    app = AppTest.from_file(APP, default_timeout=20).run()
    assert not app.exception
    assert any("at least two dates" in info.value for info in app.info)


def test_analytics_date_controls_update_later_options(
    dashboard_url, connection, monkeypatch
):
    connection.execute(
        "INSERT INTO epss_observations "
        "SELECT cve_id, '2026-01-03'::date, epss, percentile, "
        "source_url, ingested_at, raw_record FROM epss_observations "
        "WHERE score_date = '2026-01-02'"
    )
    monkeypatch.setenv("DATABASE_URL", dashboard_url)
    app = AppTest.from_file(APP, default_timeout=20).run()
    app.selectbox(key="analytics_earlier").set_value(date(2026, 1, 1)).run()
    assert not app.exception
    assert app.selectbox(key="analytics_later").options == ["2026-01-02", "2026-01-03"]
    app.selectbox(key="analytics_earlier").set_value(date(2026, 1, 2)).run()
    assert not app.exception
    assert app.selectbox(key="analytics_later").options == ["2026-01-03"]


def test_analytics_empty_scores_are_unknown(dashboard_url, connection, monkeypatch):
    connection.execute("DELETE FROM epss_observations")
    monkeypatch.setenv("DATABASE_URL", dashboard_url)
    app = AppTest.from_file(APP, default_timeout=20).run()
    assert not app.exception and not app.error
    assert any(
        metric.label == "Scored CVEs" and metric.value == "0" for metric in app.metric
    )
    assert any("2 CVEs lack EPSS" in caption.value for caption in app.caption)
    assert any("No complete score pairs" in info.value for info in app.info)


def test_dashboard_empty_and_database_error(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "not-a-real-connection")
    monkeypatch.setattr(
        "threatpulse.dashboard_data.load_vulnerabilities", lambda url: []
    )
    app = AppTest.from_file(APP).run()
    assert not app.exception
    assert "No vulnerabilities" in app.info[0].value

    def fail(url):
        raise psycopg.OperationalError("sensitive connection details")

    monkeypatch.setattr("threatpulse.dashboard_data.load_vulnerabilities", fail)
    app.run()
    assert not app.exception
    assert "Could not load data" in app.error[0].value
    assert "sensitive" not in app.error[0].value
