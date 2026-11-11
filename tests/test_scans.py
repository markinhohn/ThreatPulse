"""Native scanner formats, safe parsing, asset queues, persistence and replay."""

import base64
import csv
import io
import subprocess
import sys
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from xml.etree import ElementTree as ET

import psycopg
import pytest
from pydantic import ValidationError
from streamlit.testing.v1 import AppTest
from tests.test_tracking import sources as sources_fixture

from threatpulse import scan_worklist as sw
from threatpulse.daily import ingestion_lock
from threatpulse.priority import PriorityDataset
from threatpulse.scan_dashboard import resources, sample
from threatpulse.scan_import import (
    MAX_BYTES,
    ScanImportError,
    ScanReport,
    parse_scan,
)
from threatpulse.storage import migrate

sources = sources_fixture
APP = str(Path(__file__).parents[1] / "src/threatpulse/dashboard.py")
DECISION = datetime(2026, 1, 10, 12, tzinfo=UTC)


def raw(scanner, format="xml"):
    return resources().joinpath(f"{scanner}.{format}").read_bytes()


@pytest.mark.parametrize(
    "scanner,format,assets,findings",
    [
        ("nessus", "xml", 2, 3),
        ("nessus", "csv", 2, 2),
        ("openvas", "xml", 1, 2),
        ("openvas", "csv", 1, 2),
        ("nmap", "xml", 1, 4),
    ],
)
def test_native_formats_preserve_assets_findings_and_original_bytes(
    scanner, format, assets, findings
):
    data = raw(scanner, format)
    report = parse_scan(data, scanner, format, filename="C:\\private\\export." + format)
    assert len(report.assets) == assets and len(report.findings) == findings
    assert report.filename == "export." + format
    assert base64.b64decode(report.raw_base64) == data
    assert ScanReport.model_validate_json(report.model_dump_json()) == report
    assert parse_scan(data, scanner, format).scan_id == report.scan_id
    assert parse_scan(data, scanner, format, synthetic=True).scan_id != report.scan_id


def test_nessus_multi_cves_configuration_findings_and_score_versions():
    report = parse_scan(raw("nessus"), "nessus", "xml")
    assert report.findings[0].cves == ["CVE-2026-3001", "CVE-2026-3002"]
    assert report.findings[0].scanner_score_version == "3.1"
    assert report.assets[0].credentialed is True
    assert report.findings[-1].cves == [] and report.findings[-1].solution
    csv_report = parse_scan(raw("nessus", "csv"), "nessus", "csv")
    assert csv_report.findings[0].scanner_score_version == "3.0"


def test_openvas_qod_and_partial_export_are_visible():
    report = parse_scan(raw("openvas"), "openvas", "xml")
    assert report.findings[0].qod_percent == 80
    assert report.findings[0].solution == "Review the lab package."
    assert report.coverage["reported_full_results"] == 3
    assert "FILTERED_OR_PARTIAL_EXPORT" in report.warnings


def test_nmap_services_are_not_automatically_cves_or_confirmed_vulnerabilities():
    report = parse_scan(raw("nmap"), "nmap", "xml")
    assert len(report.assets[0].services) == 3
    assert report.assets[0].services[-1].state == "closed"
    inventory = [f for f in report.findings if f.rule_id == "service-inventory"]
    assert all(not f.cves for f in inventory)
    assert report.findings[-1].status == "negative"
    assert sw.requested_cves(report) == ["CVE-2026-3002"]


def test_nmap_mixed_vulnerability_states_are_scoped_to_their_own_table():
    data = b"""<!DOCTYPE nmaprun><nmaprun><host>
    <address addr="192.0.2.1" addrtype="ipv4"/><hostscript><script id="example">
    <table key="CVE-2026-3001"><elem key="state">VULNERABLE</elem></table>
    <table key="CVE-2026-3002"><elem key="state">NOT VULNERABLE</elem></table>
    </script></hostscript></host></nmaprun>"""
    report = parse_scan(data, "nmap", "xml")
    assert [(f.cves, f.status) for f in report.findings] == [
        (["CVE-2026-3001"], "candidate"),
        (["CVE-2026-3002"], "negative"),
    ]
    assert all(f.rule_id == "example" for f in report.findings)


@pytest.mark.parametrize(
    "scanner,format", [("nmap", "csv"), ("openvas", "xml"), ("nmap", "xml")]
)
def test_wrong_scanner_or_format_is_rejected(scanner, format):
    with pytest.raises(ScanImportError):
        parse_scan(raw("nessus"), scanner, format)


@pytest.mark.parametrize(
    "payload",
    [
        b"not xml",
        b"<NessusClientData_v2><Report>",
        b'<!DOCTYPE nmaprun [<!ENTITY x "boom">]><nmaprun>&x;</nmaprun>',
    ],
)
def test_malformed_xml_and_entities_fail_closed(payload):
    with pytest.raises(ScanImportError):
        parse_scan(payload, "nmap", "xml")


def test_external_entity_cannot_read_a_file(tmp_path):
    canary = tmp_path / "canary.txt"
    canary.write_text("private-canary-value")
    data = (
        f'<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "{canary.as_uri()}">]>'
        '<nmaprun><host><address addr="&x;" addrtype="ipv4"/>'
        "</host></nmaprun>"
    ).encode()
    with pytest.raises(ScanImportError) as error:
        parse_scan(data, "nmap", "xml")
    assert "private-canary-value" not in str(error.value)


def test_limits_depth_and_wrong_csv_structure():
    for data in [
        b"",
        b"x" * (MAX_BYTES + 1),
        b"<nmaprun>" + b"<node>" * 130 + b"</node>" * 130 + b"</nmaprun>",
    ]:
        with pytest.raises(ScanImportError):
            parse_scan(data, "nmap", "xml")
    for data in [
        b"Host,CVE\nhost,CVE-2026-3001\n",
        b"Host,Plugin ID,Name\nhost,1,name,extra\n",
        b"Host,Host,Plugin ID\na,b,1\n",
    ]:
        with pytest.raises(ScanImportError):
            parse_scan(data, "nessus", "csv")


def test_csv_bom_multiline_unknown_cves_and_zero_scores():
    data = (
        "\ufeffHost,Plugin ID,CVE,Risk,Description,CVSS v2.0 Base Score\n"
        '192.0.2.1,1,"cve-2026-3001; CVE-bad",High,"line one\nline two",0\n'
    ).encode()
    report = parse_scan(data, "nessus", "csv")
    assert report.findings[0].cves == ["CVE-2026-3001"]
    assert "UNPARSED_CVE_REFERENCE" in report.findings[0].flags
    assert report.findings[0].scanner_score == 0
    assert report.findings[0].scanner_score_version == "2.0"
    assert "\n" in report.findings[0].description


def test_scan_times_are_not_invented_from_naive_dates():
    report = parse_scan(raw("nessus", "csv"), "nessus", "csv")
    assert report.scanned_at is None
    fixed = parse_scan(raw("nessus", "csv"), "nessus", "csv", scanned_at=DECISION)
    assert all(a.scanned_at == DECISION for a in fixed.assets)
    assert report.scan_id != fixed.scan_id
    with pytest.raises(ScanImportError):
        parse_scan(raw("nessus"), "nessus", "xml", scanned_at=datetime(2026, 1, 10))


def test_zero_cvss_alone_cannot_suppress_a_reported_cve():
    report = parse_scan(
        b"Host,Plugin ID,CVE,CVSS v3.0 Base Score\n192.0.2.1,1,CVE-2026-3001,0\n",
        "nessus",
        "csv",
    )
    assert report.findings[0].scanner_score == 0
    assert report.findings[0].status == "reported"
    assert sw.requested_cves(report) == ["CVE-2026-3001"]


def test_unknown_intelligence_and_configuration_items_are_retained():
    report = parse_scan(raw("nessus"), "nessus", "xml")
    assessment = sw.assess(report, decision_at=DECISION)
    rows = sw.worklist(report, assessment)
    assert {r["priority"] for r in rows} == {"UNDETERMINED", "SCANNER_REVIEW"}
    assert all(r["epss"] is None for r in rows)
    assert all(r["next_action"] for r in rows)


def test_demo_queues_are_separate_from_match_confidence_and_have_provenance():
    report, assessment = sample("nessus", "xml")
    rows = sw.worklist(report, assessment)
    assert [r["priority"] for r in rows] == ["P1", "P2", "SCANNER_REVIEW", "P3"]
    assert all(r["synthetic"] for r in rows)
    assert rows[0]["match_basis"] == "Scanner-reported CVE"
    assert rows[2]["match_basis"] == "Scanner finding without a CVE"
    nmap, nmap_assessment = sample("nmap", "xml")
    items = sw.worklist(nmap, nmap_assessment)
    assert items[0]["priority"] == "P2" and "Unverified" in items[0]["match_basis"]
    assert all(
        r["priority"] == "NOT_RANKED" for r in items if r["cve_id"] == "CVE-2026-3001"
    )


def test_synthetic_intelligence_cannot_be_mixed_into_an_undeclared_scan():
    report = parse_scan(raw("nessus"), "nessus", "xml")
    intel = PriorityDataset.model_validate_json(
        resources().joinpath("intelligence.json").read_text()
    )
    with pytest.raises(ValueError, match="Synthetic"):
        sw.assess(report, intel, decision_at=DECISION)


def test_previous_assessment_blocks_an_unreviewed_downgrade():
    report, first = sample("nessus", "xml")
    intel = first.intelligence.model_copy(deep=True)
    for e in intel.epss_observations:
        if e.cve_id == "CVE-2026-3002":
            e.epss = "0.001"
    second = sw.assess(
        report, intel, decision_at=DECISION + timedelta(minutes=1), previous=first
    )
    row = next(r for r in sw.worklist(report, second) if r["cve_id"] == "CVE-2026-3002")
    assert row["candidate_priority"] == "P4" and row["priority"] == "P2"
    assert "DOWNGRADE_REVIEW_REQUIRED" in row["quality_flags"]


@pytest.mark.parametrize(
    "age,expected",
    [
        (None, "unknown"),
        (DECISION - timedelta(days=8), "stale"),
        (DECISION + timedelta(days=1), "future"),
    ],
)
def test_scan_age_is_visible_independently_of_cve_priority(age, expected):
    report, _ = sample("nessus", "csv")
    for asset in report.assets:
        asset.scanned_at = age
    assessment = sw.assess(report, decision_at=DECISION)
    rows = sw.worklist(report, assessment)
    assert all(r["scan_age"] == expected for r in rows)
    assert all("SCAN_TIME_" + expected.upper() in r["quality_flags"] for r in rows)


def test_csv_formula_neutralization_and_html_escaping(tmp_path):
    data = (
        b"Host,Plugin ID,CVE,Risk,Name\n"
        b"=1+1,1,CVE-2026-3001,High,<script>alert(1)</script>\n"
    )
    report = parse_scan(data, "nessus", "csv")
    assessment = sw.assess(report, decision_at=DECISION)
    output = tmp_path / "out"
    sw.write_report(report, assessment, output)
    row = next(
        csv.DictReader(
            io.StringIO((output / "worklist.csv").read_text(encoding="utf-8-sig"))
        )
    )
    assert row["asset"] == "'=1+1"
    assert "<script>" not in (output / "report.html").read_text()


def test_offline_artifact_replay_and_corruption_checks(tmp_path, monkeypatch):
    report, assessment = sample("openvas", "xml")
    first, second = tmp_path / "one", tmp_path / "two"
    sw.write_report(report, assessment, first)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert (
        sw.main(
            [
                "replay",
                "--scan",
                str(first / "scan.json"),
                "--assessment",
                str(first / "assessment.json"),
                "--output",
                str(second),
            ]
        )
        == 0
    )
    for file in first.iterdir():
        assert file.read_bytes() == (second / file.name).read_bytes()
    data = report.model_dump(mode="json")
    data["raw_base64"] = base64.b64encode(b"bad").decode()
    with pytest.raises(ValidationError):
        ScanReport.model_validate(data)
    data = assessment.model_dump(mode="json")
    data["analysis"]["cohort_cves"] = 999
    with pytest.raises(ValidationError):
        sw.Assessment.model_validate(data)


def test_database_import_is_idempotent_and_assessments_are_immutable(connection):
    migrate(connection)
    report, assessment = sample("nessus", "xml")
    sw.save_scan(connection, report)
    sw.save_scan(connection, report.model_copy(update={"imported_at": DECISION}))
    sw.save_assessment(connection, assessment)
    assert sw.load_scan(connection, report.scan_id) == report
    assert sw.latest_assessment(connection, report.scan_id) == assessment
    assert connection.execute("SELECT count(*) FROM scan_imports").fetchone() == (1,)
    assert connection.execute("SELECT count(*) FROM vulnerabilities").fetchone() == (0,)
    for statement in [
        "UPDATE scan_imports SET filename=filename",
        "DELETE FROM scan_assessments",
        "TRUNCATE scan_imports CASCADE",
    ]:
        with (
            pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState),
            connection.transaction(),
        ):
            connection.execute(statement)


def test_enrichment_passes_cve_ids_only_and_keeps_kev_on_epss_failure(
    connection, sources, monkeypatch
):
    report = parse_scan(raw("nessus"), "nessus", "xml")
    sources.kev_ids = ["CVE-2026-3001"]
    sources.failure = "epss"

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return sources.now()

    monkeypatch.setattr(sw, "datetime", Clock)
    original = __import__("threatpulse.tracking", fromlist=["collect_nvd"]).collect_nvd
    calls = []

    def nvd(ids):
        calls.append(ids)
        return original(ids)

    monkeypatch.setattr(sw, "collect_nvd", nvd)
    with ingestion_lock(connection):
        intel, outcomes = sw.refresh_intelligence(connection, report)
    assert calls == [["CVE-2026-3001", "CVE-2026-3002", "CVE-2026-3003"]]
    assert any(r["source"] == "epss" and r["state"] == "failed" for r in outcomes)
    assessment = sw.assess(report, intel, decision_at=sources.now(), outcomes=outcomes)
    row = next(
        r for r in sw.worklist(report, assessment) if r["cve_id"] == "CVE-2026-3001"
    )
    assert row["priority"] == "P1" and "EPSS_UNKNOWN" in row["quality_flags"]
    with pytest.raises(ValueError, match="cap"):
        sw.refresh_intelligence(connection, report, max_cves=1)


def test_invalid_source_batch_cannot_publish_a_partial_refresh(
    connection, sources, monkeypatch
):
    report = parse_scan(raw("nessus"), "nessus", "xml")

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return sources.now()

    monkeypatch.setattr(sw, "datetime", Clock)
    original = __import__("threatpulse.tracking", fromlist=["collect_nvd"]).collect_nvd

    def corrupt(ids):
        batch = original(ids)
        batch.records[-1].ingested_at = sources.current + timedelta(days=1)
        return batch

    monkeypatch.setattr(sw, "collect_nvd", corrupt)
    with ingestion_lock(connection):
        intel, outcomes = sw.refresh_intelligence(connection, report)
    assert intel.nvd_records == []
    assert next(r for r in outcomes if r["source"] == "nvd")["state"] == "failed"


@pytest.mark.parametrize(
    "threat,score", [("False Positive", ""), ("Low", "-1"), ("Low", "-1.0")]
)
def test_conflicting_scanner_results_are_visible_in_the_active_worklist(threat, score):
    _, demo = sample("openvas", "xml")
    root = ET.fromstring(raw("openvas"))
    results = root.find(".//results")
    negative = deepcopy(results.find("result"))
    negative.set("id", "negative-example")
    negative.find("threat").text = threat
    negative.find("severity").text = score
    results.append(negative)
    report = parse_scan(ET.tostring(root), "openvas", "xml", synthetic=True)
    assessment = sw.assess(report, demo.intelligence, decision_at=DECISION)
    rows = sw.worklist(report, assessment)
    positive = next(r for r in rows if r["priority"] == "P4")
    assert "SCANNER_STATUS_CONFLICT" in positive["quality_flags"]
    assert any(r["priority"] == "NOT_RANKED" for r in rows)


def test_selector_and_sample_work_without_database(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    app = AppTest.from_file(APP, default_timeout=20).run()
    assert not app.exception and not app.error
    assert app.selectbox(key="scan_scanner").options == [
        "Nessus",
        "OpenVAS / Greenbone",
        "Nmap",
    ]
    app.button(key="load_scan_sample").click().run()
    assert not app.exception
    assert app.metric[0].value == "2"
    assert "P1" in app.dataframe[0].value["priority"].tolist()
    app.selectbox(key="scan_scanner").set_value("Nmap").run()
    assert app.selectbox(key="scan_format_nmap").options == ["XML"]
    assert not app.exception
    app.button(key="load_scan_sample").click().run()
    assert (
        "Unverified NSE CVE reference" in app.dataframe[0].value["match_basis"].tolist()
    )


def test_fresh_streamlit_script_path_cannot_shadow_standard_library_imports():
    directory = str(Path(APP).parent)
    command = (
        "import sys; sys.path.insert(0, " + repr(directory) + "); "
        "from threatpulse.scan_dashboard import sample; "
        "scan, assessment = sample('nessus','xml'); print(len(scan.findings))"
    )
    result = subprocess.run(
        [sys.executable, "-c", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    assert result.stdout.strip() == "3"
