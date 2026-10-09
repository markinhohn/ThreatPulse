"""Policy scenarios, source validity, review binding, and database/report replay."""

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest
from cvss import CVSS3, CVSS4
from pydantic import ValidationError
from tests.test_trends import seed_history

from threatpulse.kev import CollectedVulnerability, KevCatalog
from threatpulse.models import parse_cisa_kev_record
from threatpulse.nvd import NvdBatch, NvdRecord
from threatpulse.priority import (
    POLICY,
    CatalogEvidence,
    DecisionRecord,
    DowngradeReview,
    EpssEvidence,
    KevWithdrawal,
    NvdEvidence,
    PriorityDataset,
    analyze,
    attach_previous,
    main,
    read_dataset,
)
from threatpulse.priority_report import write_report
from threatpulse.storage import ingest_catalog, ingest_nvd, migrate
from threatpulse.trends import TrendDataset
from threatpulse.velocity import ModelRegistry

ROOT = Path(__file__).parents[1]
SCENARIOS = json.loads(
    (ROOT / "docs/examples/prioritization-scenarios-v0.1.json").read_text()
)
DECISION = datetime(2026, 1, 10, 12, tzinfo=UTC)
CVE = "CVE-2026-1234"
CATALOG_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
VECTORS = {
    "NONE": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    "LOW": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
    "MEDIUM": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L",
    "HIGH": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CRITICAL": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
}


def metric(severity="LOW", source="synthetic@example.test"):
    vector = VECTORS[severity]
    parsed = (CVSS4 if severity == "CRITICAL" else CVSS3)(vector)
    assert parsed.severities()[0].upper() == severity
    return {
        "version": "4.0" if severity == "CRITICAL" else "3.1",
        "source": source,
        "metric_type": "Primary",
        "vector": vector,
        "base_score": str(parsed.scores()[0]),
        "severity": severity,
        "attack_vector": "PHYSICAL" if severity == "LOW" else "NETWORK",
    }


def base_dataset():
    captured = DECISION - timedelta(hours=1)
    return PriorityDataset(
        captured_at=DECISION,
        label="Synthetic priority examples; not real vulnerability findings",
        cohort=[CVE],
        catalogs=[
            CatalogEvidence(
                evidence_id="catalog-now",
                captured_at=captured,
                available_at=captured,
                source_url=CATALOG_URL,
                cve_ids=["CVE-2026-9999"],
            )
        ],
        nvd_records=[
            NvdEvidence(
                evidence_id="nvd-now",
                cve_id=CVE,
                captured_at=captured,
                available_at=captured,
                source_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                record={
                    "cve_id": CVE,
                    "published_at": "2025-01-01T00:00:00Z",
                    "modified_at": "2025-01-02T00:00:00Z",
                    "status": "Analyzed",
                    "description": "Synthetic example",
                    "references": [],
                    "weaknesses": [],
                    "cvss_metrics": [metric()],
                    "source_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    "ingested_at": captured.isoformat(),
                    "raw_record": {"id": CVE},
                },
            )
        ],
        epss_observations=[
            EpssEvidence(
                evidence_id="epss-now",
                cve_id=CVE,
                captured_at=captured,
                available_at=captured,
                source_url="https://api.first.org/data/v1/epss",
                score_date="2026-01-10",
                epss="0.005",
            )
        ],
    )


def outcome(dataset, decision=None):
    return analyze(dataset, decision)["decisions"][0]


def previous(tier="P2", preference=False):
    data = base_dataset()
    data.captured_at = DECISION - timedelta(minutes=1)
    data.epss_observations[0].epss = (
        "0.2" if tier == "P2" else "0.02" if tier == "P3" else "0.005"
    )
    if preference:
        data.nvd_records[0].record["cvss_metrics"][0]["source"] = (
            "previous@example.test"
        )
    return DecisionRecord.model_validate(outcome(data))


def acknowledgement(row, **overrides):
    return DowngradeReview(
        **(
            {
                "review_id": "synthetic-review",
                "reviewer": "Synthetic operator",
                "reviewed_at": DECISION,
                "rationale": "Synthetic evidence-bound acknowledgement",
                "cve_id": CVE,
                "policy_version": row["policy_version"],
                "policy_sha256": row["policy_sha256"],
                "previous_decision_id": row["previous_decision_id"],
                "input_sha256": row["input_sha256"],
                "approved_candidate": row["candidate_tier"],
            }
            | overrides
        )
    )


def scenario_dataset(case):
    inputs = SCENARIOS["input_defaults"] | case["input_overrides"]
    data = base_dataset()
    data.nvd_records[0].record["status"] = inputs["nvd_status"]
    cvss = inputs["cvss"]
    data.nvd_records[0].record["cvss_metrics"] = (
        [metric(cvss["severity"])] if cvss["quality"] == "fresh" else []
    )
    epss = inputs["epss"]
    if epss["quality"] == "missing":
        data.epss_observations = []
    else:
        data.epss_observations[0].epss = epss["probability"]
        data.epss_observations[0].percentile = epss["percentile"]
        data.epss_observations[0].score_date = (
            "2026-01-07"
            if epss["quality"] == "stale"
            else "2026-01-11"
            if epss["quality"] == "future"
            else "2026-01-10"
        )
    if inputs["catalog_state"] == "unknown":
        data.catalogs = []
    elif inputs["catalog_state"] == "fresh_complete_presence":
        data.catalogs[0].cve_ids.append(CVE)
    if inputs["confirmed_kev"] == "historical":
        old = data.catalogs[0].model_copy(deep=True)
        old.evidence_id = "catalog-old"
        old.captured_at = old.available_at = DECISION - timedelta(days=10)
        old.cve_ids = [CVE]
        data.catalogs.append(old)
    if inputs["unconfirmed_positive_exploitation"]:
        data.nvd_records[0].record["raw_record"]["cisaExploitAdd"] = "2026-01-01"
    if inputs["prior_effective_tier"]:
        data.previous_decisions = [previous(inputs["prior_effective_tier"])]
    if inputs["cvss_preference_changed"]:
        data.previous_decisions = [previous("P4", preference=True)]
    trend = inputs["trend"]
    if "observations" in trend:
        data.epss_observations = [
            data.epss_observations[0].model_copy(
                update={
                    "evidence_id": f"epss-{o['source_date']}",
                    "score_date": o["source_date"],
                    "epss": o["probability"],
                }
            )
            for o in trend["observations"]
        ]
        if trend["comparability"] == "known_same_regime":
            data.model_registry = ModelRegistry.model_validate(
                {
                    "regimes": [
                        {
                            "regime_id": "synthetic",
                            "score_date_start": "2026-01-01",
                            "score_date_end": "2026-01-10",
                            "reviewed_at": "2026-01-10T11:30:00Z",
                            "reviewer": "Synthetic audit",
                            "evidence_url": "https://www.first.org/epss/model",
                            "evidence": "Invented regime; synthetic example only.",
                        }
                    ]
                }
            )
    if inputs["downgrade_reviewed"]:
        data.reviews = [acknowledgement(outcome(data))]
    return data


@pytest.mark.parametrize("case", SCENARIOS["cases"], ids=lambda c: c["id"])
def test_all_documented_policy_scenarios(case):
    row = outcome(scenario_dataset(case))
    for key, expected in case["expected"].items():
        assert row[key] == expected


@pytest.mark.parametrize(
    "source,boundary,outside",
    [
        ("epss", "2026-01-08", "2026-01-07"),
        ("nvd", "2026-01-03T12:00:00Z", "2026-01-03T11:59:59Z"),
        ("catalog", "2026-01-08T12:00:00Z", "2026-01-08T11:59:59Z"),
    ],
)
def test_inclusive_freshness_boundaries(source, boundary, outside):
    for value, expected in ((boundary, "P4"), (outside, "UNDETERMINED")):
        data = base_dataset()
        if source == "epss":
            data.epss_observations[0].score_date = value
        else:
            evidence = data.nvd_records[0] if source == "nvd" else data.catalogs[0]
            evidence.captured_at = evidence.available_at = datetime.fromisoformat(value)
            if source == "nvd":
                evidence.record["ingested_at"] = value
        assert outcome(data)["candidate_tier"] == expected


def test_invalid_inputs_preserve_kev_and_flag_affected_signals():
    data = base_dataset()
    data.catalogs[0].cve_ids.append(CVE)
    data.epss_observations[0].epss = "NaN"
    data.nvd_records[0].record["cvss_metrics"][0]["version"] = "9.0"
    row = outcome(data)
    assert row["effective_tier"] == "P1"
    assert row["quality_flags"] == ["EPSS_UNKNOWN", "CVSS_UNKNOWN"]
    assert row["quality_details"]["epss"] == row["quality_details"]["cvss"] == "invalid"


def test_invalid_old_epss_does_not_hide_fresh_point():
    data = base_dataset()
    data.epss_observations.append(
        data.epss_observations[0].model_copy(
            update={
                "evidence_id": "old-invalid",
                "score_date": "2025-01-01",
                "epss": "NaN",
            }
        )
    )
    assert outcome(data)["candidate_tier"] == "P4"


@pytest.mark.parametrize("source", ["epss", "nvd", "catalog"])
def test_post_decision_evidence_cannot_support_a_tier(source):
    data = base_dataset()
    evidence = {
        "epss": data.epss_observations[0],
        "nvd": data.nvd_records[0],
        "catalog": data.catalogs[0],
    }[source]
    evidence.available_at = DECISION + timedelta(seconds=1)
    assert outcome(data)["candidate_tier"] == "UNDETERMINED"


@pytest.mark.parametrize(
    "change", [{"complete": False}, {"validated": False}, {"cve_ids": []}]
)
def test_partial_unvalidated_or_empty_catalog_cannot_establish_absence(change):
    data = base_dataset()
    data.catalogs[0] = data.catalogs[0].model_copy(update=change)
    row = outcome(data)
    assert row["candidate_tier"] == "UNDETERMINED"
    assert "KEV_COVERAGE_UNKNOWN" in row["quality_flags"]


def test_invalid_cvss_preserves_valid_nvd_exploitation_metadata_only():
    data = base_dataset()
    evidence = data.nvd_records[0]
    evidence.record["cvss_metrics"][0]["version"] = "9.0"
    evidence.record["raw_record"]["cisaExploitAdd"] = "2026-01-01"
    row = outcome(data)
    assert row["candidate_tier"] == "P2"
    assert "EXPLOITATION_CONFLICT" in row["reason_codes"]
    evidence.record["ingested_at"] = DECISION.isoformat()
    assert outcome(data)["candidate_tier"] == "UNDETERMINED"


def test_invalid_epss_in_window_disables_promotion_without_hiding_fresh_score():
    case = next(c for c in SCENARIOS["cases"] if c["id"] == "eligible_rising_trend")
    data = scenario_dataset(case)
    data.epss_observations[0].epss = "NaN"
    row = outcome(data)
    assert row["candidate_tier"] == "P3"
    assert row["quality_details"]["epss"] == "fresh"
    assert "INVALID_EPSS_IN_WINDOW" in row["trend"]["eligibility_reasons"]


def test_stronger_tier_takes_effect_without_downgrade_review():
    data = base_dataset()
    data.previous_decisions = [previous("P4")]
    data.epss_observations[0].epss = "0.1"
    row = outcome(data)
    assert row["effective_tier"] == "P2"
    assert row["review_status"] == "not_required"


def test_executable_policy_matches_documented_defaults():
    reference = json.loads(
        (ROOT / "docs/examples/prioritization-policy-v0.1.json").read_text()
    )
    for key in (
        "policy_version",
        "purpose",
        "epss_high_probability",
        "epss_elevated_probability",
        "severe_cvss_labels",
        "accepted_cvss_versions",
        "tier_order",
        "non_ranked_states",
        "within_tier_display_order",
        "validated_risk_model",
    ):
        assert POLICY[key] == reference[key]
    for key in (
        "epss_max_source_calendar_age_days_utc",
        "nvd_max_capture_age_hours",
        "cisa_absence_max_capture_age_hours",
        "confirmed_kev_evidence_expires_automatically",
    ):
        assert POLICY[key] == reference["freshness"][key]
    assert POLICY["ordered_rules"] == [
        {k: rule[k] for k in ("id", "tier", "reason")}
        for rule in reference["ordered_rules"]
    ]


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"input_sha256": "0" * 64}, "INPUT_VERSION_MISMATCH"),
        ({"policy_version": "other"}, "POLICY_MISMATCH"),
        ({"previous_decision_id": "0" * 64}, "PREVIOUS_DECISION_MISMATCH"),
        ({"approved_candidate": "OUT_OF_SCOPE"}, "CANDIDATE_MISMATCH"),
        ({"reviewed_at": DECISION + timedelta(seconds=1)}, "FUTURE_REVIEW"),
        ({"reviewed_at": DECISION - timedelta(minutes=1)}, "REVIEW_PRECEDES_EVIDENCE"),
    ],
)
def test_invalid_acknowledgements_cannot_lower_prior_tier(change, reason):
    data = base_dataset()
    data.previous_decisions = [previous()]
    row = outcome(data)
    data.reviews = [acknowledgement(row, **change)]
    row = outcome(data)
    assert row["candidate_tier"] == "P4" and row["effective_tier"] == "P2"
    assert reason in row["review_audit"][0]["reasons"]


def test_review_forward_clock_aging_and_changed_evidence():
    data = base_dataset()
    data.previous_decisions = [previous()]
    row = outcome(data)
    review_time = DECISION + timedelta(minutes=30)
    data.reviews = [acknowledgement(row, reviewed_at=review_time)]
    approved = outcome(data, review_time)
    assert (
        approved["effective_tier"] == "P4"
        and approved["approved_review_id"] == "synthetic-review"
    )
    assert approved["input_sha256"] == row["input_sha256"]
    assert approved["review_audit"][0]["record"]["reviewer"] == "Synthetic operator"
    data.epss_observations[0].epss = "0.006"
    assert outcome(data, review_time)["effective_tier"] == "P2"
    assert outcome(data, DECISION + timedelta(days=3))["effective_tier"] == "P2"


def test_known_kev_survives_missing_new_sources_and_requires_explicit_correction():
    old = base_dataset()
    old.catalogs[0].cve_ids.append(CVE)
    first = analyze(old)
    current = base_dataset()
    current = attach_previous(current, first)
    assert outcome(current)["candidate_tier"] == "P1"
    evidence = first["decisions"][0]["values"]["kev"]["evidence"]
    current.kev_withdrawals = [
        KevWithdrawal(
            correction_id="synthetic-correction",
            cve_id=CVE,
            evidence_ids=[e["evidence_id"] for e in evidence],
            reviewed_at=DECISION,
            reviewer="Synthetic operator",
            rationale="Invented source correction",
            source_url=CATALOG_URL,
        )
    ]
    row = outcome(current)
    assert row["candidate_tier"] == "P4" and row["effective_tier"] == "P1"
    current.reviews = [acknowledgement(row)]
    assert outcome(current)["effective_tier"] == "P4"


@pytest.mark.parametrize("case", ["unknown", "before_capture"])
def test_source_corrections_require_known_evidence_and_valid_chronology(case):
    data = base_dataset()
    data.catalogs[0].cve_ids.append(CVE)
    data.kev_withdrawals = [
        KevWithdrawal(
            correction_id="correction",
            cve_id=CVE,
            evidence_ids=["unknown" if case == "unknown" else f"catalog-now:{CVE}"],
            reviewed_at=DECISION - timedelta(days=1)
            if case == "before_capture"
            else DECISION,
            reviewer="Synthetic audit",
            rationale="Invented correction",
            source_url=CATALOG_URL,
        )
    ]
    with pytest.raises(ValueError, match="unknown|precedes"):
        outcome(data)


def test_same_time_conflicting_catalogs_are_not_arbitrarily_used_as_absence():
    data = base_dataset()
    positive = data.catalogs[0].model_copy(
        update={"evidence_id": "other", "cve_ids": [CVE]}
    )
    data.catalogs.append(positive)
    row = outcome(data)
    assert row["effective_tier"] == "P1"
    assert "EXPLOITATION_CONFLICT" in row["quality_flags"]
    assert row["values"]["kev"]["current_membership"] is None


def test_corrupted_previous_decision_rejected_and_missing_cohort_retained():
    old = analyze(base_dataset())
    empty = PriorityDataset(captured_at=DECISION, cohort=[])
    current = attach_previous(empty, old)
    assert current.cohort == [CVE]
    assert outcome(current)["candidate_tier"] == "UNDETERMINED"
    assert outcome(current)["effective_tier"] == "P4"
    old["decisions"][0]["effective_tier"] = "P1"
    with pytest.raises(ValidationError, match="checksum"):
        attach_previous(empty, old)


def test_report_replay_checksums_escaping_and_new_directory(tmp_path):
    data = base_dataset()
    data.label = '<script>alert("x")</script>'
    first, second = tmp_path / "one", tmp_path / "two"
    result = write_report(data, first)
    source = PriorityDataset.model_validate_json((first / "source.json").read_text())
    assert write_report(source, second) == result
    manifest = json.loads((first / "manifest.json").read_text())
    for name, sha in manifest["files_sha256"].items():
        assert hashlib.sha256((first / name).read_bytes()).hexdigest() == sha
        assert (first / name).read_bytes() == (second / name).read_bytes()
    assert "<script>" not in (first / "report.html").read_text()
    assert "&lt;script&gt;" in (first / "report.html").read_text()
    assert "UNDETERMINED (0 CVEs)" in (first / "report.html").read_text()
    with pytest.raises(FileExistsError):
        write_report(data, first)


def test_empty_output_and_cli_redacted_failures(tmp_path, monkeypatch, capsys):
    data = PriorityDataset(captured_at=DECISION, cohort=[])
    assert write_report(data, tmp_path / "empty")["cohort_cves"] == 0
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert main(["--output", str(tmp_path / "missing")]) == 1
    assert "Set DATABASE_URL" in capsys.readouterr().err
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"password":"must-not-appear"}')
    assert main(["--input", str(invalid), "--output", str(tmp_path / "bad")]) == 1
    assert "must-not-appear" not in capsys.readouterr().err


def test_synthetic_public_fixture_covers_every_queue(tmp_path):
    source = ROOT / "tests/fixtures/priority_dataset.json"
    assert main(["--input", str(source), "--output", str(tmp_path / "demo")]) == 0
    result = json.loads((tmp_path / "demo/analysis.json").read_text())
    assert result["tier_counts"] == {
        "P1": 2,
        "P2": 4,
        "P3": 1,
        "P4": 1,
        "UNDETERMINED": 1,
        "OUT_OF_SCOPE": 1,
    }


def test_database_exports_complete_catalogs_and_historical_nvd(connection):
    history = TrendDataset.model_validate_json(
        (ROOT / "tests/fixtures/trend_dataset.json").read_text()
    )
    seed_history(connection, history)
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        data = read_dataset(connection)
    assert len(data.catalogs) == 3
    assert len(data.nvd_records) == len(history.nvd_snapshots)
    assert data.catalogs[-1].cve_ids == [
        "CVE-2026-1001",
        "CVE-2026-1002",
        "CVE-2026-1003",
    ]
    assert all(e.available_at == data.captured_at for e in data.nvd_records)
    assert analyze(data)["tier_counts"]["P1"] == 4


def test_readonly_database_retained_kev_is_positive_not_current_membership(
    connection, tmp_path, monkeypatch
):
    migrate(connection)
    raw = json.loads((ROOT / "tests/fixtures/cisa_kev_record.json").read_text())
    raw["cveID"] = CVE
    vulnerability, entry = parse_cisa_kev_record(
        raw, source_url=CATALOG_URL, ingested_at=DECISION
    )
    ingest_catalog(
        connection,
        KevCatalog(
            records=[CollectedVulnerability(vulnerability=vulnerability, kev=entry)]
        ),
    )
    nvd = NvdRecord.model_validate(base_dataset().nvd_records[0].record)
    ingest_nvd(connection, NvdBatch(records=[nvd], missing_cves=[]))
    schema = connection.execute("SELECT current_schema()").fetchone()[0]
    original_connect, original_read = psycopg.connect, read_dataset
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])

    def connect(*args, **kwargs):
        return original_connect(*args, **kwargs, options=f"-c search_path={schema}")

    def read(conn):
        assert conn.execute("SHOW transaction_read_only").fetchone() == ("on",)
        assert conn.execute("SHOW transaction_isolation").fetchone() == (
            "repeatable read",
        )
        dataset = original_read(conn)
        assert dataset.catalogs == []
        assert all(e.available_at == dataset.captured_at for e in dataset.kev_entries)
        return dataset

    monkeypatch.setattr("threatpulse.priority.psycopg.connect", connect)
    monkeypatch.setattr("threatpulse.priority.read_dataset", read)
    assert main(["--output", str(tmp_path / "database")]) == 0
    row = json.loads((tmp_path / "database/analysis.json").read_text())["decisions"][0]
    assert row["effective_tier"] == "P1"
    assert row["values"]["kev"]["current_membership"] is None
    assert row["values"]["cvss"]["metric"]["version"] == "3.1"
    assert row["quality_details"]["cvss"] == "stale"
    assert "KEV_COVERAGE_UNKNOWN" in row["quality_flags"]
