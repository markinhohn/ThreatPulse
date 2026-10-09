"""Threat Velocity arithmetic, provenance gates, and reproducible report behavior."""

import csv
import hashlib
import json
import os
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import psycopg
import pytest
from pydantic import ValidationError

from threatpulse.epss import EpssBatch
from threatpulse.kev import KevCatalog
from threatpulse.storage import ingest_catalog, ingest_epss, migrate
from threatpulse.trends import TrendDataset
from threatpulse.velocity import (
    POLICY,
    ModelRegistry,
    VelocityDataset,
    VelocityObservation,
    analyze,
    from_history,
    main,
    read_dataset,
)
from threatpulse.velocity_report import CVE_FIELDS, write_report

FIXTURE = Path(__file__).parent / "fixtures" / "velocity_dataset.json"
DECISION = datetime(2026, 1, 10, 12, tzinfo=UTC)
A = "CVE-2026-1001"


@pytest.fixture
def dataset():
    return VelocityDataset.model_validate_json(FIXTURE.read_text())


def sample(dataset, values=None, days=None):
    data = dataset.model_copy(deep=True)
    data.cohort = [A]
    data.epss_observations = [o for o in data.epss_observations if o.cve_id == A]
    regime = data.model_registry.regimes[-1].model_copy(deep=True)
    regime.score_date_start = date(2026, 1, 1)
    data.model_registry = ModelRegistry(regimes=[regime])
    if values is not None:
        template = data.epss_observations[0]
        days = days or list(range(11 - len(values), 11))
        data.epss_observations = [
            VelocityObservation(
                **(
                    template.model_dump()
                    | {
                        "score_date": date(2026, 1, day),
                        "epss": Decimal(value),
                        "ingested_at": DECISION - timedelta(minutes=30),
                        "available_at": DECISION,
                        "raw_record": {"synthetic": True},
                    }
                )
            )
            for day, value in zip(days, values, strict=True)
        ]
    return data


def row(dataset, decision=None):
    return analyze(dataset, decision)["cves"][0]


def test_missing_percentile_and_explicit_forward_evaluation(dataset):
    data = sample(dataset)
    for observation in data.epss_observations:
        observation.percentile = None
    decision = DECISION + timedelta(days=3)
    with pytest.raises(ValueError, match="cannot follow"):
        analyze(data, decision)
    result = analyze(data, decision, allow_after_export=True)["cves"][0]
    assert not result["rising_signal"]
    assert data.captured_at == DECISION
    assert all(o.percentile is None for o in data.epss_observations)


def test_known_linear_rate_coverage_and_fixture_gates(dataset):
    result = analyze(dataset)
    rows = {r["cve_id"]: r for r in result["cves"]}
    rising = rows[A]
    assert result["rising_cves"] == 1
    assert rising["rising_signal"] is True
    assert rising["endpoint_change_pp"] == 6
    assert rising["endpoint_rate_pp_per_day"] == 1.5
    assert rising["median_pairwise_slope_pp_per_day"] == 1.5
    assert rising["pairwise_slopes"] == 10
    assert rising["coverage_fraction"] == 5 / 8
    assert rising["missing_dates"] == ["2026-01-03", "2026-01-04", "2026-01-05"]
    assert "GAP_EXCEEDS_LIMIT" in rows["CVE-2026-1002"]["eligibility_reasons"]
    assert rows["CVE-2026-1003"]["model_comparability"] == "model_boundary"
    assert rows["CVE-2026-1004"]["latest_epss"] == 0
    assert rows["CVE-2026-1004"]["descriptive_direction"] == "flat"
    assert rows["CVE-2026-1005"]["latest_epss"] is None
    assert rows["CVE-2026-1005"]["median_pairwise_slope_pp_per_day"] is None
    assert "STALE_LATEST_SCORE" in rows["CVE-2026-1006"]["eligibility_reasons"]
    gap = next(i for i in result["intervals"] if i["cve_id"] == "CVE-2026-1002")
    assert gap["elapsed_calendar_days"] == 3
    assert gap["change_pp"] == 3
    assert gap["rate_pp_per_day"] == 1


def test_inclusive_window_and_two_day_gaps(dataset):
    data = sample(dataset, ["0", ".01", ".02", ".04", ".06"], [4, 5, 6, 8, 10])
    result = row(data)
    assert result["rising_signal"] is True
    assert result["span_calendar_days"] == 6
    assert result["maximum_adjacent_gap_days"] == 2
    assert result["median_pairwise_slope_pp_per_day"] == 1
    old = data.epss_observations[0].model_copy(deep=True)
    old.score_date, old.epss = date(2026, 1, 2), Decimal(".99")
    data.epss_observations.append(old)
    assert row(data) == result  # January 2 is outside the inclusive Jan 3–10 window.


@pytest.mark.parametrize(
    "step,last,reason",
    [
        (".005", ".05", None),
        (".005", ".049999", "ENDPOINT_CHANGE_BELOW_THRESHOLD"),
        (".004999", ".05", "SLOPE_BELOW_THRESHOLD"),
    ],
)
def test_exact_thresholds_before_float_display(dataset, step, last, reason):
    values = [str(Decimal(step) * i) for i in range(7)] + [last]
    result = row(sample(dataset, values))
    if reason:
        assert reason in result["eligibility_reasons"]
        assert result["rising_signal"] is False
    else:
        assert result["endpoint_change_pp"] == 5
        assert result["median_pairwise_slope_pp_per_day"] == 0.5
        assert result["rising_signal"] is True


def test_endpoint_spike_does_not_override_robust_slope(dataset):
    result = row(sample(dataset, ["0"] * 7 + [".06"]))
    assert result["endpoint_change_pp"] == 6
    assert result["median_pairwise_slope_pp_per_day"] == 0
    assert result["rising_signal"] is False
    assert "SLOPE_BELOW_THRESHOLD" in result["eligibility_reasons"]


def test_insufficient_count_falling_and_single_zero(dataset):
    result = row(sample(dataset, ["0", ".02", ".04", ".06"], [4, 6, 8, 10]))
    assert result["eligibility_reasons"] == ["INSUFFICIENT_OBSERVED_DATES"]
    falling = row(sample(dataset, [".08", ".06", ".04", ".02", "0"]))
    assert falling["median_pairwise_slope_pp_per_day"] == -2
    assert falling["descriptive_direction"] == "decreasing"
    assert falling["rising_signal"] is False
    assert POLICY["automatic_downgrades"] is False
    zero = row(sample(dataset, ["0"]))
    assert zero["latest_epss"] == 0
    assert zero["observed_dates"] == 1
    assert zero["endpoint_change_pp"] is None
    assert zero["median_pairwise_slope_pp_per_day"] is None


@pytest.mark.parametrize(
    "decision,stale",
    [
        (datetime(2026, 1, 12, 23, tzinfo=UTC), False),
        (datetime(2026, 1, 13, tzinfo=UTC), True),
        (datetime.fromisoformat("2026-01-12T19:00:00-05:00"), True),
    ],
)
def test_freshness_uses_utc_calendar_boundaries(dataset, decision, stale):
    data = sample(dataset)
    data.captured_at = datetime(2026, 1, 14, tzinfo=UTC)
    result = row(data, decision)
    assert ("STALE_LATEST_SCORE" in result["eligibility_reasons"]) is stale
    assert result["rising_signal"] is not stale


def test_unavailable_and_invalid_future_points(dataset):
    data = sample(dataset)
    data.epss_observations[-1].available_at = DECISION + timedelta(seconds=1)
    result = row(data)
    assert result["window_end"] == "2026-01-09"
    assert result["excluded_observations"] == [
        {"score_date": "2026-01-10", "reason": "NOT_AVAILABLE_AT_DECISION"}
    ]
    assert result["rising_signal"] is False
    data = sample(dataset)
    future = data.epss_observations[-1].model_copy(deep=True)
    future.score_date = date(2026, 1, 11)
    data.epss_observations.append(future)
    result = row(data)
    assert result["window_end"] == "2026-01-10"
    assert "INVALID_FUTURE_SCORE_DATE" in result["eligibility_reasons"]
    assert result["rising_signal"] is False


def test_unknown_model_keeps_descriptive_rate_and_never_assumes_version(dataset):
    data = sample(dataset)
    data.model_registry = ModelRegistry()
    result = row(data)
    assert result["model_comparability"] == "unknown"
    assert result["median_pairwise_slope_pp_per_day"] == 1.5
    assert result["eligibility_reasons"] == ["MODEL_REGIME_UNKNOWN"]
    assert result["rising_signal"] is False


def test_model_boundary_is_not_cherry_picked_away(dataset):
    data = sample(dataset)
    left = data.model_registry.regimes[0].model_copy(deep=True)
    left.regime_id, left.score_date_end = "left", date(2026, 1, 7)
    right = left.model_copy(deep=True)
    right.regime_id = "right"
    right.score_date_start, right.score_date_end = date(2026, 1, 8), date(2026, 1, 10)
    data.model_registry = ModelRegistry(regimes=[left, right])
    result = row(data)
    assert result["observed_dates"] == 5
    assert result["model_regime_ids"] == ["left", "right"]
    assert result["eligibility_reasons"] == ["MODEL_REGIME_BOUNDARY"]
    assert result["rising_signal"] is False


def test_registry_gaps_include_unobserved_score_dates(dataset):
    data = sample(dataset, ["0", ".01", ".02", ".04", ".06"], [4, 5, 6, 8, 10])
    left = data.model_registry.regimes[0].model_copy(deep=True)
    left.score_date_end = date(2026, 1, 6)
    right = left.model_copy(deep=True)
    right.regime_id = "second"
    right.score_date_start, right.score_date_end = date(2026, 1, 8), date(2026, 1, 10)
    data.model_registry = ModelRegistry(regimes=[left, right])
    assert row(data)["model_comparability"] == "unknown"
    assert row(data)["rising_signal"] is False


def test_model_review_must_exist_at_decision_and_cannot_attest_future(dataset):
    data = sample(dataset)
    data.model_registry.regimes[0].reviewed_at = DECISION
    assert row(data)["rising_signal"] is True
    data.model_registry.regimes[0].reviewed_at += timedelta(microseconds=1)
    assert row(data)["model_comparability"] == "unknown"
    registry = data.model_registry.model_dump(mode="json")
    registry["regimes"][0]["score_date_end"] = "2026-01-11"
    with pytest.raises(ValidationError, match="future score dates"):
        ModelRegistry.model_validate(registry)


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_cve",
        "duplicate_observation",
        "outside_cohort",
        "availability",
        "probability",
    ],
)
def test_invalid_history_is_rejected(dataset, mutation):
    payload = dataset.model_dump(mode="json")
    if mutation == "duplicate_cve":
        payload["cohort"].append(A)
    elif mutation == "duplicate_observation":
        payload["epss_observations"].append(payload["epss_observations"][0])
    elif mutation == "outside_cohort":
        payload["cohort"].remove(A)
    elif mutation == "availability":
        payload["epss_observations"][0]["available_at"] = "2020-01-01T00:00:00Z"
    else:
        payload["epss_observations"][0]["epss"] = "NaN"
    with pytest.raises(ValidationError):
        VelocityDataset.model_validate(payload)


@pytest.mark.parametrize(
    "mutation", ["overlap", "duplicate_id", "reversed", "blank_evidence"]
)
def test_invalid_registries_are_rejected(dataset, mutation):
    registry = dataset.model_registry.model_dump(mode="json")
    if mutation == "overlap":
        registry["regimes"][1]["score_date_start"] = "2026-01-03"
    elif mutation == "duplicate_id":
        registry["regimes"][1]["regime_id"] = registry["regimes"][0]["regime_id"]
    elif mutation == "reversed":
        registry["regimes"][0]["score_date_end"] = "2025-12-31"
    else:
        registry["regimes"][0]["evidence"] = " "
    with pytest.raises(ValidationError):
        ModelRegistry.model_validate(registry)


def test_imported_history_is_conservative_and_decision_time_is_bounded():
    history = TrendDataset.model_validate_json(
        (FIXTURE.parent / "trend_dataset.json").read_text()
    )
    data = from_history(history)
    assert {e.available_at for e in data.epss_observations} == {data.captured_at}
    before = analyze(data, data.captured_at - timedelta(seconds=1))
    assert before["with_rates"] == 0
    assert analyze(data)["with_rates"] > 0
    with pytest.raises(ValueError, match="timezone"):
        analyze(data, datetime(2026, 1, 1))
    with pytest.raises(ValueError, match="frozen export"):
        analyze(data, data.captured_at + timedelta(seconds=1))


def test_policy_matches_documented_contract():
    contract = json.loads(
        (
            Path(__file__).parents[1] / "docs/examples/prioritization-policy-v0.1.json"
        ).read_text()
    )
    for key in (
        "lookback_calendar_days",
        "minimum_observed_dates",
        "minimum_span_calendar_days",
        "maximum_adjacent_gap_calendar_days",
        "minimum_latest_epss",
        "minimum_endpoint_change_pp",
        "minimum_median_pairwise_slope_pp_per_day",
    ):
        assert POLICY[key] == contract["trend_promotion"][key]
    assert (
        POLICY["maximum_latest_score_calendar_age_days_utc"]
        == contract["freshness"]["epss_max_source_calendar_age_days_utc"]
    )


def test_public_analysis_revalidates_mutated_inputs_and_isolates_policy(dataset):
    result = analyze(dataset)
    result["policy"]["eligible_promotion"]["P3"] = "P1"
    assert POLICY["eligible_promotion"] == {"P3": "P2"}
    dataset.epss_observations.append(dataset.epss_observations[0])
    with pytest.raises(ValidationError, match="Duplicate EPSS"):
        analyze(dataset)


def test_report_replay_integrity_escaping_and_order_independence(dataset, tmp_path):
    dataset.label = 'Synthetic <script>alert("x")</script>'
    first, second = tmp_path / "first", tmp_path / "second"
    expected = write_report(dataset, first)
    restored = VelocityDataset.model_validate_json((first / "source.json").read_text())
    restored.cohort.reverse()
    restored.epss_observations.reverse()
    restored.model_registry.regimes.reverse()
    assert write_report(restored, second) == expected
    manifest = json.loads((first / "manifest.json").read_text())
    for name, digest in manifest["files_sha256"].items():
        assert hashlib.sha256((first / name).read_bytes()).hexdigest() == digest
        assert (first / name).read_bytes() == (second / name).read_bytes()
    assert "<script>" not in (first / "report.html").read_text()
    assert "&lt;script&gt;" in (first / "report.html").read_text()
    assert (
        "Median pairwise slope (percentage points/day)"
        in (first / "threat-velocity.svg").read_text()
    )
    assert (
        manifest["policy_sha256"]
        == hashlib.sha256((first / "policy.json").read_bytes()).hexdigest()
    )
    with pytest.raises(FileExistsError):
        write_report(dataset, first)


def test_empty_report_keeps_unknowns_and_csv_schema(dataset, tmp_path):
    dataset.cohort, dataset.epss_observations = [], []
    result = write_report(dataset, tmp_path / "empty")
    assert result["cohort_cves"] == result["rising_cves"] == 0
    assert (tmp_path / "empty/velocity.csv").read_text().splitlines()[0].split(
        ","
    ) == CVE_FIELDS
    with (tmp_path / "empty/observations.csv").open() as stream:
        assert list(csv.DictReader(stream)) == []


def test_cli_replay_registry_override_and_redacted_errors(
    dataset, tmp_path, monkeypatch, capsys
):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert main(["--output", str(tmp_path / "missing")]) == 1
    assert "Set DATABASE_URL" in capsys.readouterr().err
    registry = tmp_path / "unknown.json"
    registry.write_text('{"schema_version":1,"regimes":[]}')
    target = tmp_path / "cli"
    assert (
        main(
            [
                "--input",
                str(FIXTURE),
                "--output",
                str(target),
                "--model-regimes",
                str(registry),
            ]
        )
        == 0
    )
    assert json.loads((target / "analysis.json").read_text())["rising_cves"] == 0
    assert (
        main(
            [
                "--input",
                str(FIXTURE),
                "--output",
                str(tmp_path / "naive"),
                "--decision-at",
                "2026-01-10T12:00:00",
            ]
        )
        == 1
    )
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"password":"must-not-appear"}')
    assert main(["--input", str(invalid), "--output", str(tmp_path / "invalid")]) == 1
    assert "must-not-appear" not in capsys.readouterr().err


def test_database_cli_is_readonly_and_cannot_reconstruct_old_versions(
    connection, dataset, monkeypatch, tmp_path
):
    migrate(connection)
    history = TrendDataset.model_validate_json(
        (FIXTURE.parent / "trend_dataset.json").read_text()
    )
    template = history.kev_snapshots[0].observation
    records = []
    for cve in dataset.cohort:
        record = template.model_copy(deep=True)
        record.kev.cve_id = record.vulnerability.cve_id = cve
        records.append(record)
    ingest_catalog(connection, KevCatalog(records=records))
    ingest_epss(
        connection, EpssBatch(observations=dataset.epss_observations, missing_cves=[])
    )
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
        frozen = original_read(conn)
        assert all(
            e.availability_basis == "database_export" for e in frozen.epss_observations
        )
        assert all(
            e.available_at == frozen.captured_at for e in frozen.epss_observations
        )
        assert (
            analyze(frozen, frozen.captured_at - timedelta(seconds=1))["with_rates"]
            == 0
        )
        return frozen

    monkeypatch.setattr("threatpulse.velocity.psycopg.connect", connect)
    monkeypatch.setattr("threatpulse.velocity.read_dataset", read)
    assert main(["--output", str(tmp_path / "db")]) == 0
    assert connection.execute("SELECT count(*) FROM epss_observations").fetchone()[
        0
    ] == len(dataset.epss_observations)
