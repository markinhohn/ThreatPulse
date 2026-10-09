"""Independent rank-test references, inference guards, and frozen replay."""

import hashlib
import json
import os
from decimal import Decimal
from itertools import combinations
from pathlib import Path
from uuid import uuid4

import numpy as np
import psycopg
import pytest
from pydantic import ValidationError
from scipy.stats import mannwhitneyu

from threatpulse.comparison import ComparisonStudy, classify, save_study
from threatpulse.statistical_report import write_report
from threatpulse.statistics import (
    ENDPOINTS,
    StatisticalPlan,
    _counts,
    _median_counts,
    _superiority,
    analyze,
    bootstrap_intervals,
    holm_adjust,
    main,
    rank_test,
)
from threatpulse.storage import migrate

FIXTURE = Path(__file__).parent / "fixtures" / "comparison_study.json"


@pytest.fixture
def study():
    return ComparisonStudy.model_validate_json(FIXTURE.read_text())


@pytest.fixture
def plan():
    return StatisticalPlan(
        minimum_group_size=3, permutations=999, bootstrap_resamples=999
    )


def _u(left, right):
    return sum(float(a > b) + 0.5 * float(a == b) for a in left for b in right)


def _exact_p(left, right):
    pooled = list(left) + list(right)
    observed = _u(left, right)
    statistics = []
    for selected in combinations(range(len(pooled)), len(left)):
        selection = set(selected)
        a = [value for i, value in enumerate(pooled) if i in selection]
        b = [value for i, value in enumerate(pooled) if i not in selection]
        statistics.append(_u(a, b))
    lower = sum(u <= observed for u in statistics) / len(statistics)
    upper = sum(u >= observed for u in statistics) / len(statistics)
    return min(1.0, 2 * min(lower, upper))


@pytest.mark.parametrize(
    "left,right",
    [
        ([1, 2, 3], [4, 5, 6]),
        ([1, 1, 2], [1, 2, 2]),
        ([0, 0, 0], [0, 1, 1]),
        ([1, 2, 3, 4], [2, 3, 4, 5, 6]),
        ([1, 1, 1], [1, 1, 1]),
    ],
)
def test_rank_permutation_matches_independent_exhaustive_reference(left, right, plan):
    a, b = np.array(left, dtype=float), np.array(right, dtype=float)
    result = rank_test(a, b, plan, "epss")
    assert result["u_statistic"] == _u(a, b)
    assert result["p_value"] == pytest.approx(_exact_p(a, b))
    assert result["permutation_method"] == "exact"
    assert result["exact_partitions"] == result["permutation_samples"]
    reversed_result = rank_test(b, a, plan, "epss")
    assert reversed_result["p_value"] == result["p_value"]
    assert reversed_result["u_statistic"] == len(a) * len(b) - result["u_statistic"]


def test_untied_exact_result_matches_scipy_mann_whitney(plan):
    a, b = np.array([1, 3, 6]), np.array([2, 4, 5])
    result = rank_test(a, b, plan, "epss")
    reference = mannwhitneyu(a, b, alternative="two-sided", method="exact")
    assert result["u_statistic"] == reference.statistic
    assert result["p_value"] == reference.pvalue


def test_monte_carlo_is_seeded_nonzero_and_not_mislabeled_exact(plan):
    a, b = np.arange(20), np.arange(100, 120)
    result = rank_test(a, b, plan, "epss")
    assert result == rank_test(a, b, plan, "epss")
    assert result["permutation_method"] == "monte_carlo"
    assert result["exact_partitions"] is None
    assert result["permutation_samples"] == 999
    assert result["p_value"] == result["minimum_two_sided_p"] == 0.002


@pytest.mark.parametrize(
    "left,right", [([0, 1, 1], [0, 0, 1]), ([2, 2, 2], [1, 1, 1]), ([1, 2], [1, 2])]
)
def test_superiority_and_delta_use_pair_definition_with_half_ties(left, right):
    _, a, b = _counts(np.array(left), np.array(right))
    superiority = float(_superiority(a, b))
    assert superiority == _u(left, right) / (len(left) * len(right))
    assert -1 <= 2 * superiority - 1 <= 1


@pytest.mark.parametrize(
    "samples", [([0, 0, 2], [1, 1, 1]), ([0, 1, 2, 3], [1, 1, 2, 2])]
)
def test_score_level_bootstrap_medians_match_expanded_samples(samples):
    levels = np.arange(4)
    counts = np.array([np.bincount(s, minlength=4) for s in samples])
    actual = _median_counts(levels, counts, len(samples[0]))
    assert list(actual) == [np.median(s) for s in samples]


def test_bootstrap_intervals_and_degenerate_suppression(plan):
    a = np.linspace(0, 1, 25)
    result = bootstrap_intervals(a, a, plan, "epss")
    assert result == bootstrap_intervals(a, a, plan, "epss")
    assert result["median_difference_ci_low"] < 0 < result["median_difference_ci_high"]
    assert -1 <= result["cliffs_delta_ci_low"] < 0 < result["cliffs_delta_ci_high"] <= 1
    assert result["ci_familywise_adjusted"] is False
    separated = bootstrap_intervals(np.ones(25), np.zeros(25), plan, "epss")
    assert separated["cliffs_delta_ci_low"] is None
    assert separated["median_difference_ci_high"] is None
    assert len(separated["ci_warnings"]) == 2


def test_holm_fixed_family_missing_endpoints_and_order():
    assert holm_adjust([0.01, 0.04, 0.03, None, None]) == pytest.approx(
        [0.05, 0.12, 0.12, None, None]
    )
    assert holm_adjust([None, 0.01, None, None, None]) == [None, 0.05, None, None, None]
    assert holm_adjust([0.4, 0.5, 0.6, 0.9, 1]) == [1, 1, 1, 1, 1]
    assert holm_adjust([None] * 5) == [None] * 5


@pytest.mark.parametrize("value", [-1, 1.1, float("nan"), float("inf")])
def test_invalid_p_values(value):
    with pytest.raises(ValueError):
        holm_adjust([value])


def test_default_minimum_samples_retains_descriptive_effects(study):
    result = analyze(study)
    assert result["family_size"] == 5
    assert all(
        t["status"] == "unavailable" and t["p_value_holm"] is None
        for t in result["tests"]
    )
    assert result["tests"][0]["median_difference"] == pytest.approx(59.45)
    assert result["tests"][0]["cliffs_delta"] == 0.5625
    assert all(t["bootstrap_samples"] == 0 for t in result["tests"])


def test_endpoint_coverage_versions_units_exclusions_and_multiplicity(study, plan):
    result = analyze(study, plan)
    assert [t["hypothesis_id"] for t in result["tests"]] == list(ENDPOINTS)
    assert result["exclusions"] == {"excluded_rejected": 1, "excluded_kev_conflict": 1}
    epss = result["tests"][0]
    assert epss["p_value"] == pytest.approx(16 / 70)
    assert epss["p_value_holm"] == 1
    assert epss["difference_unit"] == "percentage points"
    assert epss["kev_summary"]["min"] == 0  # Zero remains scored.
    cvss = next(t for t in result["tests"] if t["hypothesis_id"] == "cvss-3.1")
    assert cvss["status"] == "tested"
    assert cvss["difference_unit"] == "CVSS points"
    for test in result["tests"]:
        for group in ("kev", "non_kev"):
            assert test[f"{group}_cohort_n"] == 5
            assert (
                test[f"{group}_scored_n"]
                + test[f"{group}_missing_metric_n"]
                + test[f"{group}_other_versions_n"]
                == 5
            )
    assert cvss["kev_scored_n"] == 3
    assert cvss["kev_missing_metric_n"] == cvss["kev_other_versions_n"] == 1
    assert result["tests"][1]["p_value"] is None  # Too few CVSS 2.0 scores.


def test_no_variation_and_absent_group_are_explicit(study, plan):
    for observation in study.epss.observations:
        observation.epss = Decimal(0)
    epss = analyze(study, plan)["tests"][0]
    assert epss["unavailable_reason"] == "No pooled score variation"
    assert epss["p_value"] is None and epss["cliffs_delta"] == 0
    study.kev_ids = []
    empty = analyze(study, plan)["tests"][0]
    assert empty["kev_scored_n"] == 0
    assert (
        empty["median_difference"] is empty["cliffs_delta"] is empty["p_value"] is None
    )


def test_empty_study_and_no_epss_scores(study, plan):
    eligible = [
        r.cve_id
        for r in study.nvd_records
        if classify(r, set(study.kev_ids)) in ("kev", "non_kev")
    ]
    study.epss.observations = []
    study.epss.missing_cves = eligible
    result = analyze(study, plan)
    assert result["tests"][0]["kev_scored_n"] == 0
    assert result["tests"][0]["median_difference"] is None
    study.nvd_records = []
    study.epss.missing_cves = []
    assert all(t["p_value"] is None for t in analyze(study, plan)["tests"])


def test_analysis_independent_of_input_record_order(study, plan):
    first = analyze(study, plan)
    study.nvd_records.reverse()
    study.epss.observations.reverse()
    assert analyze(study, plan) == first


def test_default_plan_executes_monte_carlo_and_bootstrap_on_sufficient_cohort(study):
    """Replicated synthetic scores exercise the 20-per-group workflow, not evidence."""
    originals = {r.cve_id: r for r in study.nvd_records}
    observations = {e.cve_id: e for e in study.epss.observations}
    memberships = set(study.kev_ids)
    records, scores, missing, kev_ids = [], [], [], []
    for repeat in range(5):
        for index, (cve, record) in enumerate(originals.items()):
            group = classify(record, memberships)
            if group not in ("kev", "non_kev"):
                continue
            new_id = f"CVE-2026-{10000 + repeat * 100 + index}"
            copied = record.model_copy(deep=True)
            copied.cve_id = copied.raw_record["id"] = new_id
            records.append(copied)
            if group == "kev":
                kev_ids.append(new_id)
            if cve in observations:
                score = observations[cve].model_copy(deep=True)
                score.cve_id = score.raw_record["cve"] = new_id
                scores.append(score)
            else:
                missing.append(new_id)
    study.nvd_records, study.kev_ids = records, kev_ids
    study.epss.observations, study.epss.missing_cves = scores, missing
    result = analyze(study)
    epss = result["tests"][0]
    assert epss["kev_scored_n"] == epss["non_kev_scored_n"] == 20
    assert epss["status"] == "tested"
    assert epss["permutation_method"] == "monte_carlo"
    assert epss["permutation_samples"] == epss["bootstrap_samples"] == 9999
    assert epss["p_value_holm"] < 0.05
    assert epss["cliffs_delta_ci_low"] > 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("minimum_group_size", 2),
        ("permutations", 10),
        ("bootstrap_resamples", 0),
        ("alpha", 0),
        ("alpha", 1),
        ("alpha", float("nan")),
        ("seed", -1),
        ("seed", 2**32),
    ],
)
def test_invalid_plans(field, value):
    with pytest.raises(ValidationError):
        StatisticalPlan(**{field: value})


def test_invalid_study_rejected_before_writing(study, plan, tmp_path):
    study.epss.observations[0].score_date = study.definition.published_start
    with pytest.raises(ValidationError):
        write_report(study, tmp_path / "bad", plan)
    assert not (tmp_path / "bad").exists()


def test_report_replay_hashes_escaped_html_and_exclusive_output(study, plan, tmp_path):
    study.label = 'Synthetic <script>alert("x")</script>'
    first, second = tmp_path / "first", tmp_path / "second"
    result = write_report(study, first, plan)
    restored = ComparisonStudy.model_validate_json((first / "source.json").read_text())
    restored_plan = StatisticalPlan.model_validate_json(
        (first / "plan.json").read_text()
    )
    assert write_report(restored, second, restored_plan) == result
    manifest = json.loads((first / "manifest.json").read_text())
    for name, digest in manifest["files_sha256"].items():
        assert hashlib.sha256((first / name).read_bytes()).hexdigest() == digest
        assert (first / name).read_bytes() == (second / name).read_bytes()
    text = (first / "report.html").read_text()
    assert "<script>" not in text and "&lt;script&gt;" in text
    assert "not simultaneous" in text
    assert len(list(first.glob("*.png"))) == 2
    with pytest.raises(FileExistsError):
        write_report(study, first, plan)


def test_cli_offline_replay_and_plan_conflicts(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    assert (
        main(
            [
                "--input",
                str(FIXTURE),
                "--output",
                str(first),
                "--minimum-group-size",
                "3",
                "--permutations",
                "999",
                "--bootstrap-resamples",
                "999",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "--input",
                str(first / "source.json"),
                "--plan",
                str(first / "plan.json"),
                "--output",
                str(second),
            ]
        )
        == 0
    )
    assert (first / "analysis.json").read_bytes() == (
        second / "analysis.json"
    ).read_bytes()
    with pytest.raises(SystemExit):
        main(
            [
                "--input",
                str(FIXTURE),
                "--plan",
                str(first / "plan.json"),
                "--seed",
                "1",
                "--output",
                str(tmp_path / "conflict"),
            ]
        )


def test_cli_missing_url_and_redacted_failure(monkeypatch, capsys, tmp_path):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    args = ["--study-id", str(uuid4()), "--output", str(tmp_path / "report")]
    assert main(args) == 1
    assert "Set DATABASE_URL" in capsys.readouterr().err
    monkeypatch.setenv("DATABASE_URL", "invalid-database-credential")

    def fail(*a, **k):
        raise psycopg.OperationalError("invalid-database-credential")

    monkeypatch.setattr("threatpulse.statistics.psycopg.connect", fail)
    assert main(args) == 1
    assert "invalid-database-credential" not in capsys.readouterr().err


def test_postgres_study_analysis_is_readonly_and_preserves_replay(
    connection, study, plan, monkeypatch, tmp_path
):
    migrate(connection)
    save_study(connection, study)
    schema = connection.execute("SELECT current_schema()").fetchone()[0]
    original_connect = psycopg.connect

    def connect(*a, **k):
        return original_connect(*a, **k, options=f"-c search_path={schema}")

    from threatpulse.statistics import load_study

    def read(conn, study_id):
        assert conn.execute("SHOW transaction_read_only").fetchone() == ("on",)
        assert conn.execute("SHOW transaction_isolation").fetchone() == (
            "repeatable read",
        )
        return load_study(conn, study_id)

    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr("threatpulse.statistics.psycopg.connect", connect)
    monkeypatch.setattr("threatpulse.statistics.load_study", read)
    output = tmp_path / "db"
    assert (
        main(
            [
                "--study-id",
                str(study.study_id),
                "--output",
                str(output),
                "--minimum-group-size",
                "3",
                "--permutations",
                "999",
                "--bootstrap-resamples",
                "999",
            ]
        )
        == 0
    )
    exported = ComparisonStudy.model_validate_json((output / "source.json").read_text())
    assert analyze(exported, plan) == analyze(study, plan)
    assert connection.execute("SELECT count(*) FROM comparison_studies").fetchone() == (
        1,
    )
    assert connection.execute("SELECT count(*) FROM vulnerabilities").fetchone() == (0,)
