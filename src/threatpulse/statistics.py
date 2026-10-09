"""Reproducible exploratory inference for frozen KEV/non-KEV studies."""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from uuid import UUID

import numpy as np
import psycopg
from pydantic import BaseModel, ConfigDict, Field
from scipy.stats import permutation_test, rankdata

from threatpulse.comparison import ComparisonStudy, load_study
from threatpulse.comparison_report import analyze as describe_study
from threatpulse.exploration import CVSS_VERSIONS, describe

ENDPOINTS = ("epss", *(f"cvss-{v}" for v in CVSS_VERSIONS))


class StatisticalPlan(BaseModel):
    """Settings chosen before examining results; not a formal power analysis."""

    model_config = ConfigDict(extra="forbid")
    minimum_group_size: int = Field(default=20, ge=3, le=100000)
    permutations: int = Field(default=9999, ge=999, le=100000)
    bootstrap_resamples: int = Field(default=9999, ge=999, le=100000)
    alpha: float = Field(default=0.05, gt=0, lt=1, allow_inf_nan=False)
    seed: int = Field(default=20261009, ge=0, le=2**32 - 1)


def holm_adjust(p_values):
    """Fixed family: unavailable endpoints participate as p=1, return null."""
    values = [1.0 if p is None else float(p) for p in p_values]
    if any(not np.isfinite(p) or not 0 <= p <= 1 for p in values):
        raise ValueError("Invalid p-value")
    adjusted = [None] * len(values)
    running = 0.0
    for rank, index in enumerate(sorted(range(len(values)), key=values.__getitem__)):
        running = max(running, min(1.0, (len(values) - rank) * values[index]))
        if p_values[index] is not None:
            adjusted[index] = running
    return adjusted


def _seed(plan, endpoint, purpose):
    value = f"{plan.seed}:{endpoint}:{purpose}".encode()
    return int.from_bytes(hashlib.sha256(value).digest()[:4], "big")


def _partition_count(n, k, cap):
    """Return the exact count when enumeration fits; avoid huge integers."""
    count = 1
    for i in range(1, min(k, n - k) + 1):
        count = count * (n - i + 1) // i
        if count > cap:
            return None
    return count


def _counts(left, right):
    levels, indices = np.unique(np.concatenate((left, right)), return_inverse=True)
    a = np.bincount(indices[: len(left)], minlength=len(levels))
    b = np.bincount(indices[len(left) :], minlength=len(levels))
    return levels, a, b


def _superiority(a, b):
    """P(KEV > non-KEV) + half P(tie), from sorted score-level counts."""
    below = np.cumsum(b, axis=-1) - b
    wins = np.sum(a * (below + 0.5 * b), axis=-1)
    return wins / (np.sum(a, axis=-1) * np.sum(b, axis=-1))


def rank_test(left, right, plan, endpoint):
    """Permutation calibration of Mann-Whitney U; midpoint ranks handle ties."""
    ranks = rankdata(np.concatenate((left, right)), method="average")
    n = len(left)
    batch = max(1, min(128, 2_000_000 // len(ranks)))

    def statistic(a, b, axis):
        return np.sum(a, axis=axis) - n * (n + 1) / 2

    seed = _seed(plan, endpoint, "permutation")
    result = permutation_test(
        (ranks[:n], ranks[n:]),
        statistic,
        permutation_type="independent",
        vectorized=True,
        n_resamples=plan.permutations,
        batch=batch,
        alternative="two-sided",
        rng=np.random.Generator(np.random.PCG64(seed)),
    )
    partitions = _partition_count(len(ranks), n, plan.permutations)
    samples = len(result.null_distribution)
    return {
        "u_statistic": float(result.statistic),
        "p_value": float(result.pvalue),
        "permutation_method": "exact" if partitions is not None else "monte_carlo",
        "permutation_samples": samples,
        "exact_partitions": partitions,
        "permutation_seed": seed,
        "minimum_two_sided_p": min(
            1.0, 2 / (samples if partitions is not None else samples + 1)
        ),
    }


def _median_counts(levels, counts, n):
    cumulative = np.cumsum(counts, axis=-1)
    lower = np.sum(cumulative <= (n - 1) // 2, axis=-1)
    upper = np.sum(cumulative <= n // 2, axis=-1)
    return (levels[lower] + levels[upper]) / 2


def bootstrap_intervals(left, right, plan, endpoint):
    """Independent within-group percentile bootstrap, bounded score-level batches."""
    levels, a, b = _counts(left, right)
    n, m = len(left), len(right)
    seed = _seed(plan, endpoint, "bootstrap")
    rng = np.random.Generator(np.random.PCG64(seed))
    batch = max(1, min(128, 2_000_000 // len(levels)))
    median_changes, deltas = [], []
    for offset in range(0, plan.bootstrap_resamples, batch):
        size = min(batch, plan.bootstrap_resamples - offset)
        x = rng.multinomial(n, a / n, size=size)
        y = rng.multinomial(m, b / m, size=size)
        median_changes.extend(
            _median_counts(levels, x, n) - _median_counts(levels, y, m)
        )
        deltas.extend(2 * _superiority(x, y) - 1)
    bounds = (plan.alpha / 2, 1 - plan.alpha / 2)
    result = {
        "bootstrap_seed": seed,
        "bootstrap_samples": plan.bootstrap_resamples,
        "ci_confidence": 1 - plan.alpha,
        "ci_method": "percentile, within-group",
        "ci_familywise_adjusted": False,
        "ci_warnings": [],
    }
    for name, values in (
        ("median_difference", median_changes),
        ("cliffs_delta", deltas),
    ):
        low, high = (float(q) for q in np.quantile(values, bounds, method="linear"))
        # Empirical bootstraps can collapse, particularly under complete separation.
        # A zero-width interval does not establish zero population uncertainty.
        result[f"{name}_ci_low"] = low if low < high else None
        result[f"{name}_ci_high"] = high if low < high else None
        if low >= high:
            result["ci_warnings"].append(
                f"{name}: degenerate bootstrap interval suppressed"
            )
    return result


def _endpoint(rows, endpoint, plan):
    metric = "epss" if endpoint == "epss" else "cvss"
    version = None if metric == "epss" else endpoint.removeprefix("cvss-")
    field = "epss" if metric == "epss" else "base_score"
    scale = 100 if metric == "epss" else 1
    groups = [[r for r in rows if r["group"] == g] for g in ("kev", "non_kev")]
    samples = [
        np.array(
            [
                float(r[field]) * scale
                for r in group
                if r[field] is not None
                and (version is None or r["cvss_version"] == version)
            ]
        )
        for group in groups
    ]
    left, right = samples
    row = {
        "hypothesis_id": endpoint,
        "metric": metric,
        "cvss_version": version,
        "null_hypothesis": (
            "Equal scored-value distributions under exchangeable group labels"
        ),
        "alternative": "two-sided rank difference",
        "difference_direction": "KEV minus non-KEV",
        "difference_unit": "percentage points" if metric == "epss" else "CVSS points",
        "status": "unavailable",
        "unavailable_reason": None,
        "kev_summary": describe(left),
        "non_kev_summary": describe(right),
        "median_difference": float(np.median(left) - np.median(right))
        if len(left) and len(right)
        else None,
        "probability_superiority": None,
        "cliffs_delta": None,
        "u_statistic": None,
        "p_value": None,
        "p_value_holm": None,
        "reject_null_holm": None,
        "permutation_method": None,
        "permutation_samples": 0,
        "exact_partitions": None,
        "permutation_seed": _seed(plan, endpoint, "permutation"),
        "minimum_two_sided_p": None,
        "bootstrap_samples": 0,
        "bootstrap_seed": _seed(plan, endpoint, "bootstrap"),
        "ci_confidence": 1 - plan.alpha,
        "ci_method": "percentile, within-group",
        "ci_familywise_adjusted": False,
        "ci_warnings": [],
        "median_difference_ci_low": None,
        "median_difference_ci_high": None,
        "cliffs_delta_ci_low": None,
        "cliffs_delta_ci_high": None,
    }
    for label, group, values in zip(("kev", "non_kev"), groups, samples, strict=True):
        missing = sum(r[field] is None for r in group)
        row.update(
            {
                f"{label}_cohort_n": len(group),
                f"{label}_scored_n": len(values),
                f"{label}_missing_metric_n": missing,
                f"{label}_other_versions_n": len(group) - len(values) - missing,
                f"{label}_selected_fraction": len(values) / len(group)
                if group
                else None,
            }
        )
    if len(left) and len(right):
        levels, a, b = _counts(left, right)
        effect = float(_superiority(a, b))
        row["probability_superiority"] = effect
        row["cliffs_delta"] = 2 * effect - 1
        row["pooled_unique_scores"] = len(levels)
        row["pooled_tied_observations"] = int(np.sum((a + b)[a + b > 1]))
    else:
        row["pooled_unique_scores"] = len(np.unique(np.concatenate((left, right))))
        row["pooled_tied_observations"] = None
    if min(len(left), len(right)) < plan.minimum_group_size:
        row["unavailable_reason"] = (
            f"Require at least {plan.minimum_group_size} scored CVEs per group"
        )
    elif len(np.unique(np.concatenate((left, right)))) == 1:
        row["unavailable_reason"] = "No pooled score variation"
    else:
        row["status"] = "tested"
        row.update(rank_test(left, right, plan, endpoint))
        row.update(bootstrap_intervals(left, right, plan, endpoint))
    return row


def analyze(study: ComparisonStudy, plan: StatisticalPlan | None = None):
    plan = StatisticalPlan.model_validate((plan or StatisticalPlan()).model_dump())
    descriptive = describe_study(study)
    rows = sorted(descriptive["rows"], key=lambda r: r["cve_id"])
    tests = [_endpoint(rows, endpoint, plan) for endpoint in ENDPOINTS]
    adjusted = holm_adjust([t["p_value"] for t in tests])
    for test, p_value in zip(tests, adjusted, strict=True):
        test["p_value_holm"] = p_value
        test["reject_null_holm"] = (
            p_value <= plan.alpha if p_value is not None else None
        )
    return {
        "analysis_format": 1,
        "study_id": descriptive["study_id"],
        "label": study.label,
        "definition": descriptive["definition"],
        "collected_at": descriptive["collected_at"],
        "kev_snapshot_at": descriptive["kev_snapshot_at"],
        "plan": plan.model_dump(),
        "test_family": list(ENDPOINTS),
        "family_size": len(ENDPOINTS),
        "multiplicity_method": "Holm; unavailable endpoints included as p=1",
        "coverage": descriptive["coverage"],
        "exclusions": descriptive["exclusions"],
        "tests": tests,
        "rows": rows,
    }


def main(argv=None):
    from threatpulse.statistical_report import write_report

    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", type=Path, help="Frozen comparison source.json")
    source.add_argument("--study-id", type=UUID, help="Frozen database study UUID")
    parser.add_argument(
        "--output", required=True, type=Path, help="New report directory"
    )
    parser.add_argument("--plan", type=Path, help="Replay exported plan.json")
    parser.add_argument("--minimum-group-size", type=int, default=None)
    parser.add_argument("--permutations", type=int, default=None)
    parser.add_argument("--bootstrap-resamples", type=int, default=None)
    parser.add_argument("--alpha", type=float, default=None)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args(argv)
    overrides = {
        k: getattr(args, k)
        for k in StatisticalPlan.model_fields
        if getattr(args, k) is not None
    }
    if args.plan and overrides:
        parser.error("Use --plan or explicit settings, not both")
    try:
        if args.output.exists():
            raise FileExistsError("Use a new output directory")
        plan = (
            StatisticalPlan.model_validate_json(args.plan.read_text())
            if args.plan
            else StatisticalPlan(**overrides)
        )
        if args.input:
            study = ComparisonStudy.model_validate_json(args.input.read_text())
        else:
            url = os.environ.get("DATABASE_URL")
            if not url:
                print("Set DATABASE_URL for stored study analysis.", file=sys.stderr)
                return 1
            with psycopg.connect(url, connect_timeout=10) as conn:
                conn.execute(
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
                )
                study = load_study(conn, args.study_id)
        write_report(study, args.output, plan)
    except (psycopg.Error, ValueError, OSError) as exc:
        print(
            f"Statistical analysis failed ({type(exc).__name__}). Check the study, "
            "plan, database setup, and use a new output directory.",
            file=sys.stderr,
        )
        return 1
    print(
        json.dumps(
            {
                "study_id": str(study.study_id),
                "report": str(args.output / "report.html"),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
