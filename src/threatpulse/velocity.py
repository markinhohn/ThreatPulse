"""Quality-gated EPSS Threat Velocity with frozen, replayable inputs."""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import UTC, date, datetime, timedelta
from fractions import Fraction
from itertools import combinations
from pathlib import Path
from statistics import median
from typing import Literal

import psycopg
from psycopg.rows import dict_row
from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    model_validator,
)

from threatpulse.epss import EpssObservation
from threatpulse.models import CveId
from threatpulse.trends import TrendDataset

POLICY = {
    "method_version": 1,
    "policy_version": "0.1",
    "lookback_calendar_days": 7,
    "minimum_observed_dates": 5,
    "minimum_span_calendar_days": 4,
    "maximum_adjacent_gap_calendar_days": 2,
    "maximum_latest_score_calendar_age_days_utc": 2,
    "minimum_latest_epss": "0.01",
    "minimum_endpoint_change_pp": "5",
    "minimum_median_pairwise_slope_pp_per_day": "0.5",
    "requires_reviewed_model_regime": True,
    "automatic_downgrades": False,
    "eligible_promotion": {"P3": "P2"},
}


class VelocityObservation(EpssObservation):
    """An EPSS value and a defensible upper bound on its availability."""

    model_config = ConfigDict(extra="forbid")
    available_at: AwareDatetime
    availability_basis: Literal[
        "database_export", "history_export", "validated_capture"
    ]

    @model_validator(mode="after")
    def validate_availability(self):
        if self.available_at < self.ingested_at:
            raise ValueError("Availability cannot precede the collection timestamp")
        return self


class ModelRegime(BaseModel):
    """A bounded operator-reviewed assertion, not automatic provider verification."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    regime_id: str = Field(min_length=1, max_length=100, pattern=r"^[\w.-]+$")
    score_date_start: date
    score_date_end: date
    reviewed_at: AwareDatetime
    reviewer: str = Field(min_length=1, max_length=200)
    evidence_url: HttpUrl
    evidence: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def validate_dates(self):
        if self.score_date_end < self.score_date_start:
            raise ValueError("Model regime dates must be increasing")
        if self.score_date_end > self.reviewed_at.astimezone(UTC).date():
            raise ValueError("A review cannot attest future score dates")
        return self


class ModelRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    regimes: list[ModelRegime] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_ranges(self):
        if len({r.regime_id for r in self.regimes}) != len(self.regimes):
            raise ValueError("Duplicate model regime identifier")
        ordered = sorted(self.regimes, key=lambda r: r.score_date_start)
        if any(
            left.score_date_end >= right.score_date_start
            for left, right in zip(ordered, ordered[1:], strict=False)
        ):
            raise ValueError("Model regime date ranges overlap")
        return self


class VelocityDataset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dataset_kind: Literal["threat_velocity"] = "threat_velocity"
    schema_version: Literal[1] = 1
    captured_at: AwareDatetime
    label: str = "Stored ThreatPulse EPSS history"
    cohort: list[CveId]
    epss_observations: list[VelocityObservation]
    model_registry: ModelRegistry = Field(default_factory=ModelRegistry)

    @model_validator(mode="after")
    def validate_history(self):
        cohort = set(self.cohort)
        if len(cohort) != len(self.cohort):
            raise ValueError("Duplicate cohort CVE")
        keys = {(e.cve_id, e.score_date) for e in self.epss_observations}
        if len(keys) != len(self.epss_observations):
            raise ValueError("Duplicate EPSS CVE/date")
        if any(e.cve_id not in cohort for e in self.epss_observations):
            raise ValueError("EPSS observation outside the frozen cohort")
        return self


def from_history(history: TrendDataset) -> VelocityDataset:
    """A latest-row export cannot prove what an earlier version contained."""
    return VelocityDataset(
        captured_at=history.captured_at,
        label=history.label,
        cohort=history.cohort,
        epss_observations=[
            VelocityObservation(
                **e.model_dump(),
                available_at=max(history.captured_at, e.ingested_at),
                availability_basis="history_export",
            )
            for e in history.epss_observations
        ],
    )


def read_dataset(connection) -> VelocityDataset:
    """Caller owns a REPEATABLE READ, READ ONLY transaction; no migrations."""
    with connection.cursor(row_factory=dict_row) as cursor:
        cohort = [
            r["cve_id"]
            for r in cursor.execute(
                "SELECT cve_id FROM vulnerabilities ORDER BY cve_id"
            )
        ]
        rows = cursor.execute(
            "SELECT cve_id, score_date, epss, percentile, source_url, "
            "ingested_at, raw_record FROM epss_observations ORDER BY cve_id, score_date"
        ).fetchall()
        captured = cursor.execute("SELECT clock_timestamp() AS t").fetchone()["t"]
    return VelocityDataset(
        captured_at=captured,
        cohort=cohort,
        epss_observations=[
            VelocityObservation(
                **r,
                available_at=max(captured, r["ingested_at"]),
                availability_basis="database_export",
            )
            for r in rows
        ],
    )


def _comparability(registry, first, latest, decision):
    if first is None:
        return "unknown", []
    # Check every intervening calendar date, including dates without CVE scores.
    regimes = [r for r in registry.regimes if r.reviewed_at <= decision]
    covering = []
    for offset in range((latest - first).days + 1):
        day = first + timedelta(days=offset)
        match = next(
            (r for r in regimes if r.score_date_start <= day <= r.score_date_end), None
        )
        if match is None:
            return "unknown", sorted(
                {
                    r.regime_id
                    for r in regimes
                    if r.score_date_start <= latest and r.score_date_end >= first
                }
            )
        covering.append(match.regime_id)
    ids = sorted(set(covering))
    return ("comparable" if len(ids) == 1 else "model_boundary"), ids


def analyze(dataset: VelocityDataset, decision_at=None):
    """Calculate exact rational rates; round only the exported display values."""
    dataset = VelocityDataset.model_validate(dataset.model_dump())
    decision = decision_at or dataset.captured_at
    if decision.tzinfo is None or decision.utcoffset() is None:
        raise ValueError("decision_at must include a timezone")
    decision = decision.astimezone(UTC)
    if decision > dataset.captured_at:
        raise ValueError("decision_at cannot follow the frozen export")
    by_cve, excluded = defaultdict(list), defaultdict(list)
    for observation in dataset.epss_observations:
        if observation.available_at > decision:
            reason = "NOT_AVAILABLE_AT_DECISION"
        elif observation.score_date > decision.date():
            reason = "FUTURE_SCORE_DATE"
        else:
            by_cve[observation.cve_id].append(observation)
            continue
        excluded[observation.cve_id].append(
            {"score_date": observation.score_date.isoformat(), "reason": reason}
        )
    results, series, intervals = [], [], []
    for cve in sorted(dataset.cohort):
        available = sorted(by_cve[cve], key=lambda e: e.score_date)
        latest = available[-1].score_date if available else None
        start = (
            latest - timedelta(days=POLICY["lookback_calendar_days"])
            if latest
            else None
        )
        used = [e for e in available if e.score_date >= start] if latest else []
        dates = [e.score_date for e in used]
        probabilities = [Fraction(e.epss) for e in used]
        span = (latest - dates[0]).days if used else 0
        gaps = [(b - a).days for a, b in zip(dates, dates[1:], strict=False)]
        expected = POLICY["lookback_calendar_days"] + 1
        calendar = [start + timedelta(days=i) for i in range(expected)] if start else []
        missing = [d.isoformat() for d in calendar if d not in dates]
        endpoint = (
            100 * (probabilities[-1] - probabilities[0]) if len(used) >= 2 else None
        )
        slopes = [
            100 * (probabilities[j] - probabilities[i]) / (dates[j] - dates[i]).days
            for i, j in combinations(range(len(used)), 2)
        ]
        slope = median(slopes) if slopes else None
        comparable, regime_ids = _comparability(
            dataset.model_registry, dates[0] if dates else None, latest, decision
        )
        reasons = []
        if not used:
            reasons.append("NO_OBSERVATIONS")
        if len(used) < POLICY["minimum_observed_dates"]:
            reasons.append("INSUFFICIENT_OBSERVED_DATES")
        if span < POLICY["minimum_span_calendar_days"]:
            reasons.append("INSUFFICIENT_SPAN")
        if max(gaps, default=0) > POLICY["maximum_adjacent_gap_calendar_days"]:
            reasons.append("GAP_EXCEEDS_LIMIT")
        age = (decision.date() - latest).days if latest else None
        if (
            age is not None
            and age > POLICY["maximum_latest_score_calendar_age_days_utc"]
        ):
            reasons.append("STALE_LATEST_SCORE")
        if probabilities and probabilities[-1] < Fraction(
            POLICY["minimum_latest_epss"]
        ):
            reasons.append("LATEST_SCORE_BELOW_THRESHOLD")
        if comparable != "comparable":
            reasons.append(
                "MODEL_REGIME_BOUNDARY"
                if comparable == "model_boundary"
                else "MODEL_REGIME_UNKNOWN"
            )
        if endpoint is not None and endpoint < Fraction(
            POLICY["minimum_endpoint_change_pp"]
        ):
            reasons.append("ENDPOINT_CHANGE_BELOW_THRESHOLD")
        if slope is not None and slope < Fraction(
            POLICY["minimum_median_pairwise_slope_pp_per_day"]
        ):
            reasons.append("SLOPE_BELOW_THRESHOLD")
        if any(e["reason"] == "FUTURE_SCORE_DATE" for e in excluded[cve]):
            reasons.append("INVALID_FUTURE_SCORE_DATE")
        results.append(
            {
                "cve_id": cve,
                "window_start": start.isoformat() if start else None,
                "window_end": latest.isoformat() if latest else None,
                "observed_dates": len(used),
                "expected_calendar_dates": expected if used else None,
                "coverage_fraction": len(used) / expected if used else None,
                "span_calendar_days": span if used else None,
                "missing_dates": missing,
                "maximum_adjacent_gap_days": max(gaps) if gaps else None,
                "latest_epss": float(probabilities[-1]) if probabilities else None,
                "latest_score_age_days": age,
                "endpoint_change_pp": float(endpoint) if endpoint is not None else None,
                "endpoint_rate_pp_per_day": float(endpoint / span)
                if endpoint is not None
                else None,
                "median_pairwise_slope_pp_per_day": float(slope)
                if slope is not None
                else None,
                "pairwise_slopes": len(slopes),
                "descriptive_direction": "increasing"
                if slope is not None and slope > 0
                else "decreasing"
                if slope is not None and slope < 0
                else "flat"
                if slope is not None
                else "unavailable",
                "model_comparability": comparable,
                "model_regime_ids": regime_ids,
                "rising_signal": not reasons,
                "eligibility_reasons": reasons or ["ELIGIBLE_RISING"],
                "excluded_observations": sorted(
                    excluded[cve], key=lambda e: (e["score_date"], e["reason"])
                ),
            }
        )
        for observation in used:
            series.append(observation.model_dump(mode="json"))
        for left, right in zip(used, used[1:], strict=False):
            elapsed = (right.score_date - left.score_date).days
            delta = 100 * (Fraction(right.epss) - Fraction(left.epss))
            state, ids = _comparability(
                dataset.model_registry, left.score_date, right.score_date, decision
            )
            intervals.append(
                {
                    "cve_id": cve,
                    "earlier_date": left.score_date.isoformat(),
                    "later_date": right.score_date.isoformat(),
                    "elapsed_calendar_days": elapsed,
                    "missing_days_between": elapsed - 1,
                    "change_pp": float(delta),
                    "rate_pp_per_day": float(delta / elapsed),
                    "model_comparability": state,
                    "model_regime_ids": ids,
                }
            )
    return {
        "analysis_format": 1,
        "label": dataset.label,
        "captured_at": dataset.captured_at.astimezone(UTC).isoformat(),
        "decision_at": decision.isoformat(),
        "policy": deepcopy(POLICY),
        "cohort_cves": len(dataset.cohort),
        "rising_cves": sum(r["rising_signal"] for r in results),
        "with_rates": sum(
            r["median_pairwise_slope_pp_per_day"] is not None for r in results
        ),
        "comparability_counts": dict(
            sorted(Counter(r["model_comparability"] for r in results).items())
        ),
        "reason_counts": dict(
            sorted(
                Counter(
                    code for r in results for code in r["eligibility_reasons"]
                ).items()
            )
        ),
        "series": series,
        "intervals": intervals,
        "cves": results,
    }


def main(argv=None):
    from threatpulse.velocity_report import write_report

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, required=True, help="New report directory"
    )
    parser.add_argument(
        "--input", type=Path, help="Replay velocity or trend source.json"
    )
    parser.add_argument(
        "--decision-at",
        type=datetime.fromisoformat,
        help="Aware ISO timestamp, at or before export",
    )
    parser.add_argument(
        "--model-regimes", type=Path, help="Reviewed bounded model registry JSON"
    )
    args = parser.parse_args(argv)
    try:
        if args.input:
            payload = json.loads(args.input.read_text())
            dataset = (
                VelocityDataset.model_validate(payload)
                if isinstance(payload, dict)
                and payload.get("dataset_kind") == "threat_velocity"
                else from_history(TrendDataset.model_validate(payload))
            )
        else:
            url = os.environ.get("DATABASE_URL")
            if not url:
                print("Set DATABASE_URL or pass --input source.json.", file=sys.stderr)
                return 1
            with psycopg.connect(url, connect_timeout=10) as connection:
                connection.execute(
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
                )
                dataset = read_dataset(connection)
        if args.model_regimes:
            dataset.model_registry = ModelRegistry.model_validate_json(
                args.model_regimes.read_text()
            )
        write_report(dataset, args.output, decision_at=args.decision_at)
    except (psycopg.Error, ValueError, OSError) as exc:
        print(
            f"Threat Velocity failed ({type(exc).__name__}). Check database setup, "
            "input format, decision time, model registry, and use a new "
            "output directory.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps({"report": str(args.output / "report.html")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
