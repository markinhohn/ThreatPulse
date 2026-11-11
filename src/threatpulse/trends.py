"""Read-only historical KEV, NVD, and EPSS trend analysis."""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import UTC, date, timedelta
from pathlib import Path
from typing import Literal

import psycopg
from psycopg.rows import dict_row
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from threatpulse.epss import EpssObservation
from threatpulse.exploration import describe
from threatpulse.kev import CollectedVulnerability
from threatpulse.models import CveId
from threatpulse.nvd import NvdRecord


class Run(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: int = Field(gt=0)
    run_date: date
    started_at: AwareDatetime
    finished_at: AwareDatetime | None
    status: Literal["running", "succeeded", "failed", "interrupted"]


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: int
    source: Literal["kev", "nvd", "epss"]
    processed: int = Field(ge=0)
    missing_cves: list[CveId]
    finished_at: AwareDatetime


class KevSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: int
    observation: CollectedVulnerability


class NvdSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: int
    observation: NvdRecord


class TrendDataset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    captured_at: AwareDatetime
    label: str = "Stored ThreatPulse history"
    cohort: list[CveId]
    runs: list[Run]
    steps: list[Step]
    kev_snapshots: list[KevSnapshot]
    nvd_snapshots: list[NvdSnapshot]
    epss_observations: list[EpssObservation]

    @model_validator(mode="after")
    def validate_history(self):
        cohort = set(self.cohort)
        runs = {r.id for r in self.runs}
        steps = {(s.run_id, s.source): s for s in self.steps}
        if len(cohort) != len(self.cohort) or len(runs) != len(self.runs):
            raise ValueError("Duplicate cohort CVE or run")
        if len(steps) != len(self.steps):
            raise ValueError("Duplicate checkpoint")
        for step in self.steps:
            if step.run_id not in runs:
                raise ValueError("Checkpoint without run")
            if len(set(step.missing_cves)) != len(step.missing_cves):
                raise ValueError("Duplicate missing CVE")
            if not set(step.missing_cves) <= cohort:
                raise ValueError("Missing CVE outside cohort")
        for source, snapshots in (
            ("kev", self.kev_snapshots),
            ("nvd", self.nvd_snapshots),
        ):
            seen = set()
            counts = Counter()
            for snapshot in snapshots:
                record = snapshot.observation
                cve = record.kev.cve_id if source == "kev" else record.cve_id
                if source == "kev" and cve != record.vulnerability.cve_id:
                    raise ValueError("KEV identifiers disagree")
                key = (snapshot.run_id, cve)
                step = steps.get((snapshot.run_id, source))
                if key in seen or cve not in cohort or step is None:
                    raise ValueError("Duplicate, orphan, or out-of-cohort snapshot")
                if cve in step.missing_cves:
                    raise ValueError("Snapshot also declared missing")
                seen.add(key)
                counts[snapshot.run_id] += 1
            for step in self.steps:
                if step.source == source:
                    count = counts[step.run_id]
                    # NVD processed counts latest-row writes, excluding stale data.
                    if (source == "kev" and count != step.processed) or (
                        source == "nvd" and step.processed > count
                    ):
                        raise ValueError("Snapshot and checkpoint counts disagree")
        keys = {(e.cve_id, e.score_date) for e in self.epss_observations}
        if len(keys) != len(self.epss_observations):
            raise ValueError("Duplicate EPSS CVE/date")
        if any(e.cve_id not in cohort for e in self.epss_observations):
            raise ValueError("EPSS observation outside cohort")
        return self


def read_dataset(connection) -> TrendDataset:
    """Caller owns a REPEATABLE READ, READ ONLY transaction; no migrations."""
    with connection.cursor(row_factory=dict_row) as cursor:
        captured = cursor.execute("SELECT transaction_timestamp() AS t").fetchone()["t"]
        cohort = [
            r["cve_id"]
            for r in cursor.execute(
                "SELECT cve_id FROM vulnerabilities ORDER BY cve_id"
            )
        ]
        runs = cursor.execute(
            "SELECT id, run_date, started_at, finished_at, status "
            "FROM ingestion_runs ORDER BY id"
        ).fetchall()
        steps = cursor.execute(
            "SELECT run_id, source, processed, missing_cves, finished_at "
            "FROM ingestion_steps ORDER BY finished_at, run_id, source"
        ).fetchall()
        kev = cursor.execute(
            "SELECT run_id, observation FROM kev_snapshots ORDER BY run_id, cve_id"
        ).fetchall()
        nvd = cursor.execute(
            "SELECT run_id, observation FROM nvd_snapshots ORDER BY run_id, cve_id"
        ).fetchall()
        epss = cursor.execute(
            "SELECT cve_id, score_date, epss, percentile, source_url, "
            "ingested_at, raw_record FROM epss_observations ORDER BY score_date, cve_id"
        ).fetchall()
    return TrendDataset(
        captured_at=captured,
        cohort=cohort,
        runs=runs,
        steps=steps,
        kev_snapshots=kev,
        nvd_snapshots=nvd,
        epss_observations=epss,
    )


def _day(timestamp):
    return timestamp.astimezone(UTC).date()


def _captures(dataset, source, start, end):
    """A committed source remains usable even if a later step failed."""
    runs = {r.id: r for r in dataset.runs}
    return sorted(
        [
            s
            for s in dataset.steps
            if s.source == source and start <= _day(s.finished_at) <= end
        ],
        key=lambda s: (s.finished_at, s.run_id),
    ), runs


def kev_trends(dataset, start, end):
    captures, runs = _captures(dataset, "kev", start, end)
    records = defaultdict(dict)
    for snapshot in dataset.kev_snapshots:
        records[snapshot.run_id][snapshot.observation.kev.cve_id] = snapshot.observation
    coverage, events, seen = [], [], set()
    previous = None
    for capture in captures:
        current = records[capture.run_id]
        before = records[previous.run_id] if previous else {}
        added = set(current) - set(before) if previous else set()
        removed = set(before) - set(current) if previous else set()
        coverage.append(
            {
                "run_id": capture.run_id,
                "run_date": runs[capture.run_id].run_date.isoformat(),
                "run_status": runs[capture.run_id].status,
                "captured_at": capture.finished_at.isoformat(),
                "catalog_cves": len(current),
                "previous_run_id": previous.run_id if previous else None,
                "added": len(added) if previous else None,
                "removed": len(removed) if previous else None,
                "interval_days": (
                    _day(capture.finished_at) - _day(previous.finished_at)
                ).days
                if previous
                else None,
            }
        )
        for kind, ids, source_records in (
            ("added", added, current),
            ("removed", removed, before),
        ):
            for cve in sorted(ids):
                record = source_records[cve]
                events.append(
                    {
                        "cve_id": cve,
                        "kind": kind,
                        "earlier_run_id": previous.run_id,
                        "later_run_id": capture.run_id,
                        "interval_start": previous.finished_at.isoformat(),
                        "interval_end": capture.finished_at.isoformat(),
                        "cisa_date_added": record.kev.date_added.isoformat(),
                        "reappearance": kind == "added" and cve in seen,
                        "vendor": record.vulnerability.vendor,
                        "product": record.vulnerability.product,
                    }
                )
        seen.update(current)
        previous = capture
    return {"captures": coverage, "events": events}


def _metric(record):
    metric = record.preferred_cvss
    if metric is None:
        return None
    return {
        "version": metric.version,
        "source": metric.source,
        "metric_type": metric.metric_type,
        "vector": metric.vector,
        "base_score": float(metric.base_score),
        "severity": metric.severity,
    }


def nvd_trends(dataset, start, end):
    captures, runs = _captures(dataset, "nvd", start, end)
    records = defaultdict(dict)
    for snapshot in dataset.nvd_snapshots:
        records[snapshot.run_id][snapshot.observation.cve_id] = snapshot.observation
    coverage, pairs, intervals = [], [], []
    previous = None
    for capture in captures:
        current = records[capture.run_id]
        coverage.append(
            {
                "run_id": capture.run_id,
                "run_date": runs[capture.run_id].run_date.isoformat(),
                "run_status": runs[capture.run_id].status,
                "captured_at": capture.finished_at.isoformat(),
                "observed": len(current),
                "scored": sum(r.preferred_cvss is not None for r in current.values()),
                "missing_requested": len(capture.missing_cves),
                "latest_rows_written": capture.processed,
            }
        )
        if previous:
            before = records[previous.run_id]
            common = set(before) & set(current)
            interval_pairs = []
            for cve in sorted(common):
                left, right = before[cve], current[cve]
                a, b = _metric(left), _metric(right)
                if a is None and b is None:
                    kind = "unscored"
                elif a is None:
                    kind = "metric_added"
                elif b is None:
                    kind = "metric_removed"
                elif a["version"] != b["version"]:
                    kind = "version_changed"
                elif a["source"] != b["source"]:
                    kind = "source_changed"
                elif a["metric_type"] != b["metric_type"]:
                    kind = "metric_type_changed"
                else:
                    kind = "metric_changed" if a != b else "unchanged"
                regression = right.modified_at < left.modified_at
                comparable = (
                    kind in ("metric_changed", "unchanged")
                    and not regression
                    and "Rejected" not in (left.status, right.status)
                )
                interval_pairs.append(
                    {
                        "cve_id": cve,
                        "earlier_run_id": previous.run_id,
                        "later_run_id": capture.run_id,
                        "interval_start": previous.finished_at.isoformat(),
                        "interval_end": capture.finished_at.isoformat(),
                        "earlier_modified_at": left.modified_at.isoformat(),
                        "later_modified_at": right.modified_at.isoformat(),
                        "earlier_status": left.status,
                        "later_status": right.status,
                        "earlier_metric": a,
                        "later_metric": b,
                        "kind": kind,
                        "comparable": comparable,
                        "modified_at_regressed": regression,
                        "severity_changed": a["severity"] != b["severity"]
                        if comparable
                        else None,
                        "score_change": float(
                            right.preferred_cvss.base_score
                            - left.preferred_cvss.base_score
                        )
                        if comparable
                        else None,
                    }
                )
            intervals.append(
                {
                    "earlier_run_id": previous.run_id,
                    "later_run_id": capture.run_id,
                    "interval_start": previous.finished_at.isoformat(),
                    "interval_end": capture.finished_at.isoformat(),
                    "elapsed_days": (
                        _day(capture.finished_at) - _day(previous.finished_at)
                    ).days,
                    "matched": len(common),
                    "earlier_only": len(set(before) - common),
                    "later_only": len(set(current) - common),
                    "comparable": sum(p["comparable"] for p in interval_pairs),
                    "severity_changed": sum(
                        p["severity_changed"] is True for p in interval_pairs
                    ),
                    "score_changed": sum(
                        p["score_change"] not in (None, 0) for p in interval_pairs
                    ),
                    "noncomparable": sum(not p["comparable"] for p in interval_pairs),
                    "modified_at_regressed": sum(
                        p["modified_at_regressed"] for p in interval_pairs
                    ),
                    "kind_counts": dict(
                        sorted(Counter(p["kind"] for p in interval_pairs).items())
                    ),
                }
            )
            pairs.extend(interval_pairs)
        previous = capture
    return {"captures": coverage, "intervals": intervals, "pairs": pairs}


def epss_trends(dataset, start, end):
    observations = defaultdict(dict)
    for record in dataset.epss_observations:
        if start <= record.score_date <= end:
            observations[record.score_date][record.cve_id] = record
    checkpoints = defaultdict(list)
    runs = {r.id: r for r in dataset.runs}
    for step in dataset.steps:
        if step.source == "epss":
            checkpoints[runs[step.run_id].run_date].append(step)
    recorded_dates = sorted(observations)
    panel = set(dataset.cohort) if recorded_dates else set()
    for day in recorded_dates:
        panel.intersection_update(observations[day])
    coverage, gaps, series, intervals, changes = [], [], [], [], []
    gap_start = None
    for offset in range((end - start).days + 1):
        day = start + timedelta(days=offset)
        scores = observations.get(day, {})
        summary = describe(r.epss for r in scores.values())
        coverage.append(
            {
                "score_date": day.isoformat(),
                "cohort_cves": len(dataset.cohort),
                "observed": len(scores),
                "missing": len(dataset.cohort) - len(scores),
                "coverage_fraction": len(scores) / len(dataset.cohort)
                if dataset.cohort
                else None,
                "completed_daily_steps": len(checkpoints[day]),
                "checkpoint_missing_cves": len(
                    {c for s in checkpoints[day] for c in s.missing_cves}
                ),
                "median_epss": summary["median"],
                "p25_epss": summary["p25"],
                "p75_epss": summary["p75"],
                "panel_median_epss": describe(scores[c].epss for c in sorted(panel))[
                    "median"
                ]
                if scores
                else None,
            }
        )
        if not scores and gap_start is None:
            gap_start = day
        if gap_start is not None and (scores or day == end):
            gap_end = day - timedelta(days=1) if scores else day
            gaps.append(
                {
                    "start_date": gap_start.isoformat(),
                    "end_date": gap_end.isoformat(),
                    "days": (gap_end - gap_start).days + 1,
                }
            )
            gap_start = None
    for cve in sorted(dataset.cohort):
        days = [d for d in recorded_dates if cve in observations[d]]
        # Excludes leading/trailing gaps, reported separately from full-window coverage.
        span = (days[-1] - days[0]).days + 1 if days else 0
        series.append(
            {
                "cve_id": cve,
                "observed_dates": len(days),
                "first_date": days[0].isoformat() if days else None,
                "last_date": days[-1].isoformat() if days else None,
                "missing_calendar_dates": (end - start).days + 1 - len(days),
                "internal_gap_days": span - len(days),
                "in_balanced_panel": cve in panel,
            }
        )
    for earlier, later in zip(recorded_dates, recorded_dates[1:], strict=False):
        before, after = observations[earlier], observations[later]
        matched = set(before) & set(after)
        deltas = []
        for cve in sorted(matched):
            delta = float((after[cve].epss - before[cve].epss) * 100)
            deltas.append(delta)
            changes.append(
                {
                    "cve_id": cve,
                    "earlier_date": earlier.isoformat(),
                    "later_date": later.isoformat(),
                    "change_pp": delta,
                    "earlier_epss": float(before[cve].epss),
                    "later_epss": float(after[cve].epss),
                }
            )
        intervals.append(
            {
                "earlier_date": earlier.isoformat(),
                "later_date": later.isoformat(),
                "elapsed_days": (later - earlier).days,
                "unobserved_days_between": (later - earlier).days - 1,
                "matched": len(matched),
                "earlier_only": len(set(before) - matched),
                "later_only": len(set(after) - matched),
                "neither": len(dataset.cohort) - len(set(before) | set(after)),
                "increased": sum(d > 0 for d in deltas),
                "decreased": sum(d < 0 for d in deltas),
                "unchanged": sum(d == 0 for d in deltas),
                **{f"change_pp_{k}": v for k, v in describe(deltas).items()},
            }
        )
    return {
        "coverage": coverage,
        "gaps": gaps,
        "series": series,
        "intervals": intervals,
        "changes": changes,
        "recorded_dates": len(recorded_dates),
        "balanced_panel_cves": len(panel),
        "balanced_panel_dates": [d.isoformat() for d in recorded_dates],
    }


def analyze(dataset, start_date=None, end_date=None):
    dates = [_day(s.finished_at) for s in dataset.steps if s.source in ("kev", "nvd")]
    dates.extend(e.score_date for e in dataset.epss_observations)
    runs = {r.id: r for r in dataset.runs}
    dates.extend(runs[s.run_id].run_date for s in dataset.steps if s.source == "epss")
    start = start_date or min(dates, default=_day(dataset.captured_at))
    end = end_date or max(dates, default=_day(dataset.captured_at))
    if end < start or (end - start).days >= 3660:
        raise ValueError("Select an increasing window of at most 3660 calendar days")
    return {
        "analysis_format": 1,
        "label": dataset.label,
        "captured_at": dataset.captured_at.isoformat(),
        "start_date": start.isoformat(),
        "end_date": end.isoformat(),
        "cohort_cves": len(dataset.cohort),
        "kev": kev_trends(dataset, start, end),
        "nvd": nvd_trends(dataset, start, end),
        "epss": epss_trends(dataset, start, end),
    }


def main(argv=None):
    from threatpulse.trend_report import write_report

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, required=True, help="New report directory"
    )
    parser.add_argument("--input", type=Path, help="Replay exported source.json")
    parser.add_argument(
        "--start-date", type=date.fromisoformat, help="Inclusive UTC start"
    )
    parser.add_argument("--end-date", type=date.fromisoformat, help="Inclusive UTC end")
    args = parser.parse_args(argv)
    try:
        if args.input:
            dataset = TrendDataset.model_validate_json(args.input.read_text())
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
        write_report(
            dataset, args.output, start_date=args.start_date, end_date=args.end_date
        )
    except (psycopg.Error, ValueError, OSError) as exc:
        print(
            f"Trend analysis failed ({type(exc).__name__}). Check database setup, "
            "input format, date window, and use a new output directory.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps({"report": str(args.output / "report.html")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
