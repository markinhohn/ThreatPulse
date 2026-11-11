"""Frozen longitudinal exports with offline integrity and coverage verification."""

import base64
import csv
import hashlib
import html
import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, date, datetime, timedelta
from importlib.metadata import version
from pathlib import Path
from uuid import UUID

from threatpulse.epss import EpssBatch
from threatpulse.kev import KevCatalog
from threatpulse.models import parse_cisa_kev_record
from threatpulse.nvd import NvdBatch
from threatpulse.tracking import (
    STAGES,
    EnrollmentDefinition,
    canonical,
    digest,
    enrollment_reasons,
    rows,
    validate_batch,
)

TABLES = {
    "cohorts": ("tracking_cohorts", ("cohort_id",)),
    "registry": ("tracking_registry", ("cve_id",)),
    "runs": ("tracking_runs", ("run_id",)),
    "attempts": ("tracking_attempts", ("attempt_id",)),
    "requests": ("tracking_requests", ("request_id",)),
    "responses": ("tracking_responses", ("request_id",)),
    "observations": ("tracking_observations", ("observation_id",)),
    "checkpoints": ("tracking_checkpoints", ("run_id", "stage")),
    "run_members": ("tracking_run_members", ("run_id", "cve_id")),
    "memberships": ("tracking_memberships", ("cohort_id", "cve_id")),
}


def serializable(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    raise TypeError("Unsupported export value")


def timestamp(value):
    result = datetime.fromisoformat(value)
    if result.utcoffset() is None:
        raise ValueError("Tracking timestamps require a timezone")
    return result.astimezone(UTC)


def read_dataset(connection):
    """Caller supplies a REPEATABLE READ, READ ONLY transaction."""
    tables = {}
    for name, (table, keys) in TABLES.items():
        tables[name] = rows(
            connection, f"SELECT * FROM {table} ORDER BY {','.join(keys)}"
        )
    payload = {
        "dataset_kind": "longitudinal_tracking",
        "schema_version": 1,
        "captured_at": connection.execute("SELECT clock_timestamp()").fetchone()[0],
        "tables": tables,
    }
    return json.loads(json.dumps(payload, default=serializable, allow_nan=False))


def validate_dataset(payload):
    if (
        not isinstance(payload, dict)
        or payload.get("dataset_kind") != "longitudinal_tracking"
        or payload.get("schema_version") != 1
        or not isinstance(payload.get("tables"), dict)
        or set(payload["tables"]) != set(TABLES)
    ):
        raise ValueError("Expected a complete longitudinal tracking export")
    cutoff = timestamp(payload["captured_at"])
    tables = payload["tables"]
    for name, (_, keys) in TABLES.items():
        items = tables[name]
        if not isinstance(items, list) or any(not isinstance(r, dict) for r in items):
            raise ValueError("Invalid export table")
        identities = [tuple(r[k] for k in keys) for r in items]
        if len(identities) != len(set(identities)):
            raise ValueError("Duplicate export identity")
        for item in items:
            for field in (
                "created_at",
                "first_seen_at",
                "started_at",
                "finished_at",
                "received_at",
                "captured_at",
                "available_at",
                "baseline_at",
            ):
                if item.get(field) and timestamp(item[field]) > cutoff:
                    raise ValueError("Export contains post-export timestamps")
    cohorts = {r["cohort_id"]: r for r in tables["cohorts"]}
    registry = {r["cve_id"] for r in tables["registry"]}
    runs = {r["run_id"]: r for r in tables["runs"]}
    attempts = {r["attempt_id"]: r for r in tables["attempts"]}
    requests = {r["request_id"]: r for r in tables["requests"]}
    observations = {r["observation_id"]: r for r in tables["observations"]}
    checks = {(r["run_id"], r["stage"]): r for r in tables["checkpoints"]}
    by_attempt = defaultdict(list)
    for cohort in cohorts.values():
        definition = EnrollmentDefinition.model_validate(cohort["definition"])
        if digest(definition.model_dump(mode="json")) != cohort["definition_sha256"]:
            raise ValueError("Cohort definition checksum mismatch")
    for run in runs.values():
        if run["kind"] not in ("daily", "enrollment") or (
            run["kind"] == "enrollment" and run["cohort_id"] not in cohorts
        ):
            raise ValueError("Unknown run/cohort")
    for attempt in attempts.values():
        if attempt["run_id"] not in runs:
            raise ValueError("Unknown attempt run")
        if attempt["finished_at"] and timestamp(attempt["finished_at"]) < timestamp(
            attempt["started_at"]
        ):
            raise ValueError("Invalid attempt chronology")
    for request in requests.values():
        if request["attempt_id"] not in attempts:
            raise ValueError("Unknown request attempt")
        if timestamp(request["started_at"]) < timestamp(
            attempts[request["attempt_id"]]["started_at"]
        ):
            raise ValueError("Request precedes attempt")
    for response in tables["responses"]:
        request = requests.get(response["request_id"])
        if request is None or timestamp(response["received_at"]) < timestamp(
            request["started_at"]
        ):
            raise ValueError("Invalid response provenance")
        if (200 <= response["status_code"] < 300) != (
            response["body_base64"] is not None
        ):
            raise ValueError("Successful response bytes are missing")
        if response["body_base64"] is not None:
            body = base64.b64decode(response["body_base64"], validate=True)
            if hashlib.sha256(body).hexdigest() != response["body_sha256"]:
                raise ValueError("Raw HTTP response checksum mismatch")
    for item in observations.values():
        if item["attempt_id"] not in attempts or item["cve_id"] not in registry:
            raise ValueError("Unknown observation provenance")
        if timestamp(item["captured_at"]) > timestamp(item["available_at"]):
            raise ValueError("Availability precedes capture")
        if item["state"] == "observed":
            data = item["observation"]
            normalized = data["kev"] if item["source"] == "kev" else data
            if (
                normalized["cve_id"] != item["cve_id"]
                or timestamp(normalized["ingested_at"])
                != timestamp(item["captured_at"])
                or normalized["source_url"] != item["source_url"]
            ):
                raise ValueError("Observation wrapper does not match its source")
            raw = (
                data["kev"]["raw_record"]
                if item["source"] == "kev"
                else data["raw_record"]
            )
            if (
                digest(data) != item["observation_sha256"]
                or digest(raw) != item["raw_sha256"]
            ):
                raise ValueError("Source observation checksum mismatch")
        elif item["state"] != "missing" or any(
            item[k] is not None
            for k in ("observation", "observation_sha256", "raw_sha256")
        ):
            raise ValueError("Missing source is not an observed zero")
        by_attempt[item["attempt_id"]].append(item)
    completed_attempts = set()
    for step in checks.values():
        attempt = attempts.get(step["attempt_id"])
        if (
            attempt is None
            or attempt["status"] != "succeeded"
            or attempt["run_id"] != step["run_id"]
            or attempt["stage"] != step["stage"]
        ):
            raise ValueError("Invalid source checkpoint")
        completed_attempts.add(step["attempt_id"])
        if step["stage"] == "plan":
            continue
        source = {
            "census": "nvd",
            "discovery": "kev",
            "final_kev": "kev",
            "epss": "epss",
            "nvd": "nvd",
        }[step["stage"]]
        found = by_attempt[step["attempt_id"]]
        if any(
            r["source"] != source or r["available_at"] != step["available_at"]
            for r in found
        ):
            raise ValueError("Observation/checkpoint mismatch")
        data = {
            "observations" if source == "epss" else "records": [
                r["observation"] for r in found if r["state"] == "observed"
            ]
        }
        if source != "kev":
            data["missing_cves"] = [
                r["cve_id"] for r in found if r["state"] == "missing"
            ]
        batch = {"kev": KevCatalog, "nvd": NvdBatch, "epss": EpssBatch}[
            source
        ].model_validate(data)
        run = runs[step["run_id"]]
        definition = (
            EnrollmentDefinition.model_validate(cohorts[run["cohort_id"]]["definition"])
            if step["stage"] == "census"
            else None
        )
        entries, missing = validate_batch(
            batch,
            source,
            None if source == "kev" or definition else attempt["requested_ids"],
            timestamp(attempt["started_at"]),
            timestamp(step["available_at"]),
            definition,
        )
        if step["metadata"]["observed"] != len(entries) or step["metadata"][
            "missing"
        ] != len(missing):
            raise ValueError("Checkpoint coverage counts disagree")
    if any(a not in completed_attempts for a in by_attempt):
        raise ValueError("Observations without an atomic successful checkpoint")
    for member in tables["run_members"]:
        if member["run_id"] not in runs or member["cve_id"] not in registry:
            raise ValueError("Unknown run member")
    for member in tables["memberships"]:
        census = observations.get(member["census_observation_id"])
        baseline = attempts.get(member["baseline_attempt_id"])
        if (
            member["cohort_id"] not in cohorts
            or member["cve_id"] not in registry
            or census is None
            or census["cve_id"] != member["cve_id"]
            or baseline is None
            or baseline["stage"] != "final_kev"
            or member["baseline_at"]
            != checks[(baseline["run_id"], "final_kev")]["available_at"]
        ):
            raise ValueError("Invalid enrollment provenance")
        for stage in ("census", "epss", "nvd"):
            if timestamp(
                checks[(baseline["run_id"], stage)]["available_at"]
            ) > timestamp(member["baseline_at"]):
                raise ValueError("Feature source follows the baseline boundary")
        final = checks[(baseline["run_id"], "final_kev")]
        present = {r["cve_id"] for r in by_attempt[baseline["attempt_id"]]}
        known = present | set(final["metadata"]["historical_kev_ids"])
        expected = enrollment_reasons(
            census["observation"], member["cve_id"], present, known
        )
        if member["exclusion_reasons"] != expected or member["eligibility"] != (
            "excluded" if expected else "eligible"
        ):
            raise ValueError("Enrollment eligibility does not match frozen evidence")
        run = runs[baseline["run_id"]]
        if run["kind"] != "enrollment" or run["cohort_id"] != member["cohort_id"]:
            raise ValueError("Enrollment belongs to another cohort")
    for run in runs.values():
        if run["status"] == "succeeded":
            required = STAGES + (("census",) if run["kind"] == "enrollment" else ())
            if any((run["run_id"], stage) not in checks for stage in required):
                raise ValueError("Successful run lacks a source checkpoint")
            if run["kind"] == "enrollment":
                census_ids = {
                    r["cve_id"]
                    for r in by_attempt[checks[(run["run_id"], "census")]["attempt_id"]]
                }
                member_ids = {
                    m["cve_id"]
                    for m in tables["memberships"]
                    if m["cohort_id"] == run["cohort_id"]
                }
                if census_ids != member_ids:
                    raise ValueError("Completed census lost enrollment members")
    for step in checks.values():
        if step["stage"] != "final_kev":
            continue
        before_fetch = timestamp(attempts[step["attempt_id"]]["started_at"])
        proofs = step["metadata"]["historical_kev_evidence"]
        ids = [p["cve_id"] for p in proofs]
        if (
            len(set(ids)) != len(ids)
            or sorted(ids) != step["metadata"]["historical_kev_ids"]
        ):
            raise ValueError("Historical KEV proof coverage mismatch")
        for proof in proofs:
            if proof["basis"] == "tracking_observation":
                item = observations.get(proof["observation_id"])
                if (
                    item is None
                    or item["cve_id"] != proof["cve_id"]
                    or item["source"] != "kev"
                    or item["state"] != "observed"
                    or timestamp(item["available_at"]) > before_fetch
                ):
                    raise ValueError("Historical KEV observation was not available")
            elif proof["basis"] in (
                "legacy_kev_entry_export",
                "legacy_kev_snapshot_export",
            ):
                _, entry = parse_cisa_kev_record(
                    proof["raw_record"],
                    source_url=proof["source_url"],
                    ingested_at=timestamp(proof["captured_at"]),
                )
                if (
                    entry.cve_id != proof["cve_id"]
                    or digest(proof["raw_record"]) != proof["raw_sha256"]
                    or timestamp(proof["captured_at"])
                    > timestamp(proof["available_at"])
                    or timestamp(proof["available_at"]) > before_fetch
                    or entry.date_added > before_fetch.date()
                ):
                    raise ValueError("Historical KEV export proof is invalid")
            else:
                raise ValueError("Unknown historical KEV provenance basis")
    return payload


def summarize(payload):
    validate_dataset(payload)
    tables = payload["tables"]
    attempts = defaultdict(list)
    checks = {(r["run_id"], r["stage"]): r for r in tables["checkpoints"]}
    for item in tables["attempts"]:
        attempts[(item["run_id"], item["stage"])].append(item)
    coverage = []
    for run in tables["runs"]:
        for stage in (("census",) if run["kind"] == "enrollment" else ()) + STAGES:
            history = sorted(
                attempts[(run["run_id"], stage)],
                key=lambda a: (a["started_at"], a["attempt_id"]),
            )
            step = checks.get((run["run_id"], stage))
            latest = history[-1] if history else None
            coverage.append(
                {
                    "run_id": run["run_id"],
                    "run_date": run["run_date"],
                    "kind": run["kind"],
                    "stage": stage,
                    "state": "succeeded"
                    if step
                    else latest["status"]
                    if latest
                    else "not_attempted",
                    "attempts": len(history),
                    "requested": len(latest["requested_ids"])
                    if latest and stage in ("plan", "epss", "nvd")
                    else None,
                    "observed": step["metadata"].get("observed") if step else None,
                    "missing": step["metadata"].get("missing") if step else None,
                    "available_at": step["available_at"] if step else None,
                }
            )
    cohorts = []
    for cohort in tables["cohorts"]:
        members = [
            m for m in tables["memberships"] if m["cohort_id"] == cohort["cohort_id"]
        ]
        cohorts.append(
            {
                "cohort_id": cohort["cohort_id"],
                "label": cohort["label"],
                **cohort["definition"],
                "enrolled": len(members),
                "enrollment_status": next(
                    r["status"]
                    for r in tables["runs"]
                    if r["cohort_id"] == cohort["cohort_id"]
                ),
                "eligible": sum(m["eligibility"] == "eligible" for m in members),
                "excluded": sum(m["eligibility"] == "excluded" for m in members),
                "exclusion_reasons": dict(
                    sorted(
                        Counter(
                            r for m in members for r in m["exclusion_reasons"]
                        ).items()
                    )
                ),
            }
        )
    as_of = timestamp(payload["captured_at"])
    daily_dates = {
        date.fromisoformat(r["run_date"])
        for r in tables["runs"]
        if r["kind"] == "daily"
    }
    start = min(
        (timestamp(c["created_at"]).date() for c in tables["cohorts"]),
        default=as_of.date(),
    )
    absent_days = []
    while start < as_of.date():
        if start not in daily_dates:
            absent_days.append(start.isoformat())
        start += timedelta(days=1)
    captures = sorted(
        timestamp(s["available_at"])
        for s in tables["checkpoints"]
        if s["stage"] in ("discovery", "final_kev")
    )
    return {
        "analysis_kind": "longitudinal_tracking",
        "analysis_format": 1,
        "captured_at": payload["captured_at"],
        "registry_cves": len(tables["registry"]),
        "runs": tables["runs"],
        "run_status_counts": dict(
            sorted(Counter(r["status"] for r in tables["runs"]).items())
        ),
        "attempt_status_counts": dict(
            sorted(Counter(r["status"] for r in tables["attempts"]).items())
        ),
        "registry_origins": dict(
            sorted(Counter(r["origin"] for r in tables["registry"]).items())
        ),
        "cohorts": cohorts,
        "source_coverage": coverage,
        "daily_dates_without_run": absent_days,
        "today_has_daily_run": as_of.date() in daily_dates,
        "catalog_gaps_over_48h": [
            {
                "start": a.isoformat(),
                "end": b.isoformat(),
                "hours": (b - a).total_seconds() / 3600,
            }
            for a, b in zip(captures, captures[1:], strict=False)
            if b - a > timedelta(hours=48)
        ],
        "latest_catalog_age_hours": (as_of - captures[-1]).total_seconds() / 3600
        if captures
        else None,
        "unanswered_requests": len(tables["requests"]) - len(tables["responses"]),
        "labels_generated": False,
    }


def write_report(payload, output: Path):
    # Normalize table order so a frozen export has byte-identical offline replay.
    payload = json.loads(canonical(payload))
    validate_dataset(payload)
    for name, (_, keys) in TABLES.items():
        payload["tables"][name].sort(key=lambda r: tuple(r[k] for k in keys))
    result = summarize(payload)
    source = json.dumps(payload, sort_keys=True, indent=2) + "\n"
    result["source_sha256"] = hashlib.sha256(source.encode()).hexdigest()
    output.mkdir(parents=True, exist_ok=False)
    (output / "source.json").write_text(source, encoding="utf-8")
    (output / "analysis.json").write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    fields = (
        "run_id",
        "run_date",
        "kind",
        "stage",
        "state",
        "attempts",
        "requested",
        "observed",
        "missing",
        "available_at",
    )
    with (output / "coverage.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(result["source_coverage"])
    content = html.escape(
        json.dumps(
            {k: v for k, v in result.items() if k != "source_coverage"}, indent=2
        )
    )
    (output / "report.html").write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        "<title>ThreatPulse longitudinal coverage</title>"
        "<h1>Longitudinal cohort coverage</h1>"
        '<p><a href="coverage.csv">Source coverage CSV</a> · '
        '<a href="source.json">Frozen source and request history</a> · '
        '<a href="analysis.json">Analysis JSON</a></p><pre>' + content + "</pre>"
        "<p>A defined publication census is not a random sample. Missing, failed, "
        "and unattempted sources remain distinct. Nominal run dates do not "
        "reconstruct historical availability. Catalog inclusion is a listing "
        "proxy, not observed exploitation timing. No features, labels, or fitted "
        "models are generated. Initial eligibility is fixed; later KEV inclusion "
        "does not remove the CVE. Preserve at least 32 days of prospective "
        "follow-up. Calendar and catalog-gap summaries are coverage diagnostics, "
        "not a completed censoring/label algorithm. Legacy dashboard data is "
        "separate. Headers and error response bodies are excluded; successful "
        "public response bytes and normalized record hashes support offline replay. "
        "Database administrators can disable immutability triggers.</p></html>",
        encoding="utf-8",
    )
    package_root = Path(__file__).parent
    manifest = {
        "python": sys.version.split()[0],
        "packages": {
            name: version(name)
            for name in ("threatpulse", "httpx", "psycopg", "pydantic", "cvss")
        },
        "code_sha256": {
            name: hashlib.sha256((package_root / name).read_bytes()).hexdigest()
            for name in (
                "tracking.py",
                "tracking_report.py",
                "nvd.py",
                "epss.py",
                "kev.py",
                "models.py",
                "daily.py",
                "storage.py",
                "migrations/006_longitudinal.sql",
            )
        },
        "files_sha256": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.iterdir())
        },
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return {
        "report": str(output / "report.html"),
        "registry_cves": result["registry_cves"],
    }
