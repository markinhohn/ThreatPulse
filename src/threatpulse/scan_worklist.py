"""Asset findings joined to reproducible CVE intelligence and review actions."""

import argparse
import base64
import csv
import hashlib
import html
import io
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from importlib.metadata import version
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import psycopg
from psycopg.types.json import Jsonb
from pydantic import AwareDatetime, Field, model_validator

from threatpulse.daily import IngestionBusyError, ingestion_lock
from threatpulse.epss import EpssCollectionError, collect_epss
from threatpulse.kev import CISA_KEV_URL, KevCollectionError, collect_kev
from threatpulse.nvd import NvdCollectionError, collect_nvd
from threatpulse.priority import (
    CatalogEvidence,
    EpssEvidence,
    KevEvidence,
    NvdEvidence,
    PriorityDataset,
    analyze,
    attach_previous,
    read_dataset,
)
from threatpulse.scan_import import (
    FORMATS,
    SEVERITIES,
    ScanImportError,
    ScanReport,
    Strict,
    canonical,
    parse_scan,
    sha,
)
from threatpulse.storage import migrate

MAX_ENRICH_CVES = 200
QUEUE_ORDER = {
    name: i
    for i, name in enumerate(
        (
            "P1",
            "P2",
            "UNDETERMINED",
            "SCANNER_REVIEW",
            "P3",
            "P4",
            "OUT_OF_SCOPE",
            "NOT_RANKED",
        )
    )
}


def requested_cves(scan):
    return sorted(
        {
            cve
            for finding in scan.findings
            if finding.status not in ("negative", "informational")
            for cve in finding.cves
        }
    )


def subset(dataset, ids):
    data = dataset.model_dump(mode="json")
    data["cohort"] = sorted(ids)
    for name in (
        "kev_entries",
        "nvd_records",
        "epss_observations",
        "previous_decisions",
        "reviews",
        "kev_withdrawals",
    ):
        data[name] = [r for r in data[name] if r["cve_id"] in ids]
    return PriorityDataset.model_validate(data)


class Assessment(Strict):
    schema_version: int = Field(default=1, ge=1, le=1)
    assessment_id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    decision_at: AwareDatetime
    intelligence: PriorityDataset
    analysis: dict
    source_outcomes: list[dict] = Field(default_factory=list)

    @model_validator(mode="after")
    def integrity(self):
        if analyze(self.intelligence, self.decision_at) != self.analysis:
            raise ValueError("Assessment does not match its frozen intelligence")
        return self


def assess(scan, intelligence=None, *, decision_at=None, previous=None, outcomes=None):
    decision = decision_at or datetime.now(UTC)
    intelligence = (
        subset(intelligence, set(requested_cves(scan)))
        if intelligence
        else PriorityDataset(
            captured_at=decision,
            cohort=requested_cves(scan),
            label="No CVE intelligence loaded",
        )
    )
    if not scan.synthetic and "synthetic" in intelligence.label.casefold():
        raise ValueError("Synthetic intelligence requires a declared synthetic scan")
    if previous:
        if previous.scan_id != scan.scan_id:
            raise ValueError("Previous assessment belongs to another scan")
        intelligence = attach_previous(intelligence, previous.analysis)
    return Assessment(
        scan_id=scan.scan_id,
        decision_at=decision,
        intelligence=intelligence,
        analysis=analyze(intelligence, decision),
        source_outcomes=outcomes or [],
    )


def cached_intelligence(connection, scan):
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        return subset(read_dataset(connection), set(requested_cves(scan)))


def refresh_intelligence(connection, scan, *, max_cves=MAX_ENRICH_CVES):
    """Caller holds ingestion_lock. Only public CVE IDs go to the providers."""
    ids = requested_cves(scan)
    if not 0 < max_cves or len(ids) > max_cves:
        raise ValueError("Scan exceeds the explicit CVE enrichment cap")
    data = cached_intelligence(connection, scan).model_dump(mode="json")
    outcomes = []
    if not ids:
        return PriorityDataset.model_validate(data), outcomes
    for source, collect in (
        ("nvd", lambda: collect_nvd(ids)),
        ("epss", lambda: collect_epss(ids)),
        ("kev", collect_kev),
    ):
        started = datetime.now(UTC)
        try:
            candidate = json.loads(canonical(data))
            batch = collect()
            available = datetime.now(UTC)
            prefix = f"scan-{scan.scan_id}-{source}-{available.isoformat()}"
            if source == "kev":
                if not batch.records or len(
                    {r.kev.cve_id for r in batch.records}
                ) != len(batch.records):
                    raise ValueError("Invalid complete KEV catalog")
                if any(
                    not started <= r.kev.ingested_at <= available
                    or r.kev.date_added > available.date()
                    for r in batch.records
                ):
                    raise ValueError("Invalid KEV capture provenance")
                evidence = CatalogEvidence(
                    evidence_id=prefix,
                    captured_at=available,
                    available_at=available,
                    source_url=CISA_KEV_URL,
                    cve_ids=sorted(r.kev.cve_id for r in batch.records),
                )
                candidate["catalogs"].append(evidence.model_dump(mode="json"))
                for record in batch.records:
                    if record.kev.cve_id in ids:
                        entry = record.kev
                        candidate["kev_entries"].append(
                            KevEvidence(
                                evidence_id=prefix + entry.cve_id,
                                captured_at=entry.ingested_at,
                                available_at=available,
                                source_url=entry.source_url,
                                cve_id=entry.cve_id,
                                entry=entry.model_dump(mode="json"),
                            ).model_dump(mode="json")
                        )
            else:
                entries = batch.records if source == "nvd" else batch.observations
                seen = [r.cve_id for r in entries]
                if (
                    len(set(seen)) != len(seen)
                    or len(set(batch.missing_cves)) != len(batch.missing_cves)
                    or set(seen) & set(batch.missing_cves)
                    or set(seen) | set(batch.missing_cves) != set(ids)
                ):
                    raise ValueError("Invalid source coverage")
                for record in entries:
                    if not started <= record.ingested_at <= available:
                        raise ValueError("Invalid source capture time")
                    if source == "nvd":
                        evidence = NvdEvidence(
                            evidence_id=prefix + record.cve_id,
                            captured_at=record.ingested_at,
                            available_at=available,
                            source_url=record.source_url,
                            cve_id=record.cve_id,
                            record=record.model_dump(mode="json"),
                        )
                        candidate["nvd_records"].append(
                            evidence.model_dump(mode="json")
                        )
                    else:
                        # Same-date revisions replace the selected copy in this new
                        # assessment only; earlier assessments remain immutable.
                        candidate["epss_observations"] = [
                            e
                            for e in candidate["epss_observations"]
                            if (e["cve_id"], e["score_date"])
                            != (record.cve_id, record.score_date.isoformat())
                        ]
                        evidence = EpssEvidence(
                            evidence_id=prefix + record.cve_id,
                            captured_at=record.ingested_at,
                            available_at=available,
                            source_url=record.source_url,
                            cve_id=record.cve_id,
                            score_date=record.score_date.isoformat(),
                            epss=str(record.epss),
                            percentile=str(record.percentile),
                            raw_record=record.raw_record,
                        )
                        candidate["epss_observations"].append(
                            evidence.model_dump(mode="json")
                        )
                outcomes.append(
                    {
                        "source": source,
                        "state": "observed",
                        "observed": len(entries),
                        "missing_cves": batch.missing_cves,
                        "available_at": available.isoformat(),
                    }
                )
                data = candidate
                continue
            outcomes.append(
                {
                    "source": source,
                    "state": "observed",
                    "observed": len(batch.records),
                    "available_at": available.isoformat(),
                }
            )
            data = candidate
        except (
            NvdCollectionError,
            EpssCollectionError,
            KevCollectionError,
            httpx.HTTPError,
            ValueError,
        ) as exc:
            outcomes.append(
                {"source": source, "state": "failed", "error_type": type(exc).__name__}
            )
    data["captured_at"] = datetime.now(UTC).isoformat()
    return PriorityDataset.model_validate(data), outcomes


def scan_age(asset, decision):
    if asset.scanned_at is None:
        return "unknown"
    age = decision - asset.scanned_at
    return (
        "future"
        if age < timedelta(0)
        else "stale"
        if age > timedelta(days=7)
        else "fresh"
    )


def worklist(scan, assessment):
    if assessment.scan_id != scan.scan_id:
        raise ValueError("Assessment/scan mismatch")
    decisions = {r["cve_id"]: r for r in assessment.analysis["decisions"]}
    assets = {a.asset_key: a for a in scan.assets}
    grouped = defaultdict(list)
    negatives = {
        (f.asset_key, cve)
        for f in scan.findings
        if f.status == "negative"
        for cve in f.cves
    }
    for finding in scan.findings:
        for cve in finding.cves or [None]:
            # Informational/negative references remain outside the active CVE queue.
            disposition = (
                finding.status
                if finding.status in ("negative", "informational")
                else "active"
            )
            grouped[
                (
                    finding.asset_key,
                    cve,
                    disposition,
                    None if cve else finding.finding_id,
                )
            ].append(finding)
    result = []
    for (key, cve, disposition, _), findings in grouped.items():
        asset = assets[key]
        decision = decisions.get(cve) if cve and disposition == "active" else None
        tier = (
            decision["effective_tier"]
            if decision
            else "UNDETERMINED"
            if cve and disposition == "active"
            else "NOT_RANKED"
            if disposition != "active" or scan.scanner == "nmap"
            else "SCANNER_REVIEW"
        )
        age = scan_age(asset, assessment.decision_at)
        flags = sorted(
            {f for finding in findings for f in finding.flags}
            | set(decision["quality_flags"] if decision else [])
            | ({"SCAN_TIME_" + age.upper()} if age != "fresh" else set())
        )
        if disposition == "active" and (key, cve) in negatives:
            flags.append("SCANNER_STATUS_CONFLICT")
        evidence = (
            "Scanner-reported CVE"
            if scan.scanner != "nmap" and cve
            else "Scanner finding without a CVE"
            if scan.scanner != "nmap"
            else "Unverified NSE CVE reference"
            if cve
            else "Service inventory"
        )
        if disposition == "negative":
            evidence = "Scanner marked this result negative"
        if tier == "NOT_RANKED":
            action = (
                (
                    "Review the service fingerprint; verify product/version and "
                    "applicability before matching CVEs."
                )
                if not cve and scan.scanner == "nmap"
                else (
                    "Retain as informational/negative evidence; no vulnerability "
                    "remediation is inferred."
                )
            )
        elif not cve:
            action = (
                "Review the scanner finding and its remediation guidance; a "
                "CVE may not apply."
            )
        elif tier == "UNDETERMINED":
            action = "Load/refresh CVE intelligence and verify this asset finding."
        else:
            action = {
                "P1": (
                    "Verify applicability first, then review patch/mitigation "
                    "with the asset owner."
                ),
                "P2": "Verify applicability and perform focused remediation review.",
                "P3": (
                    "Verify applicability and plan review under local "
                    "maintenance policy."
                ),
                "P4": (
                    "Verify applicability and monitor under local maintenance policy."
                ),
                "OUT_OF_SCOPE": (
                    "Review the rejected CVE reference with the scanner evidence."
                ),
            }[tier]
        if cve and scan.scanner == "nmap" and disposition == "active":
            action = "Verify the NSE CVE reference and installed software. " + action
        if age != "fresh":
            action = "Confirm scan time/current asset state. " + action
        if "SCANNER_STATUS_CONFLICT" in flags:
            action = "Resolve conflicting scanner results. " + action
        result.append(
            {
                "asset": asset.address,
                "synthetic": scan.synthetic,
                "intelligence_decision_at": assessment.decision_at.isoformat(),
                "hostnames": asset.hostnames,
                "ports": sorted(
                    {
                        f"{f.protocol or 'unknown'}/{f.port}"
                        for f in findings
                        if f.port is not None
                    }
                ),
                "cve_id": cve,
                "priority": tier,
                "candidate_priority": decision["candidate_tier"] if decision else None,
                "scanner_severity": max(
                    (f.severity for f in findings), key=SEVERITIES.index
                ),
                "credentialed_scan": asset.credentialed,
                "qod_percent": sorted(
                    {
                        float(f.qod_percent)
                        for f in findings
                        if f.qod_percent is not None
                    }
                ),
                "scanner_scores": [
                    {"score": str(f.scanner_score), "version": f.scanner_score_version}
                    for f in findings
                    if f.scanner_score is not None
                ],
                "kev_confirmed": decision["values"]["kev"]["confirmed"]
                if decision
                else None,
                "match_basis": evidence,
                "scan_age": age,
                "scanned_at": asset.scanned_at.isoformat()
                if asset.scanned_at
                else None,
                "rule_ids": sorted({f.rule_id for f in findings}),
                "finding_ids": [f.finding_id for f in findings],
                "titles": sorted({f.title for f in findings}),
                "solutions": sorted({f.solution for f in findings if f.solution}),
                "priority_reasons": decision["reason_codes"] if decision else [],
                "quality_flags": flags,
                "intelligence_quality": decision["quality_details"]
                if decision
                else None,
                "needs_review": disposition == "active" or bool(flags),
                "epss": decision["values"]["epss"]["epss"]
                if decision and decision["values"]["epss"]
                else None,
                "epss_date": decision["values"]["epss"]["score_date"]
                if decision and decision["values"]["epss"]
                else None,
                "cvss": decision["values"]["cvss"]["metric"] if decision else None,
                "next_action": action,
                "owner": "",
            }
        )
    return sorted(
        result,
        key=lambda r: (
            QUEUE_ORDER[r["priority"]],
            -SEVERITIES.index(r["scanner_severity"])
            if r["priority"] == "SCANNER_REVIEW"
            else 0,
            r["cve_id"] or "",
            r["asset"],
            r["finding_ids"][0],
        ),
    )


def spreadsheet_safe(value):
    text = str(value)
    return (
        "'" + text
        if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@"))
        or text.startswith(("\t", "\r", "\n"))
        else text
    )


def csv_bytes(rows):
    output = io.StringIO(newline="")
    fields = (
        list(rows[0])
        if rows
        else ["asset", "cve_id", "priority", "next_action", "owner"]
    )
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                k: spreadsheet_safe(
                    canonical(v)
                    if isinstance(v, (dict, list))
                    else ""
                    if v is None
                    else v
                )
                for k, v in row.items()
            }
        )
    return output.getvalue().encode("utf-8-sig")


def save_scan(connection, scan):
    scan = ScanReport.model_validate(scan.model_dump(mode="json"))
    payload = scan.model_dump(mode="json", exclude={"raw_base64"})
    with connection.transaction():
        connection.execute(
            (
                "INSERT INTO scan_imports VALUES "
                "(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (scan_id) DO "
                "NOTHING"
            ),
            (
                scan.scan_id,
                scan.imported_at,
                scan.scanner,
                scan.format,
                scan.filename,
                scan.raw_sha256,
                base64.b64decode(scan.raw_base64),
                Jsonb(payload),
                sha(payload),
            ),
        )
    return load_scan(connection, scan.scan_id)


def load_scan(connection, scan_id):
    row = connection.execute(
        "SELECT raw_bytes,dataset,dataset_sha256 FROM scan_imports WHERE scan_id=%s",
        (scan_id,),
    ).fetchone()
    if not row or sha(row[1]) != row[2]:
        raise ValueError("Scan not found or checksum mismatch")
    return ScanReport.model_validate(
        row[1] | {"raw_base64": base64.b64encode(row[0]).decode()}
    )


def save_assessment(connection, assessment):
    assessment = Assessment.model_validate(assessment.model_dump(mode="json"))
    data = assessment.model_dump(mode="json")
    connection.execute(
        (
            "INSERT INTO scan_assessments VALUES (%s,%s,%s,%s,%s) ON "
            "CONFLICT (assessment_id) DO NOTHING"
        ),
        (
            assessment.assessment_id,
            assessment.scan_id,
            assessment.decision_at,
            Jsonb(data),
            sha(data),
        ),
    )


def latest_assessment(connection, scan_id):
    row = connection.execute(
        (
            "SELECT dataset,dataset_sha256 FROM scan_assessments WHERE "
            "scan_id=%s ORDER BY decision_at DESC,assessment_id DESC "
            "LIMIT 1"
        ),
        (scan_id,),
    ).fetchone()
    if row is None:
        return None
    if sha(row[0]) != row[1]:
        raise ValueError("Assessment checksum mismatch")
    return Assessment.model_validate(row[0])


def write_report(scan, assessment, output):
    rows = worklist(scan, assessment)
    output.mkdir(parents=True, exist_ok=False)
    for name, payload in (
        ("scan.json", scan.model_dump(mode="json")),
        ("assessment.json", assessment.model_dump(mode="json")),
        ("intelligence.json", assessment.intelligence.model_dump(mode="json")),
        ("worklist.json", rows),
    ):
        (output / name).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    (output / "worklist.csv").write_bytes(csv_bytes(rows))
    (output / f"original.{scan.format}").write_bytes(base64.b64decode(scan.raw_base64))
    rendered = "".join(
        "<tr>"
        + "".join(
            "<td>" + html.escape(str(row[key] or "Unknown")) + "</td>"
            for key in ("asset", "cve_id", "priority", "match_basis", "next_action")
        )
        + "</tr>"
        for row in rows[:100]
    )
    (output / "report.html").write_text(
        (
            '<!doctype html><html lang="en"><meta '
            'charset="utf-8"><title>ThreatPulse scan '
            "review</title><h1>Scan review worklist</h1><p>"
        )
        + html.escape(scan.filename)
        + (" — SYNTHETIC DEMO" if scan.synthetic else "")
        + "</p><p>Intelligence decision: "
        + html.escape(assessment.decision_at.isoformat())
        + (
            ". CVE intelligence tiers and asset applicability are "
            "separate. Verify reported findings before remediation. Scan "
            "freshness uses a provisional seven-day review threshold. No "
            "exploit execution or automatic remediation occurs.</p><p><a "
            'href="worklist.csv">Complete worklist CSV</a> · <a '
            'href="scan.json">Scan evidence</a> · <a '
            'href="assessment.json">Assessment</a></p><table><tr><th>Asse'
            "t</th><th>CVE</th><th>Priority</th><th>Evidence "
            "basis</th><th>Next action</th></tr>"
        )
        + rendered
        + (
            "</table><p>First 100 rows shown; JSON/CSV contain all "
            "items. Missing intelligence is unknown. Service "
            "fingerprints alone do not establish CVE applicability. "
            "Negative/informational findings are retained without an "
            "active CVE rank. Ownership is assigned in the exported "
            "worklist. A different import starts a new baseline; absence "
            "from a later scan does not prove resolution.</p></html>"
        ),
        encoding="utf-8",
    )
    root = Path(__file__).parent
    manifest = {
        "source_sha256": scan.raw_sha256,
        "python": sys.version.split()[0],
        "packages": {
            name: version(name)
            for name in ("threatpulse", "pydantic", "defusedxml", "cvss")
        },
        "code_sha256": {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in (
                "scan_import.py",
                "scan_worklist.py",
                "priority.py",
                "velocity.py",
                "nvd.py",
                "epss.py",
                "kev.py",
                "models.py",
                "migrations/007_scans.sql",
            )
        },
        "files_sha256": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.iterdir())
        },
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "report": str(output / "report.html"),
        "assets": len(scan.assets),
        "work_items": len(rows),
        "queues": dict(Counter(r["priority"] for r in rows)),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    imp = commands.add_parser("import")
    imp.add_argument("--scanner", choices=FORMATS, required=True)
    imp.add_argument("--format", choices=("xml", "csv"), required=True)
    imp.add_argument("--input", type=Path, required=True)
    imp.add_argument("--scanned-at", type=datetime.fromisoformat)
    imp.add_argument("--intelligence", type=Path)
    imp.add_argument("--decision-at", type=datetime.fromisoformat)
    imp.add_argument("--save", action="store_true")
    imp.add_argument("--enrich", action="store_true")
    imp.add_argument("--synthetic", action="store_true")
    imp.add_argument("--max-cves", type=int, default=MAX_ENRICH_CVES)
    replay = commands.add_parser("replay")
    replay.add_argument("--scan", type=Path, required=True)
    replay.add_argument("--assessment", type=Path, required=True)
    for command in (imp, replay):
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.output.exists():
            raise FileExistsError("Use a new output directory")
        if args.command == "replay":
            scan = ScanReport.model_validate_json(args.scan.read_text())
            assessment = Assessment.model_validate_json(args.assessment.read_text())
        else:
            if args.input.stat().st_size > 25 * 1024 * 1024:
                raise ScanImportError("Scan exceeds 25 MiB")
            scan = parse_scan(
                args.input.read_bytes(),
                args.scanner,
                args.format,
                filename=args.input.name,
                scanned_at=args.scanned_at,
                synthetic=args.synthetic,
            )
            intelligence = (
                PriorityDataset.model_validate_json(args.intelligence.read_text())
                if args.intelligence
                else None
            )
            previous = None
            outcomes = []
            if args.save or args.enrich:
                url = os.environ.get("DATABASE_URL")
                if not url:
                    raise ValueError(
                        "DATABASE_URL is required for persistence/live enrichment"
                    )
                with psycopg.connect(url, autocommit=True, connect_timeout=10) as conn:
                    migrate(conn)
                    with ingestion_lock(conn):
                        scan = save_scan(conn, scan)
                        previous = latest_assessment(conn, scan.scan_id)
                        if args.enrich:
                            intelligence, outcomes = refresh_intelligence(
                                conn, scan, max_cves=args.max_cves
                            )
                        elif intelligence is None:
                            intelligence = cached_intelligence(conn, scan)
                        assessment = assess(
                            scan,
                            intelligence,
                            decision_at=args.decision_at,
                            previous=previous,
                            outcomes=outcomes,
                        )
                        save_assessment(conn, assessment)
            else:
                assessment = assess(scan, intelligence, decision_at=args.decision_at)
        print(json.dumps(write_report(scan, assessment, args.output)))
        return 0
    except (ValueError, OSError, psycopg.Error, IngestionBusyError) as exc:
        message = (
            str(exc)
            if isinstance(exc, ScanImportError)
            else (
                "Check input, scanner/format, database, evidence dates, and "
                "output directory."
            )
        )
        print(f"Scan import failed ({type(exc).__name__}): {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
