"""Standalone priority queues and checksum-bound audit/replay artifacts."""

import csv
import hashlib
import html
import json
import sys
from importlib.metadata import version as package_version
from pathlib import Path

from threatpulse.exploration import table
from threatpulse.priority import PriorityDataset, analyze, canonical

REASONS = {
    "REJECTED_RECORD": "NVD rejected this record; no exploitation contradiction.",
    "CONFIRMED_KEV": "CISA has reported exploitation for this CVE.",
    "EPSS_HIGH": "Fresh EPSS probability is at least 10%.",
    "SEVERITY_AND_EPSS": "Fresh HIGH/CRITICAL severity and EPSS of at least 1%.",
    "EPSS_ELEVATED": "Fresh EPSS probability is at least 1%.",
    "HIGH_SEVERITY": "Fresh CVSS severity is HIGH or CRITICAL.",
    "LOWER_SIGNALS_COMPLETE": "Fresh lower scores and complete recent KEV absence.",
    "INSUFFICIENT_EVIDENCE": "Available evidence cannot support a baseline tier.",
    "TREND_RISING": "A quality-gated EPSS rise promotes planned to focused review.",
    "EXPLOITATION_CONFLICT": "Unconfirmed/contradictory exploitation needs review.",
    "SEVERITY_WITH_UNKNOWN_EPSS": "Severe consequences with unknown EPSS need review.",
}

LIMITATIONS = [
    "Tiers express public-intelligence review order, not calibrated risk, "
    "probability of compromise, asset applicability, or remediation deadlines. "
    "Thresholds are provisional and have not been prospectively validated.",
    "Confirmed current/historical CISA evidence has no automatic expiry. "
    "A complete recent catalog establishes observed absence, not proof of no "
    "exploitation. Retained KEV rows do not establish current membership. "
    "Only explicit evidence-bound source corrections withdraw known evidence.",
    "EPSS requires a source date no more than two UTC calendar days old; CVSS "
    "requires a fetch no more than seven days old. Catalog absence requires "
    "a complete capture within 48 hours. Values remain visible when unusable, "
    "with detailed quality classifications. Zero is distinct from unknown.",
    "Preferred CVSS uses the newest version, then Primary, then source/vector. "
    "HIGH/CRITICAL is a categorical policy approximation across versions. "
    "Rejected records' technical metrics cannot support severity rules. "
    "Different valid severity metrics are not exploitation contradictions.",
    "Threat Velocity promotion requires its complete coverage/freshness/model "
    "review contract. Unknown model regimes never authorize promotion; falling "
    "or missing trends do not authorize automatic downgrades.",
    "Downgrades retain the previous effective tier until a reviewer acknowledges "
    "the exact evidence fingerprint, policy, previous decision, and candidate. "
    "Approvals are local operator audit records, not cryptographic identity "
    "authentication. Preserved input/decision checksums detect unintended edits.",
    "Previous decisions and approvals are supplied explicitly as versioned files; "
    "the engine does not write priority state into PostgreSQL. Carry previous "
    "decisions on every scheduled evaluation to retain the downgrade guard. "
    "Missing prior-cohort CVEs remain visible instead of silently disappearing.",
    "Database exports conservatively mark rows available at export completion. "
    "Overwritten latest rows and legacy timestamps cannot reconstruct earlier "
    "versions. Daily KEV captures retain complete catalogs; manual ingestion "
    "provides positive evidence without authoritative current absence.",
    "The database cohort is historically KEV-based; comparison studies are "
    "separate. Selection bias, source delays, missingness, upstream corrections, "
    "and version changes limit conclusions. The report loads history in memory "
    "and previews only the first 20 CVEs per queue; JSON/CSV contain all rows.",
]


def _json(value):
    return json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"


def write_report(dataset: PriorityDataset, output: Path, *, decision_at=None):
    data = dataset.model_dump(mode="json")
    data["cohort"] = sorted(data["cohort"])
    for key, field in (
        ("catalogs", "evidence_id"),
        ("kev_entries", "evidence_id"),
        ("nvd_records", "evidence_id"),
        ("epss_observations", "evidence_id"),
        ("previous_decisions", "cve_id"),
        ("reviews", "review_id"),
        ("kev_withdrawals", "correction_id"),
    ):
        data[key] = sorted(data[key], key=lambda row: row[field])
    for catalog in data["catalogs"]:
        catalog["cve_ids"].sort()
    data["model_registry"]["regimes"].sort(key=lambda r: r["score_date_start"])
    frozen = PriorityDataset.model_validate(data)
    result = analyze(frozen, decision_at)
    output.mkdir(parents=True, exist_ok=False)
    source = _json(frozen.model_dump(mode="json"))
    result["source_sha256"] = hashlib.sha256(source.encode()).hexdigest()
    (output / "source.json").write_text(source, encoding="utf-8")
    (output / "policy.json").write_text(_json(result["policy"]), encoding="utf-8")
    (output / "analysis.json").write_text(_json(result), encoding="utf-8")
    fields = [
        "cve_id",
        "decision_at",
        "candidate_tier",
        "effective_tier",
        "rule_id",
        "needs_review",
        "reason_codes",
        "quality_flags",
        "quality_details",
        "values",
        "trend",
        "decision_id",
        "input_sha256",
        "policy_version",
        "policy_sha256",
        "previous_decision_id",
        "approved_review_id",
        "review_status",
        "review_audit",
    ]
    with (output / "decisions.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in result["decisions"]:
            writer.writerow(
                {
                    k: canonical(v) if isinstance(v, (dict, list)) else v
                    for k, v in row.items()
                }
            )
    summaries = []
    nvd_sources = {e.evidence_id: e for e in frozen.nvd_records}
    # Unknown evidence stays in its own visible queue, preceding lower-signal P4.
    for tier in ("P1", "P2", "P3", "UNDETERMINED", "P4", "OUT_OF_SCOPE"):
        rows = [r for r in result["decisions"] if r["effective_tier"] == tier]
        preview = [
            {
                "CVE": r["cve_id"],
                "Candidate": r["candidate_tier"],
                "Review needed": r["needs_review"],
                "EPSS probability / source date": {
                    key: r["values"]["epss"][key] for key in ("epss", "score_date")
                }
                if r["values"]["epss"]
                else None,
                "Preferred CVSS": r["values"]["cvss"]["metric"],
                "NVD capture": nvd_sources[
                    r["values"]["cvss"]["evidence_id"]
                ].captured_at.isoformat()
                if r["values"]["cvss"]["evidence_id"]
                else None,
                "Reasons": [REASONS[code] for code in r["reason_codes"]],
                "Quality flags": r["quality_flags"],
                "Source quality": r["quality_details"],
            }
            for r in rows[:20]
        ]
        summaries.append(f"<h2>{tier} ({len(rows)} CVEs)</h2>" + table(preview))
    document = f"""<!doctype html><html lang="en"><meta charset="utf-8">
<title>ThreatPulse baseline priorities</title>
<style>body{{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;
color:#203340}}table{{border-collapse:collapse;display:block;overflow-x:auto}}
th,td{{padding:8px;border:1px solid #cbd5dc;text-align:left;font-size:14px}}
p{{line-height:1.6}}code{{overflow-wrap:anywhere}}</style>
<h1>ThreatPulse baseline intelligence review</h1><p>{html.escape(frozen.label)}</p>
<p>Decision: {html.escape(result["decision_at"])};
policy {result["policy"]["policy_version"]}.
{result["cohort_cves"]} CVEs;
{result["needs_review_cves"]} need source/downgrade review.</p>
<p>Each queue previews the first 20 CVEs by identifier; full decisions are exported.</p>
<p>Download <a href="decisions.csv">decisions CSV</a>,
<a href="analysis.json">full analysis</a>, <a href="source.json">frozen sources</a>,
<a href="policy.json">policy</a>, or <a href="manifest.json">checksum manifest</a>.</p>
{"".join(summaries)}<h2>Methods and limitations</h2>
{"".join("<p>" + html.escape(text) + "</p>" for text in LIMITATIONS)}
<h2>Reproduce</h2><p>Replay <code>source.json</code> with the recorded decision time,
same code/policy version and locked environment. <code>analysis.json</code> and
<code>decisions.csv</code> preserve all decisions; <code>policy.json</code> and
<code>manifest.json</code> preserve policy and code/source hashes. Source SHA-256:
<code>{result["source_sha256"]}</code>.
This report requires no network access.</p></html>"""
    (output / "report.html").write_text(document, encoding="utf-8")
    manifest = {
        "analysis_format": 1,
        "decision_at": result["decision_at"],
        "policy_sha256": result["policy_sha256"],
        "python": sys.version.split()[0],
        "packages": {
            name: package_version(name)
            for name in ("threatpulse", "pydantic", "psycopg", "cvss")
        },
        "code_sha256": {
            name: hashlib.sha256(
                Path(__file__).with_name(name).read_bytes()
            ).hexdigest()
            for name in (
                "priority.py",
                "priority_report.py",
                "velocity.py",
                "epss.py",
                "nvd.py",
                "models.py",
                "trends.py",
                "exploration.py",
            )
        },
        "files_sha256": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.iterdir())
            if p.is_file()
        },
    }
    (output / "manifest.json").write_text(_json(manifest), encoding="utf-8")
    return result
