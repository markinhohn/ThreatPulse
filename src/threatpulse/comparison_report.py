"""Reproducible descriptive distributions for a frozen comparison study."""

import hashlib
import html
import io
import json
import sys
from collections import Counter
from decimal import Decimal
from importlib.metadata import version as package_version
from pathlib import Path

from threatpulse.comparison import ComparisonStudy, classify
from threatpulse.exploration import CVSS_VERSIONS, describe, plt, table

GROUPS = ("kev", "non_kev")
GROUP_LABELS = {"kev": "KEV", "non_kev": "Non-KEV"}


LIMITATIONS = """
This is a census of NVD responses in one user-selected publication window,
not a random sample of all vulnerabilities. Publication time means NVD's
published timestamp, not discovery time or the year in the CVE identifier.
Both groups use the same publication window but are not matched on vendor,
product, exposure, analysis maturity, or exploitation opportunities.
Membership uses the captured current CISA catalog, not today's live membership
and not necessarily membership at the historical EPSS score date. Non-KEV means
absent from that catalog with no positive NVD CISA metadata, not proof of no
exploitation. Positive NVD KEV metadata absent from CISA is excluded as a conflict.
Rejected NVD CVEs are excluded and counted; CVEs awaiting analysis are retained
with unknown scores. Missing CVSS and EPSS are not zero-filled. Score
availability can differ between groups and introduce missing-data bias.
CVSS distributions are separated by preferred version. NVD metrics are the
current fetched metrics, not metrics at the historical score date. EPSS is
predicted exploitation probability over the next 30 days; percentile is not
probability. Both cohorts use one exact EPSS score date.
Distribution percentages use each group's SCORED CVEs as denominator, not its
whole cohort. Coverage counts remain visible. Small or empty groups do not
support reliable generalization. Differences in medians are descriptive only;
no significance, causation, model accuracy, or prioritization claim is made.
The publication-window choice, CISA selection, NVD coverage, and EPSS model
revisions affect results. KEV labels describe known exploitation, so they are
not independent outcomes for validating an exploitation prediction model.
Stable page totals and duplicate checks detect common pagination changes but
cannot guarantee an upstream point-in-time NVD snapshot. Fetch timestamps and
original source records are retained for audit. Collection is bounded in memory;
a cap rejects the whole window instead of silently selecting the first records.
""".strip()


def analyze(study: ComparisonStudy):
    # Revalidate mutable model instances before producing any artifact.
    study = ComparisonStudy.model_validate(study.model_dump(mode="json"))
    kev_ids = set(study.kev_ids)
    epss = {o.cve_id: o for o in study.epss.observations}
    rows = []
    for record in study.nvd_records:
        metric = record.preferred_cvss
        observation = epss.get(record.cve_id)
        rows.append(
            {
                "cve_id": record.cve_id,
                "group": classify(record, kev_ids),
                "published_at": record.published_at.isoformat(),
                "nvd_modified_at": record.modified_at.isoformat(),
                "nvd_ingested_at": record.ingested_at.isoformat(),
                "nvd_status": record.status,
                "cvss_version": metric.version if metric else None,
                "base_score": str(metric.base_score) if metric else None,
                "epss": str(observation.epss) if observation else None,
                "percentile": str(observation.percentile) if observation else None,
            }
        )
    counts = Counter(r["group"] for r in rows)
    coverage, summaries, distributions = [], [], []
    for group in GROUPS:
        cohort = [r for r in rows if r["group"] == group]
        cvss_count = sum(r["base_score"] is not None for r in cohort)
        epss_values = [r["epss"] for r in cohort if r["epss"] is not None]
        coverage.append(
            {
                "group": group,
                "cves": len(cohort),
                "cvss_scored": cvss_count,
                "missing_cvss": len(cohort) - cvss_count,
                "epss_scored": len(epss_values),
                "missing_epss": len(cohort) - len(epss_values),
                "complete_pairs": sum(
                    r["base_score"] is not None and r["epss"] is not None
                    for r in cohort
                ),
            }
        )
        for metric, version, values, width in [
            ("epss", None, epss_values, Decimal("0.1")),
            *[
                (
                    "cvss",
                    version,
                    [r["base_score"] for r in cohort if r["cvss_version"] == version],
                    Decimal(1),
                )
                for version in CVSS_VERSIONS
            ],
        ]:
            summaries.append(
                {
                    "group": group,
                    "metric": metric,
                    "cvss_version": version,
                    **describe(values),
                }
            )
            bins = Counter(min(int(Decimal(value) / width), 9) for value in values)
            for index in range(10):
                distributions.append(
                    {
                        "group": group,
                        "metric": metric,
                        "cvss_version": version,
                        "bin_lower": float(index * width),
                        "bin_upper": float((index + 1) * width),
                        "count": bins[index],
                        "n_scored": len(values),
                        "percent_of_scored": (
                            bins[index] / len(values) * 100 if values else None
                        ),
                    }
                )
    differences = []
    for metric, version in [("epss", None), *[("cvss", v) for v in CVSS_VERSIONS]]:
        matched = [
            s
            for s in summaries
            if s["metric"] == metric and s["cvss_version"] == version
        ]
        before, after = matched
        delta = (
            before["median"] - after["median"] if before["n"] and after["n"] else None
        )
        differences.append(
            {
                "metric": metric,
                "cvss_version": version,
                "kev_n": before["n"],
                "non_kev_n": after["n"],
                "kev_median": before["median"],
                "non_kev_median": after["median"],
                "median_difference": (
                    delta * 100 if delta is not None and metric == "epss" else delta
                ),
                "difference_unit": "percentage points"
                if metric == "epss"
                else "CVSS points",
            }
        )
    return {
        "analysis_format": 1,
        "study_id": str(study.study_id),
        "label": study.label,
        "definition": study.definition.model_dump(mode="json"),
        "collected_at": study.collected_at.isoformat(),
        "kev_snapshot_at": study.kev_snapshot_at.isoformat(),
        "kev_source_url": study.kev_source_url,
        "nvd_window_count": len(rows),
        "catalog_count": len(study.kev_ids),
        "exclusions": {
            name: counts[name]
            for name in ("excluded_rejected", "excluded_kev_conflict")
        },
        "coverage": coverage,
        "summaries": summaries,
        "distributions": distributions,
        "median_differences": differences,
        "rows": rows,
    }


def figures(result, output):
    plt.rcParams.update({"svg.hashsalt": "threatpulse-comparison-v1", "font.size": 10})
    embedded = []
    for metric, version in [("epss", None), *[("cvss", v) for v in CVSS_VERSIONS]]:
        data = [
            r
            for r in result["distributions"]
            if r["metric"] == metric and r["cvss_version"] == version
        ]
        if metric == "cvss" and not any(r["n_scored"] for r in data):
            continue
        fig, ax = plt.subplots(figsize=(9, 4.5))
        scale = 100 if metric == "epss" else 1
        width = 3.8 if metric == "epss" else 0.38
        for index, group in enumerate(GROUPS):
            group_data = [r for r in data if r["group"] == group]
            n = group_data[0]["n_scored"]
            if not n:
                # An unavailable distribution is never drawn as ten zero bins.
                ax.plot(
                    [],
                    [],
                    label=f"{GROUP_LABELS[group]}: no scores",
                    color=("#287d8e", "#ac4d34")[index],
                )
                continue
            centers = [
                (r["bin_lower"] + r["bin_upper"]) / 2 * scale + (index - 0.5) * width
                for r in group_data
            ]
            ax.bar(
                centers,
                [r["percent_of_scored"] for r in group_data],
                width=width,
                color=("#287d8e", "#ac4d34")[index],
                label=f"{GROUP_LABELS[group]} (n={n:,} scored)",
            )
        ax.set(
            xlim=(0, 100 if metric == "epss" else 10),
            ylim=(0, 100),
            xlabel="EPSS probability (%)"
            if metric == "epss"
            else f"CVSS {version} base score",
            ylabel="Percentage of scored CVEs in group",
            title=(
                f"EPSS · {result['definition']['score_date']}"
                if metric == "epss"
                else f"Preferred CVSS {version}"
            ),
        )
        ax.legend()
        fig.tight_layout()
        name = "epss-distribution" if metric == "epss" else f"cvss-{version}"
        stream = io.StringIO()
        fig.savefig(stream, format="svg", metadata={"Date": None})
        fig.savefig(output / f"{name}.png", dpi=160)
        plt.close(fig)
        svg = stream.getvalue()
        (output / f"{name}.svg").write_text(svg)
        embedded.append(svg[svg.index("<svg") :])
    return embedded


def write_report(study, output: Path):
    result = analyze(study)
    output.mkdir(parents=True, exist_ok=False)
    source = json.dumps(
        study.model_dump(mode="json"), sort_keys=True, ensure_ascii=False, indent=2
    )
    digest = hashlib.sha256(source.encode()).hexdigest()
    result["source_sha256"] = digest
    (output / "source.json").write_text(source)
    (output / "analysis.json").write_text(json.dumps(result, indent=2, allow_nan=False))
    import pandas as pd

    for filename, records, columns in (
        (
            "cohorts",
            result["rows"],
            [
                "cve_id",
                "group",
                "published_at",
                "nvd_modified_at",
                "nvd_ingested_at",
                "nvd_status",
                "cvss_version",
                "base_score",
                "epss",
                "percentile",
            ],
        ),
        ("coverage", result["coverage"], None),
        ("summaries", result["summaries"], None),
        ("distributions", result["distributions"], None),
        ("median-differences", result["median_differences"], None),
    ):
        pd.DataFrame(records, columns=columns).to_csv(
            output / f"{filename}.csv", index=False
        )
    charts = figures(result, output)
    definition = result["definition"]
    caption = (
        f"NVD publication interval: {definition['published_start']} inclusive "
        f"to {definition['published_end']} exclusive, UTC. "
        f"EPSS date for both groups: {definition['score_date']}."
    )
    text = f"""<!doctype html><html lang="en"><meta charset="utf-8">
<title>ThreatPulse KEV versus non-KEV comparison</title>
<style>body{{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;
color:#203340}}table{{border-collapse:collapse;font-size:14px;display:block;
overflow-x:auto}}th,td{{padding:8px;border:1px solid #cbd5dc;text-align:left}}
svg{{width:100%;height:auto}}p{{line-height:1.6}}code{{overflow-wrap:anywhere}}</style>
<h1>KEV versus non-KEV comparison</h1><p>{html.escape(study.label)}</p>
<p>{html.escape(caption)}</p>
<p>Study {study.study_id} · completed {html.escape(result["collected_at"])}.<br>
CISA membership captured {html.escape(result["kev_snapshot_at"])}.</p>
<h2>Selection and coverage</h2>
<p>{result["nvd_window_count"]:,} NVD CVEs fetched; the full catalog has
{result["catalog_count"]:,} KEV CVEs. Only CVEs in the publication interval
participate. Groups are defined by the frozen CISA snapshot.</p>
{table(result["coverage"])}
<p>Excluded records (retained in cohorts.csv for audit):</p>
{table([result["exclusions"]])}
<h2>Distribution summaries</h2>{table(result["summaries"])}
<p>EPSS summary values are probability fractions (0–1); CVSS values are base
scores (0–10). Missing scores remain unknown and are excluded from summaries.</p>
<h2>Median differences</h2>{table(result["median_differences"])}
<p>Differences are KEV minus non-KEV. EPSS differences are percentage points;
CVSS differences use the same preferred version. Unknown indicates an empty
scored group. These are descriptive differences, not significance tests.</p>
<h2>Score distributions</h2>{"".join(charts)}
<p>Percentages are normalized to scored CVEs within each group. Equal-width bins
include their lower bound, exclude their upper bound, and include the maximum
in the final bin. A group with no scores has no plotted distribution.</p>
<h2>Methods and selection bias</h2>
{"".join("<p>" + html.escape(p) + "</p>" for p in LIMITATIONS.splitlines())}
<h2>Reproduce</h2><p>Source SHA-256: <code>{digest}</code>.<br>
The source.json, analysis.json, CSV tables, standalone SVG/PNG figures, and
manifest.json preserve the frozen study and computed results. Replay with the
same code and locked dependencies; no database or network is needed.</p></html>"""
    (output / "report.html").write_text(text)
    manifest = {
        "analysis_format": 1,
        "python": sys.version.split()[0],
        "study_id": str(study.study_id),
        "definition": definition,
        "packages": {
            name: package_version(name)
            for name in (
                "threatpulse",
                "pandas",
                "numpy",
                "matplotlib",
                "pydantic",
                "psycopg",
            )
        },
        "code_sha256": {
            name: hashlib.sha256(
                Path(__file__).with_name(name).read_bytes()
            ).hexdigest()
            for name in (
                "comparison.py",
                "comparison_report.py",
                "exploration.py",
                "nvd.py",
            )
        },
        "files_sha256": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.iterdir())
            if p.is_file()
        },
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return result
