"""Standalone trend reports and reproducible export artifacts."""

import hashlib
import html
import io
import json
import sys
from datetime import date, datetime
from importlib.metadata import version as package_version
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from matplotlib import rc_context
from matplotlib.ticker import MaxNLocator

from threatpulse.epss import EpssObservation
from threatpulse.exploration import table
from threatpulse.trends import analyze

LIMITATIONS = [
    "The cohort is all CVEs stored at export time, historically populated from KEV. "
    "It is not a representative sample of all vulnerabilities. Comparison studies "
    "are stored separately and are not included. Cohort size is frozen; "
    "older dates may predate some CVEs' publication or enrollment.",
    "KEV additions/removals are set differences between consecutive committed full "
    "catalog captures in the selected window. The first capture is a baseline. "
    "An addition is observed within the capture interval, not at an exact exploitation "
    "time. CISA dateAdded is retained separately. Reappearances are flagged relative "
    "to this window; changes between captures can be missed.",
    "KEV/NVD chronology uses UTC source checkpoint completion times, not nominal "
    "run dates. Retries can capture sources on different days. Committed steps from "
    "failed, interrupted, or running runs remain usable. Per-record fetch timestamps "
    "remain in source.json. No source history is reconstructed before collection.",
    "NVD compares only CVEs present in both adjacent captures. Earlier-only and "
    "later-only records are coverage changes, not severity changes. Missing-request "
    "counts and fetched records are preserved even when stale records did not update "
    "the latest table. Modified-time regressions are flagged and excluded from numeric "
    "changes, not interpreted as severity decreases.",
    "Preferred CVSS selects the newest version, then Primary, then source/vector "
    "order. Numeric and severity comparisons require the same version, source, and "
    "metric type, non-Rejected status, and no modified-time regression. Version/source "
    "changes and metric additions/removals are reported separately. Unselected metrics "
    "may also change; this analysis does not enumerate every CVSS metric revision.",
    "EPSS is a predicted probability of exploitation in the next 30 days, not an "
    "observed exploitation count. Dates are source score dates. Missing scores remain "
    "unknown; no interpolation, carry-forward, or zero substitution is used. An empty "
    "calendar date means no stored scores, not proof that FIRST had no scores. Daily "
    "checkpoint missing lists describe those requests; later manual writes may differ.",
    "Daily EPSS medians and quartiles use available scores and can change with score "
    "coverage. The balanced panel includes only CVEs scored on every nonempty recorded "
    "date in the selected window; it excludes whole-date gaps and may be biased. "
    "Matched interval changes exclude one-sided missingness and retain elapsed days "
    "and empty days between dates. Calendar gaps remain visible in charts.",
    "EPSS rows can be updated for a previously stored CVE/date; frozen source.json "
    "preserves this export, not all revisions. Model changes, selection bias, "
    "vendor/age differences, and collection outages may affect trends. Quantiles use "
    "linear interpolation. Changes are descriptive percentage points, without "
    "significance, causation, forecasting, or a Threat Velocity score.",
    "The report loads stored history in memory and limits its calendar window to "
    "3660 days. Artifacts contain source metadata; connection credentials "
    "and API headers are never included. Exact image bytes require the same locked "
    "dependencies, Python, fonts, and plotting environment.",
]


def charts(dataset, result, output):
    figures = []

    def save(name, fig):
        fig.tight_layout()
        buffer = io.StringIO()
        fig.savefig(buffer, format="svg", metadata={"Date": None})
        svg = buffer.getvalue()
        (output / f"{name}.svg").write_text(svg)
        fig.savefig(output / f"{name}.png", dpi=160)
        figures.append(svg[svg.index("<svg") :])
        plt.close(fig)

    def empty(ax, message):
        ax.text(0.5, 0.5, message, ha="center", va="center", transform=ax.transAxes)

    def counts(ax):
        ax.set_ylim(bottom=0)
        ax.yaxis.set_major_locator(MaxNLocator(integer=True))

    with rc_context({"svg.hashsalt": "threatpulse-trends-v1"}):
        fig, axes = plt.subplots(2, 1, figsize=(10, 6), sharex=True)
        captures = result["kev"]["captures"]
        days = [datetime.fromisoformat(c["captured_at"]) for c in captures]
        axes[0].scatter(days, [c["catalog_cves"] for c in captures], color="#287d8e")
        axes[0].set(title="KEV catalog captures", ylabel="Catalog CVEs")
        if not captures:
            empty(axes[0], "No committed KEV captures")
        for field, color in (("added", "#287d8e"), ("removed", "#ac4d34")):
            axes[1].scatter(
                days[1:], [c[field] for c in captures[1:]], label=field, color=color
            )
        if len(captures) < 2:
            empty(axes[1], "Two captures required; first is a baseline")
        axes[1].set(xlabel="UTC checkpoint completion", ylabel="Observed changes")
        axes[1].legend()
        for ax in axes:
            counts(ax)
        fig.autofmt_xdate()
        save("kev-trends", fig)

        fig, ax = plt.subplots(figsize=(10, 4))
        intervals = result["nvd"]["intervals"]
        days = [datetime.fromisoformat(i["interval_end"]) for i in intervals]
        for field, label, color in (
            ("comparable", "Comparable CVEs", "#777777"),
            ("severity_changed", "Severity label changed", "#ac4d34"),
            ("score_changed", "Base score changed", "#287d8e"),
        ):
            ax.scatter(days, [i[field] for i in intervals], label=label, color=color)
        if not intervals:
            empty(ax, "Two committed NVD captures required")
        ax.set(
            title="NVD changes between adjacent captures",
            xlabel="UTC later checkpoint",
            ylabel="Matched CVEs",
        )
        counts(ax)
        ax.legend()
        fig.autofmt_xdate()
        save("nvd-trends", fig)

        coverage = result["epss"]["coverage"]
        days = [date.fromisoformat(c["score_date"]) for c in coverage]
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.scatter(
            days,
            [c["observed"] for c in coverage],
            label="Stored scores",
            color="#287d8e",
        )
        ax.axhline(
            result["cohort_cves"],
            label="Frozen cohort",
            linestyle="--",
            color="#777777",
        )
        ax.set(
            title="EPSS calendar coverage (empty dates remain visible)",
            xlabel="Source score date",
            ylabel="CVEs",
        )
        counts(ax)
        ax.legend()
        fig.autofmt_xdate()
        save("epss-coverage", fig)

        def percent(value):
            return value * 100 if value is not None else float("nan")

        fig, ax = plt.subplots(figsize=(10, 4))
        ax.plot(
            days,
            [percent(c["median_epss"]) for c in coverage],
            marker=".",
            color="#287d8e",
            label="Available-score median",
        )
        ax.fill_between(
            days,
            [percent(c["p25_epss"]) for c in coverage],
            [percent(c["p75_epss"]) for c in coverage],
            color="#287d8e",
            alpha=0.15,
            label="Available-score quartiles",
        )
        ax.plot(
            days,
            [percent(c["panel_median_epss"]) for c in coverage],
            marker=".",
            color="#ac4d34",
            label=f"Balanced panel (n={result['epss']['balanced_panel_cves']})",
        )
        ax.set(
            title="EPSS probability trends (lines break at missing dates)",
            xlabel="Source score date",
            ylabel="EPSS probability (%)",
            ylim=(0, 100),
        )
        if not result["epss"]["recorded_dates"]:
            empty(ax, "No stored EPSS scores")
        ax.legend()
        fig.autofmt_xdate()
        save("epss-trends", fig)

        # Fixed, deterministic sample; all observations and CVE coverage are exported.
        sample = sorted(
            result["epss"]["series"], key=lambda c: (-c["observed_dates"], c["cve_id"])
        )[:5]
        sample = [c["cve_id"] for c in sample if c["observed_dates"]]
        if sample:
            scores = {
                (e.cve_id, e.score_date): float(e.epss) * 100
                for e in dataset.epss_observations
            }
            fig, ax = plt.subplots(figsize=(10, 4))
            for cve in sample:
                ax.plot(
                    days,
                    [scores.get((cve, d), float("nan")) for d in days],
                    marker=".",
                    label=cve,
                )
            ax.set(
                title="CVE histories: five most observed, ties by CVE ID",
                xlabel="Source score date",
                ylabel="EPSS probability (%)",
                ylim=(0, 100),
            )
            ax.legend(fontsize=8)
            fig.autofmt_xdate()
            save("epss-cve-histories", fig)
    return figures


CSV_FIELDS = {
    "kev-captures": (
        "run_id run_date run_status captured_at catalog_cves previous_run_id "
        "added removed interval_days"
    ),
    "kev-events": (
        "cve_id kind earlier_run_id later_run_id interval_start interval_end "
        "cisa_date_added reappearance vendor product"
    ),
    "nvd-captures": (
        "run_id run_date run_status captured_at observed scored missing_requested "
        "latest_rows_written"
    ),
    "nvd-intervals": (
        "earlier_run_id later_run_id interval_start interval_end elapsed_days "
        "matched earlier_only later_only comparable severity_changed score_changed "
        "noncomparable modified_at_regressed kind_counts"
    ),
    "nvd-pairs": (
        "cve_id earlier_run_id later_run_id interval_start interval_end "
        "earlier_modified_at later_modified_at earlier_status later_status "
        "earlier_metric later_metric kind comparable modified_at_regressed "
        "severity_changed score_change"
    ),
    "epss-coverage": (
        "score_date cohort_cves observed missing coverage_fraction "
        "completed_daily_steps checkpoint_missing_cves median_epss p25_epss "
        "p75_epss panel_median_epss"
    ),
    "epss-gaps": "start_date end_date days",
    "epss-series": (
        "cve_id observed_dates first_date last_date missing_calendar_dates "
        "internal_gap_days in_balanced_panel"
    ),
    "epss-intervals": (
        "earlier_date later_date elapsed_days unobserved_days_between matched "
        "earlier_only later_only neither increased decreased unchanged change_pp_n "
        "change_pp_min change_pp_p25 change_pp_median change_pp_p75 "
        "change_pp_max change_pp_mean"
    ),
    "epss-changes": "cve_id earlier_date later_date change_pp earlier_epss later_epss",
}


def findings(result):
    kev, nvd, epss = (result[k] for k in ("kev", "nvd", "epss"))
    additions = sum(e["kind"] == "added" for e in kev["events"])
    removals = sum(e["kind"] == "removed" for e in kev["events"])
    return [
        f"Window: {result['start_date']} through {result['end_date']} (inclusive); "
        f"frozen cohort: {result['cohort_cves']} stored CVEs.",
        f"KEV: {len(kev['captures'])} committed captures. "
        + (
            f"{additions} observed additions and {removals} removals across adjacent "
            "captures, counting repeated appearances."
            if len(kev["captures"]) >= 2
            else "Insufficient captures to establish changes."
        ),
        f"NVD: {len(nvd['captures'])} committed captures and {len(nvd['intervals'])} "
        f"adjacent intervals; {sum(i['comparable'] for i in nvd['intervals'])} "
        "comparable "
        f"CVE/interval pairs, {sum(i['severity_changed'] for i in nvd['intervals'])} "
        "severity label changes. Counts can include the same CVE in several intervals.",
        f"EPSS: {epss['recorded_dates']} nonempty score dates; "
        f"{sum(g['days'] for g in epss['gaps'])} calendar dates without stored scores. "
        f"Balanced panel: {epss['balanced_panel_cves']} CVEs scored "
        "on every nonempty date.",
    ]


def write_report(dataset, output: Path, *, start_date=None, end_date=None):
    result = analyze(dataset, start_date, end_date)
    output.mkdir(parents=True, exist_ok=False)
    source = json.dumps(
        dataset.model_dump(mode="json"), sort_keys=True, indent=2, allow_nan=False
    )
    digest = hashlib.sha256(source.encode()).hexdigest()
    result["source_sha256"] = digest
    (output / "source.json").write_text(source)
    (output / "analysis.json").write_text(json.dumps(result, indent=2, allow_nan=False))
    for name, fields in CSV_FIELDS.items():
        group, key = name.split("-", 1)
        rows = [
            {
                k: json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else v
                for k, v in row.items()
            }
            for row in result[group][key]
        ]
        pd.DataFrame(rows, columns=fields.split()).to_csv(
            output / f"{name}.csv", index=False
        )
    # Export every selected EPSS observation; source.json retains the full history.
    rows = [
        {
            k: json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else v
            for k, v in e.model_dump(mode="json").items()
        }
        for e in dataset.epss_observations
        if result["start_date"] <= e.score_date.isoformat() <= result["end_date"]
    ]
    pd.DataFrame(rows, columns=list(EpssObservation.model_fields)).to_csv(
        output / "epss-observations.csv", index=False
    )
    figures = charts(dataset, result, output)
    sections = "".join(
        f"<h2>{html.escape(name)}</h2>"
        + table(result[group][key][:20] if key == "events" else result[group][key])
        for name, group, key in (
            ("KEV captures", "kev", "captures"),
            ("KEV events (first 20; complete CSV available)", "kev", "events"),
            ("NVD capture coverage", "nvd", "captures"),
            ("NVD interval coverage and changes", "nvd", "intervals"),
            ("EPSS dates without stored scores", "epss", "gaps"),
            ("EPSS matched interval changes (percentage points)", "epss", "intervals"),
        )
    )
    document = f"""<!doctype html><html lang="en"><meta charset="utf-8">
<title>ThreatPulse vulnerability trends</title>
<style>body{{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;
color:#203340}}table{{border-collapse:collapse;font-size:14px;display:block;
overflow-x:auto}}
th,td{{padding:8px;border:1px solid #cbd5dc;text-align:left}}
svg{{width:100%;height:auto}}
code{{overflow-wrap:anywhere}}p{{line-height:1.6}}</style>
<h1>ThreatPulse vulnerability trends</h1>
<p>{html.escape(dataset.label)} · exported {html.escape(result["captured_at"])}</p>
<h2>Findings</h2>{"".join("<p>" + html.escape(s) + "</p>" for s in findings(result))}
<h2>Figures</h2>{"".join(figures)}{sections}
<h2>Methods and limitations</h2>
{"".join("<p>" + html.escape(s) + "</p>" for s in LIMITATIONS)}
<h2>Reproduce</h2><p>Source SHA-256: <code>{digest}</code>. Replay source.json using
the same date window and locked dependencies. Full capture, event, pair, coverage,
gap, observation, and change tables are in the CSV files; SVG/PNG charts can be
shared separately. This document requires no network access.</p></html>"""
    (output / "report.html").write_text(document)
    manifest = {
        "analysis_format": 1,
        "python": sys.version.split()[0],
        "selected_dates": {k: result[k] for k in ("start_date", "end_date")},
        "packages": {
            name: package_version(name)
            for name in (
                "threatpulse",
                "pandas",
                "numpy",
                "matplotlib",
                "pydantic",
                "psycopg",
                "cvss",
            )
        },
        "code_sha256": {
            name: hashlib.sha256(
                Path(__file__).with_name(name).read_bytes()
            ).hexdigest()
            for name in ("trends.py", "trend_report.py", "exploration.py", "nvd.py")
        },
        "files_sha256": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.iterdir())
            if p.is_file()
        },
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return result
