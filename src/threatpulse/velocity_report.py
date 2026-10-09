"""Standalone Threat Velocity charts, tables, provenance, and replay manifest."""

import csv
import hashlib
import html
import io
import json
import sys
from datetime import date, timedelta
from importlib.metadata import version as package_version
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib import rc_context
from matplotlib.ticker import MaxNLocator

from threatpulse.exploration import table
from threatpulse.velocity import VelocityDataset, analyze

LIMITATIONS = [
    "Threat Velocity is a descriptive EPSS rate in percentage points per calendar "
    "day, not observed attacks, a forecast, or a calibrated risk probability. "
    "Promotion thresholds are provisional policy choices requiring evaluation. "
    "The priority engine will consume this signal later; this report assigns no tiers.",
    "Each CVE uses its own latest available score date and the inclusive trailing "
    "seven-day interval (eight possible calendar dates). At least five dates, a "
    "four-day span, and no adjacent gap above two days are required for a rising "
    "signal. Missing dates remain in coverage; age to decision is separate. "
    "Rates use elapsed "
    "calendar days; there is no interpolation, carry-forward, or zero imputation.",
    "The median of all pairwise slopes is the main rate. Endpoint change and "
    "endpoint-average rate are also exported. Zero scores are valid. Percentiles "
    "are retained as metadata and never substituted for probabilities. Eligibility "
    "uses exact rational arithmetic; exported numbers are rounded display floats.",
    "A rising signal additionally requires a latest score at least 1%, no more than "
    "two UTC calendar days old, an endpoint increase at least five percentage points, "
    "and median slope at least 0.5 percentage points per day. Falling or unavailable "
    "history never authorizes a downgrade. Every failed condition is reported.",
    "Model comparability requires one bounded reviewed regime covering every date "
    "between the first and last used observation, including dates without scores. "
    "Unknown coverage, model boundaries, or reviews after the decision disable "
    "promotion. A registry is an operator assertion with evidence, not automatic "
    "provider verification. Descriptive cross-regime rates remain visible "
    "with warnings.",
    "Only values available by the decision are used. Future score dates captured "
    "by then are invalid and block promotion. Stored EPSS rows can be overwritten "
    "for the same CVE/date, and older collection timestamps are not immutable "
    "availability logs. Database exports conservatively mark all rows available "
    "at export completion; imported trend exports use their recorded capture. "
    "They cannot reconstruct versions before that export. Validated-capture inputs "
    "require independent provenance for the stated availability time.",
    "The database cohort contains all currently stored CVEs and is historically "
    "KEV-based; frozen comparison studies are separate. It is not a representative "
    "non-KEV or public-vulnerability sample. Missing dates can reflect collection "
    "outages, source absence, publication, or enrollment rather than score stability.",
    "The report freezes input, decision time, model declarations, and policy. It "
    "loads stored history in memory. Exact image bytes require the same locked "
    "packages, Python, fonts, and plotting environment. The CVE preview and charts "
    "are deterministic samples; CSV/JSON exports include the entire frozen cohort.",
]


def _json(value):
    return json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"


def _digest(content):
    return hashlib.sha256(content).hexdigest()


def _csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    key: json.dumps(value, sort_keys=True)
                    if isinstance(value, (dict, list))
                    else value
                    for key, value in row.items()
                }
            )


def charts(result, output):
    with rc_context(
        {"svg.hashsalt": "threatpulse-velocity-v1", "svg.fonttype": "none"}
    ):
        fig, axes = plt.subplots(2, 1, figsize=(10, 8))
        fig.suptitle(result["label"][:120], fontsize=10)
        all_rates = [
            r["median_pairwise_slope_pp_per_day"]
            for r in result["cves"]
            if r["median_pairwise_slope_pp_per_day"] is not None
        ]
        bins = np.histogram_bin_edges(all_rates, bins=15)
        for state, color in (
            ("comparable", "#287d8e"),
            ("unknown", "#777777"),
            ("model_boundary", "#ac4d34"),
        ):
            rates = [
                r["median_pairwise_slope_pp_per_day"]
                for r in result["cves"]
                if r["model_comparability"] == state
                and r["median_pairwise_slope_pp_per_day"] is not None
            ]
            if rates:
                axes[0].hist(
                    rates,
                    bins=bins,
                    alpha=0.55,
                    color=color,
                    label=state.replace("_", " "),
                )
        axes[0].set(
            title="Descriptive EPSS rates by model comparability",
            xlabel="Median pairwise slope (percentage points/day)",
            ylabel="CVEs",
        )
        axes[0].yaxis.set_major_locator(MaxNLocator(integer=True))
        if result["with_rates"]:
            axes[0].legend()
        else:
            axes[0].text(
                0.5,
                0.5,
                "No two-date histories available",
                transform=axes[0].transAxes,
                ha="center",
            )
        scores = {
            (e["cve_id"], e["score_date"]): float(e["epss"]) * 100
            for e in result["series"]
        }
        sample = sorted(
            result["cves"], key=lambda r: (-r["observed_dates"], r["cve_id"])
        )[:5]
        for row in sample:
            if not row["observed_dates"]:
                continue
            first = date.fromisoformat(row["window_start"])
            days = [
                first + timedelta(days=i) for i in range(row["expected_calendar_dates"])
            ]
            values = [
                scores.get((row["cve_id"], d.isoformat()), float("nan")) for d in days
            ]
            verified = row["model_comparability"] == "comparable"
            state_label = row["model_comparability"].replace("_", " ")
            axes[1].plot(
                days,
                values,
                marker=".",
                linestyle="-" if verified else "None",
                label=f"{row['cve_id']} ({state_label})",
            )
        axes[1].set(
            title="Five most observed CVEs; ties by CVE ID",
            xlabel="UTC source score date (gaps remain missing)",
            ylabel="EPSS probability (%)",
            ylim=(0, 100),
        )
        if any(r["observed_dates"] for r in sample):
            axes[1].legend(fontsize=8)
        else:
            axes[1].text(
                0.5,
                0.5,
                "No available observations",
                transform=axes[1].transAxes,
                ha="center",
            )
        axes[1].tick_params(axis="x", labelrotation=30)
        for label in axes[1].get_xticklabels():
            label.set_horizontalalignment("right")
        fig.tight_layout()
        stream = io.StringIO()
        fig.savefig(stream, format="svg", metadata={"Date": None})
        svg = stream.getvalue()
        (output / "threat-velocity.svg").write_text(svg, encoding="utf-8")
        fig.savefig(output / "threat-velocity.png", dpi=160)
        plt.close(fig)
        return svg[svg.index("<svg") :]


def write_report(dataset: VelocityDataset, output: Path, *, decision_at=None):
    # Validate mutable caller-owned models and normalize ordering before freezing.
    source_data = dataset.model_dump(mode="json")
    source_data["cohort"] = sorted(source_data["cohort"])
    source_data["epss_observations"] = sorted(
        source_data["epss_observations"], key=lambda e: (e["cve_id"], e["score_date"])
    )
    source_data["model_registry"]["regimes"] = sorted(
        source_data["model_registry"]["regimes"], key=lambda r: r["score_date_start"]
    )
    frozen = VelocityDataset.model_validate(source_data)
    result = analyze(frozen, decision_at)
    output.mkdir(parents=True, exist_ok=False)
    source = _json(frozen.model_dump(mode="json"))
    policy = _json(result["policy"])
    result["source_sha256"] = _digest(source.encode())
    result["policy_sha256"] = _digest(policy.encode())
    (output / "source.json").write_text(source, encoding="utf-8")
    (output / "policy.json").write_text(policy, encoding="utf-8")
    (output / "analysis.json").write_text(_json(result), encoding="utf-8")
    _csv(
        output / "velocity.csv",
        result["cves"],
        CVE_FIELDS,
    )
    _csv(output / "observations.csv", result["series"], OBSERVATION_FIELDS)
    _csv(output / "intervals.csv", result["intervals"], INTERVAL_FIELDS)
    svg = charts(result, output)
    preview = [
        {
            key: row[key]
            for key in (
                "cve_id",
                "latest_epss",
                "observed_dates",
                "coverage_fraction",
                "median_pairwise_slope_pp_per_day",
                "model_comparability",
                "rising_signal",
                "eligibility_reasons",
            )
        }
        for row in result["cves"][:50]
    ]
    document = f"""<!doctype html><html lang="en"><meta charset="utf-8">
<title>ThreatPulse Threat Velocity</title>
<style>body{{font:16px system-ui;max-width:1100px;margin:40px auto;
padding:0 20px;color:#203340}}
table{{border-collapse:collapse;display:block;overflow-x:auto;font-size:14px}}
th,td{{padding:8px;border:1px solid #cbd5dc;text-align:left}}
svg{{width:100%;height:auto}}
code{{overflow-wrap:anywhere}}p{{line-height:1.6}}</style>
<h1>ThreatPulse Threat Velocity</h1><p>{html.escape(frozen.label)}</p>
<p>Decision: {html.escape(result["decision_at"])};
policy {result["policy"]["policy_version"]}.</p>
<p>{result["cohort_cves"]} CVEs; {result["with_rates"]} with descriptive rates;
{result["rising_cves"]} eligible rising signals.
All failed eligibility checks remain visible.</p>
{svg}<h2>CVE preview (first 50 by identifier; full CSV available)</h2>{table(preview)}
<h2>Methods and limitations</h2>
{"".join("<p>" + html.escape(s) + "</p>" for s in LIMITATIONS)}
<h2>Reproduce</h2><p>Replay <code>source.json</code> with the recorded
decision time and locked dependencies. <code>policy.json</code> freezes
the thresholds; <code>analysis.json</code>, <code>velocity.csv</code>,
<code>observations.csv</code>, and <code>intervals.csv</code> preserve
all results and used evidence. Charts are exported as SVG/PNG. Source SHA-256:
<code>{result["source_sha256"]}</code>.
This report requires no network access.</p></html>"""
    (output / "report.html").write_text(document, encoding="utf-8")
    manifest = {
        "analysis_format": result["analysis_format"],
        "decision_at": result["decision_at"],
        "policy_sha256": result["policy_sha256"],
        "python": sys.version.split()[0],
        "packages": {
            name: package_version(name)
            for name in (
                "threatpulse",
                "pydantic",
                "psycopg",
                "numpy",
                "matplotlib",
                "pandas",
            )
        },
        "code_sha256": {
            name: _digest(Path(__file__).with_name(name).read_bytes())
            for name in (
                "velocity.py",
                "velocity_report.py",
                "epss.py",
                "trends.py",
                "exploration.py",
                "models.py",
                "nvd.py",
            )
        },
        "files_sha256": {
            p.name: _digest(p.read_bytes())
            for p in sorted(output.iterdir())
            if p.is_file()
        },
    }
    (output / "manifest.json").write_text(_json(manifest), encoding="utf-8")
    return result


# Explicit columns keep empty exports useful and replayable.
CVE_FIELDS = (
    "cve_id window_start window_end observed_dates expected_calendar_dates "
    "coverage_fraction span_calendar_days missing_dates maximum_adjacent_gap_days "
    "latest_epss latest_score_age_days endpoint_change_pp endpoint_rate_pp_per_day "
    "median_pairwise_slope_pp_per_day pairwise_slopes descriptive_direction "
    "model_comparability model_regime_ids rising_signal eligibility_reasons "
    "excluded_observations"
).split()
OBSERVATION_FIELDS = (
    "cve_id score_date epss percentile source_url ingested_at raw_record "
    "available_at availability_basis"
).split()
INTERVAL_FIELDS = (
    "cve_id earlier_date later_date elapsed_calendar_days missing_days_between "
    "change_pp rate_pp_per_day model_comparability model_regime_ids"
).split()
