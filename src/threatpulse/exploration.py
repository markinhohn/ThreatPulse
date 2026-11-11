"""Reproducible, read-only exploratory analysis of stored vulnerability data."""

import argparse
import hashlib
import html
import io
import json
import os
import sys
from collections import Counter
from datetime import date
from decimal import Decimal
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Literal

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import psycopg
from matplotlib.ticker import MaxNLocator
from psycopg.rows import dict_row
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

CVSS_VERSIONS = ("2.0", "3.0", "3.1", "4.0")


class StoredCve(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    vendor: str
    product: str
    kev_date: date | None
    nvd_ingested_at: AwareDatetime | None
    nvd_modified_at: AwareDatetime | None
    cvss_version: Literal["2.0", "3.0", "3.1", "4.0"] | None
    base_score: Decimal | None = Field(ge=0, le=10)
    severity: str | None

    @model_validator(mode="after")
    def score_version(self):
        if (self.base_score is None) != (self.cvss_version is None):
            raise ValueError("CVSS score and version must both be present or absent")
        return self


class StoredEpss(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve_id: str
    score_date: date
    epss: Decimal = Field(ge=0, le=1)
    percentile: Decimal = Field(ge=0, le=1)
    ingested_at: AwareDatetime


class Dataset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    captured_at: AwareDatetime
    label: str = "Stored ThreatPulse dataset"
    vulnerabilities: list[StoredCve]
    epss_observations: list[StoredEpss]

    @model_validator(mode="after")
    def unique_keys(self):
        ids = {v.cve_id for v in self.vulnerabilities}
        if len(ids) != len(self.vulnerabilities):
            raise ValueError("Duplicate CVEs")
        keys = {(e.cve_id, e.score_date) for e in self.epss_observations}
        if len(keys) != len(self.epss_observations):
            raise ValueError("Duplicate EPSS CVE/date observations")
        if any(e.cve_id not in ids for e in self.epss_observations):
            raise ValueError("EPSS observation outside stored cohort")
        return self


def read_dataset(connection) -> Dataset:
    """Read inside the caller's REPEATABLE READ, READ ONLY transaction."""
    with connection.cursor(row_factory=dict_row) as cursor:
        captured_at = cursor.execute("SELECT transaction_timestamp() AS captured_at")
        captured_at = captured_at.fetchone()["captured_at"]
        vulnerabilities = cursor.execute(
            """
            SELECT v.cve_id, v.vendor, v.product, k.date_added AS kev_date,
                   n.ingested_at AS nvd_ingested_at,
                   n.modified_at AS nvd_modified_at,
                   n.cvss_version, n.base_score, n.severity
            FROM vulnerabilities v
            LEFT JOIN kev_entries k USING (cve_id)
            LEFT JOIN nvd_enrichments n USING (cve_id)
            ORDER BY v.cve_id
            """
        ).fetchall()
        observations = cursor.execute(
            "SELECT cve_id, score_date, epss, percentile, ingested_at "
            "FROM epss_observations ORDER BY score_date, cve_id"
        ).fetchall()
    return Dataset(
        captured_at=captured_at,
        vulnerabilities=vulnerabilities,
        epss_observations=observations,
    )


def describe(values) -> dict:
    """Type-7 linear quantiles; no missing-value substitution."""
    series = pd.Series([float(v) for v in values], dtype=float)
    return {
        "n": len(series),
        **{
            key: None if series.empty else float(value)
            for key, value in {
                "min": series.min(),
                "p25": series.quantile(0.25),
                "median": series.median(),
                "p75": series.quantile(0.75),
                "max": series.max(),
                "mean": series.mean(),
            }.items()
        },
    }


def analyze(dataset: Dataset, score_date=None, earlier=None, later=None) -> dict:
    date_counts = Counter(e.score_date for e in dataset.epss_observations)
    dates = sorted(date_counts)
    score_date = score_date or (dates[-1] if dates else None)
    if score_date is not None and score_date not in dates:
        raise ValueError("Selected EPSS date has no observations")
    if (earlier is None) != (later is None):
        raise ValueError("Provide both comparison dates")
    if earlier is None and len(dates) >= 2:
        earlier, later = dates[0], dates[-1]
    if earlier is not None and (
        earlier >= later or earlier not in dates or later not in dates
    ):
        raise ValueError("Comparison requires two recorded dates in increasing order")
    observations = {(e.cve_id, e.score_date): e for e in dataset.epss_observations}
    rows = []
    for cve in dataset.vulnerabilities:
        score = observations.get((cve.cve_id, score_date))
        rows.append(
            {
                **cve.model_dump(mode="json"),
                "epss": float(score.epss) if score else None,
                "score_date": score_date.isoformat() if score else None,
            }
        )
    relationships = []
    for version in CVSS_VERSIONS:
        eligible = [r for r in rows if r["cvss_version"] == version]
        paired = [r for r in eligible if r["epss"] is not None]
        x = pd.Series([float(r["base_score"]) for r in paired], dtype=float)
        y = pd.Series([r["epss"] for r in paired], dtype=float)
        reason = None
        if len(paired) < 3:
            reason = "Fewer than three complete pairs"
        elif x.nunique() < 2 or y.nunique() < 2:
            reason = "Constant score series"
        relationships.append(
            {
                "cvss_version": version,
                "eligible": len(eligible),
                "paired": len(paired),
                "missing_epss": len(eligible) - len(paired),
                "pearson_r": None if reason else float(x.corr(y)),
                # Average ranks for ties, then Pearson; avoids a scipy dependency.
                "spearman_rho": None if reason else float(x.rank().corr(y.rank())),
                "unavailable_reason": reason,
                "cvss_summary": describe(r["base_score"] for r in eligible),
            }
        )
    changes = []
    before_only = after_only = neither = 0
    if earlier is not None:
        for cve in dataset.vulnerabilities:
            before = observations.get((cve.cve_id, earlier))
            after = observations.get((cve.cve_id, later))
            if before is not None and after is not None:
                changes.append(
                    {
                        "cve_id": cve.cve_id,
                        "earlier_epss": float(before.epss),
                        "later_epss": float(after.epss),
                        "change_pp": float((after.epss - before.epss) * 100),
                    }
                )
            elif before is not None:
                before_only += 1
            elif after is not None:
                after_only += 1
            else:
                neither += 1
        changes.sort(key=lambda r: (-r["change_pp"], r["cve_id"]))
    total = len(rows)
    available = sum(r["epss"] is not None for r in rows)
    cvss = sum(r["base_score"] is not None for r in rows)
    return {
        "label": dataset.label,
        "captured_at": dataset.captured_at.isoformat(),
        "score_date": score_date.isoformat() if score_date else None,
        "coverage": {
            "stored_cves": total,
            "stored_kev_entries": sum(r["kev_date"] is not None for r in rows),
            "nvd_enriched": sum(r["nvd_ingested_at"] is not None for r in rows),
            "cvss_scored": cvss,
            "missing_cvss": total - cvss,
            "epss_scored": available,
            "missing_epss": total - available,
            "complete_pairs": sum(
                r["base_score"] is not None and r["epss"] is not None for r in rows
            ),
        },
        "epss_summary": describe(r["epss"] for r in rows if r["epss"] is not None),
        "relationships": relationships,
        "vulnerabilities": rows,
        "history_coverage": [
            {
                "score_date": day.isoformat(),
                "observed": date_counts[day],
                "missing": total - date_counts[day],
            }
            for day in dates
        ],
        "comparison": {
            "earlier": earlier.isoformat() if earlier else None,
            "later": later.isoformat() if later else None,
            "matched": len(changes),
            "earlier_only": before_only,
            "later_only": after_only,
            "neither": neither,
            "increased": sum(r["change_pp"] > 0 for r in changes),
            "decreased": sum(r["change_pp"] < 0 for r in changes),
            "unchanged": sum(r["change_pp"] == 0 for r in changes),
            "delta_summary_pp": describe(r["change_pp"] for r in changes),
        },
        "changes": changes,
    }


LIMITATIONS = """
The cohort contains all stored CVEs and is KEV-based. Retained KEV entries do
not establish current catalog membership, and this report cannot compare KEV
with a representative non-KEV population. Vendor/product labels are unnormalized.
CVSS is severity; EPSS is predicted exploitation probability over 30 days,
not observed exploitation. EPSS percentile is not probability.
The score distributions and relationship use the selected exact EPSS date;
missing scores stay unknown. NVD uses each CVE's current preferred metric,
not its metric as of the EPSS date. Versions are analyzed separately.
Pearson r and Spearman rho are descriptive associations in this selected cohort,
not causal evidence or validated prioritization weights. No p-values or
population significance claims are calculated. Three pairs is only a computation
minimum, not evidence of reliable inference. Ties use average ranks.
History compares exact endpoints only for matched CVEs. One-sided and absent
coverage are reported; gaps are not filled. Changing collection coverage and
EPSS model revisions can affect observed changes. Percentage-point differences
are not percent growth or time-normalized Threat Velocity.
The database export uses one repeatable-read, read-only transaction. It contains
normalized analysis fields and timestamps, not raw source JSON or credentials.
Daily KEV/NVD snapshot tables are not used to reconstruct historical cohorts.
""".strip()


def charts(result, output):
    """Export SVG figures and embed them in the standalone HTML report."""
    plt.rcParams.update({"svg.hashsalt": "threatpulse-eda-v1", "font.size": 10})
    figures = []

    def save(name, fig):
        fig.tight_layout()
        stream = io.StringIO()
        fig.savefig(stream, format="svg", metadata={"Date": None})
        fig.savefig(output / f"{name}.png", dpi=160)
        plt.close(fig)
        svg = stream.getvalue()
        (output / f"{name}.svg").write_text(svg)
        figures.append(svg[svg.index("<svg") :])

    rows = result["vulnerabilities"]
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.hist(
        [r["epss"] * 100 for r in rows if r["epss"] is not None],
        bins=list(range(0, 101, 10)),
        color="#287d8e",
        edgecolor="white",
    )
    ax.set(
        xlim=(0, 100),
        xlabel="EPSS probability (%)",
        ylabel="CVEs",
        title=f"EPSS distribution · {result['score_date'] or 'no recorded date'}",
    )
    ax.set_ylim(bottom=0)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    save("epss-distribution", fig)
    for version in CVSS_VERSIONS:
        eligible = [r for r in rows if r["cvss_version"] == version]
        if not eligible:
            continue
        fig, axes = plt.subplots(1, 2, figsize=(10, 4))
        axes[0].hist(
            [float(r["base_score"]) for r in eligible],
            bins=list(range(11)),
            color="#287d8e",
            edgecolor="white",
        )
        axes[0].set(
            xlim=(0, 10),
            xlabel="CVSS base score",
            ylabel="CVEs",
            title=f"CVSS {version} distribution (n={len(eligible)})",
        )
        paired = [r for r in eligible if r["epss"] is not None]
        axes[1].scatter(
            [float(r["base_score"]) for r in paired],
            [r["epss"] * 100 for r in paired],
            alpha=0.45,
            color="#ac4d34",
        )
        axes[1].set(
            xlim=(0, 10),
            ylim=(0, 100),
            xlabel=f"CVSS {version} base score",
            ylabel="EPSS probability (%)",
            title=f"Complete pairs (n={len(paired)})",
        )
        axes[0].set_ylim(bottom=0)
        axes[0].yaxis.set_major_locator(MaxNLocator(integer=True))
        save(f"cvss-{version}", fig)
    if result["history_coverage"]:
        fig, ax = plt.subplots(figsize=(9, 4))
        history = result["history_coverage"]
        days = [date.fromisoformat(r["score_date"]) for r in history]
        ax.scatter(days, [r["observed"] for r in history], color="#287d8e")
        ax.axhline(len(rows), color="#777", linestyle="--", label="Stored cohort")
        ax.set(
            ylim=(0, max(len(rows), 1) * 1.1),
            xlabel="Recorded score date",
            ylabel="Observed CVEs",
            title="EPSS collection coverage (no interpolation)",
        )
        ax.legend()
        fig.autofmt_xdate()
        save("history-coverage", fig)
    if result["changes"]:
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.hist(
            [r["change_pp"] for r in result["changes"]],
            bins=20,
            color="#ac4d34",
            edgecolor="white",
        )
        ax.set(
            xlabel="EPSS change (percentage points)",
            ylabel="Matched CVEs",
            title=(
                f"{result['comparison']['earlier']} → {result['comparison']['later']}"
            ),
        )
        ax.yaxis.set_major_locator(MaxNLocator(integer=True))
        save("epss-changes", fig)
    return figures


def table(records):
    frame = pd.DataFrame(records).astype(object)
    return frame.where(frame.notna(), "Unknown").to_html(index=False, escape=True)


def findings(result):
    coverage = result["coverage"]
    total = coverage["stored_cves"]
    if not total:
        return ["No stored CVEs are available. Ingest data before interpreting charts."]
    sentences = [
        f"Of {total:,} stored CVEs, {coverage['nvd_enriched']:,} have NVD data "
        f"and {coverage['cvss_scored']:,} have a preferred CVSS score.",
        f"On {result['score_date'] or 'no recorded EPSS date'}, "
        f"{coverage['epss_scored']:,} CVEs have EPSS "
        f"({coverage['epss_scored'] / total:.1%} coverage); "
        f"{coverage['missing_epss']:,} remain unknown.",
    ]
    median = result["epss_summary"]["median"]
    if median is not None:
        sentences.append(
            f"Median EPSS among scored CVEs is {median * 100:.2f}%. "
            "This excludes CVEs without scores."
        )
    for relationship in result["relationships"]:
        if relationship["pearson_r"] is not None:
            sentences.append(
                f"CVSS {relationship['cvss_version']}: "
                f"{relationship['paired']:,} complete pairs give "
                f"Pearson r={relationship['pearson_r']:.3f} and "
                f"Spearman rho={relationship['spearman_rho']:.3f}. "
                "These describe this cohort only."
            )
    comparison = result["comparison"]
    if comparison["earlier"]:
        sentences.append(
            f"Between {comparison['earlier']} and {comparison['later']}, "
            f"{comparison['matched']:,} CVEs have both observations: "
            f"{comparison['increased']:,} increased, "
            f"{comparison['decreased']:,} decreased, "
            f"and {comparison['unchanged']:,} were unchanged."
        )
    return sentences


def write_report(dataset, output: Path, *, score_date=None, earlier=None, later=None):
    result = analyze(dataset, score_date, earlier, later)
    # Exclusive destination prevents clobbering an earlier reproducible export.
    output.mkdir(parents=True, exist_ok=False)
    source = dataset.model_dump_json(indent=2)
    digest = hashlib.sha256(source.encode()).hexdigest()
    result["source_sha256"] = digest
    (output / "source.json").write_text(source)
    (output / "analysis.json").write_text(json.dumps(result, indent=2, allow_nan=False))
    for name, records, columns in (
        (
            "vulnerabilities",
            result["vulnerabilities"],
            list(StoredCve.model_fields) + ["epss", "score_date"],
        ),
        (
            "epss-observations",
            [e.model_dump(mode="json") for e in dataset.epss_observations],
            list(StoredEpss.model_fields),
        ),
        (
            "relationships",
            result["relationships"],
            [
                "cvss_version",
                "eligible",
                "paired",
                "missing_epss",
                "pearson_r",
                "spearman_rho",
                "unavailable_reason",
                "cvss_summary",
            ],
        ),
        (
            "history-coverage",
            result["history_coverage"],
            ["score_date", "observed", "missing"],
        ),
        (
            "changes",
            result["changes"],
            ["cve_id", "earlier_epss", "later_epss", "change_pp"],
        ),
    ):
        pd.DataFrame(records, columns=columns).to_csv(
            output / f"{name}.csv", index=False
        )
    figures = charts(result, output)
    relations = [
        {k: v for k, v in r.items() if k != "cvss_summary"}
        for r in result["relationships"]
    ]
    text = f"""<!doctype html><html lang="en"><meta charset="utf-8">
<title>ThreatPulse exploratory analysis</title>
<style>body{{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;
color:#203340}}table{{border-collapse:collapse;font-size:14px;display:block;
overflow-x:auto}}th,td{{padding:8px;border:1px solid #cbd5dc;text-align:left}}
svg{{width:100%;height:auto}}code{{overflow-wrap:anywhere}}p{{line-height:1.6}}</style>
<h1>ThreatPulse exploratory analysis</h1>
<p>{html.escape(dataset.label)} · captured {html.escape(result["captured_at"])}</p>
<p>Exact EPSS date: {result["score_date"] or "none"}. All stored CVEs form the cohort.
Current preferred NVD metrics are used. Missing scores stay unknown.</p>
<h2>Findings</h2>
{"".join("<p>" + html.escape(sentence) + "</p>" for sentence in findings(result))}
<h2>Data coverage</h2>{table([result["coverage"]])}
<h2>EPSS summary (probability fractions, 0–1)</h2>{table([result["epss_summary"]])}
<h2>CVSS summaries by preferred version (0–10)</h2>
{
        table(
            [
                {"version": r["cvss_version"], **r["cvss_summary"]}
                for r in result["relationships"]
            ]
        )
    }
<h2>CVSS and EPSS associations</h2>{table(relations)}
<p>Correlations are descriptive; no significance or causation is claimed.
Unknown coefficients indicate too few pairs or a constant score series.</p>
<h2>Historical EPSS changes</h2>
{table([{k: v for k, v in result["comparison"].items() if k != "delta_summary_pp"}])}
{table([result["comparison"]["delta_summary_pp"]])}
<p>At least two recorded dates and matched CVEs are needed for changes.
The default endpoints are the earliest and latest recorded dates.</p>
<h2>Figures</h2>{"".join(figures)}
<h2>Largest signed changes (first 20 matched CVEs)</h2>{table(result["changes"][:20])}
<h2>Methods and limitations</h2>
{"".join("<p>" + html.escape(p.strip()) + "</p>" for p in LIMITATIONS.splitlines())}
<p>Quantiles use linear interpolation. EPSS histogram bins include their lower
bound, exclude their upper bound, and include 100% in the last bin.</p>
<h2>Reproduce</h2><p>Analysis format: 1 · source SHA-256: <code>{digest}</code>.
Replay source.json using the locked project dependencies and the same selected
dates. The CSV files contain the full cohort, observations, and computed changes.
SVG figures can be shared separately; this HTML needs no network access.</p></html>"""
    (output / "report.html").write_text(text)
    manifest = {
        "analysis_format": 1,
        "analysis_code_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "python": sys.version.split()[0],
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
        "selected_dates": {key: result[key] for key in ("score_date",)},
        "comparison_dates": {
            key: result["comparison"][key] for key in ("earlier", "later")
        },
        "files_sha256": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.iterdir())
            if p.is_file()
        },
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, required=True, help="New report directory"
    )
    parser.add_argument(
        "--input", type=Path, help="Replay a previously exported source.json"
    )
    parser.add_argument("--score-date", type=date.fromisoformat)
    parser.add_argument("--earlier", type=date.fromisoformat)
    parser.add_argument("--later", type=date.fromisoformat)
    args = parser.parse_args(argv)
    try:
        if args.input:
            dataset = Dataset.model_validate_json(args.input.read_text())
        else:
            database_url = os.environ.get("DATABASE_URL")
            if not database_url:
                print("Set DATABASE_URL or pass --input source.json.", file=sys.stderr)
                return 1
            with psycopg.connect(database_url, connect_timeout=10) as connection:
                connection.execute(
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
                )
                dataset = read_dataset(connection)
        write_report(
            dataset,
            args.output,
            score_date=args.score_date,
            earlier=args.earlier,
            later=args.later,
        )
    except (psycopg.Error, ValueError, OSError) as exc:
        print(
            f"Analysis failed ({type(exc).__name__}). Check database setup, "
            "input format, selected dates, and use a new output directory.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps({"report": str(args.output / "report.html")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
