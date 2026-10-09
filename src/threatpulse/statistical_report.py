"""Standalone statistical reports with frozen inputs, plans, and checksums."""

import hashlib
import html
import io
import json
import sys
from importlib.metadata import version as package_version
from pathlib import Path

import pandas as pd
from matplotlib import rc_context

from threatpulse.comparison import ComparisonStudy
from threatpulse.comparison_report import LIMITATIONS as COHORT_LIMITATIONS
from threatpulse.exploration import plt, table
from threatpulse.statistics import ENDPOINTS, StatisticalPlan, analyze

LIMITATIONS = [
    "These are exploratory, model-based comparisons of a defined observational "
    "publication-window census. The frozen scores and their observed differences "
    "are known; p-values and bootstrap intervals refer to hypothetical exchangeable "
    "labels or independent within-group resampling, not sampling error in the census. "
    "CVE independence and exchangeability are assumptions, not established facts. "
    "Related CVEs, vendors, products, and campaigns may create dependence.",
    "The two-sided rank test calibrates Mann-Whitney U under equal score distributions "
    "using pooled midpoint ranks. It can detect rank differences; it is not solely a "
    "test of medians or an omnibus detector of every distribution difference. "
    "Ties count as half a win in probability superiority and Cliff's delta. "
    "Positive effects favor higher KEV scores; this is not a remediation ranking.",
    "All possible group partitions are enumerated when they fit the configured "
    "permutation budget; otherwise seeded Monte Carlo uses SciPy's conservative "
    "plus-one p-value correction. Two-sided p-values are twice the smaller tail, "
    "capped at one. Randomized p-values have simulation uncertainty, especially "
    "near the alpha threshold. Their finite resolution is reported.",
    "The five endpoints are fixed in advance by this workflow: EPSS and preferred "
    "CVSS 2.0, 3.0, 3.1, and 4.0. Holm correction includes unavailable endpoints "
    "as p=1, preserving the family size. It controls familywise error only if the "
    "underlying p-values and assumptions are valid. Repeated windows, dates, plans, "
    "or additional analyses are outside this family and require separate accounting.",
    "Confidence intervals use independent within-group percentile bootstraps for "
    "median differences and Cliff's delta. They have nominal confidence and are "
    "not simultaneous or multiplicity-adjusted. Small samples, discrete scores, "
    "rare tails, and empirical support limit their accuracy. Collapsed intervals "
    "are suppressed and flagged rather than presented as certainty; complete "
    "separation can make the bootstrap delta interval collapse.",
    "The default minimum is 20 scored CVEs in each group for an endpoint, a reporting "
    "guardrail rather than a power calculation or guarantee of validity. A lower "
    "configured threshold is exported. Insufficient groups and no pooled variation "
    "receive descriptive effects when possible, but no p-values or intervals. "
    "Failing to reject the null does not establish equality or equivalence.",
    "Missing scores stay unknown, and each endpoint uses its scored subset. CVSS "
    "versions are never pooled. Coverage tables partition each group into selected "
    "scores, missing metric values, and other preferred CVSS versions. Differential "
    "missingness, cohort age, vendor mix, model changes, analysis maturity, and "
    "exposure can affect results; statistical correction cannot remove those biases.",
    "EPSS predicts exploitation, while KEV reflects known exploitation and may "
    "overlap its evidence sources. This is not an independent model-validation "
    "experiment. Significance does not establish causation, practical importance, "
    "population representativeness, prediction quality, or prioritization weights. "
    "Choose windows, dates, hypotheses, thresholds, and seeds before inspecting "
    "results; an exported plan alone is not external preregistration.",
    "Scores are analyzed with double-precision numerical values. Resampling uses "
    "bounded batches, but runtime grows with cohort size and resampling budgets. "
    "Exact reproduction requires the same inputs, plan, code, locked dependencies, "
    "Python, random generator implementation, fonts, and plotting environment.",
]


def _label(test):
    return "EPSS" if test["metric"] == "epss" else f"CVSS {test['cvss_version']}"


def charts(result, output):
    embedded = []

    def save(name, fig):
        fig.tight_layout()
        stream = io.StringIO()
        fig.savefig(stream, format="svg", metadata={"Date": None})
        svg = stream.getvalue()
        (output / f"{name}.svg").write_text(svg)
        fig.savefig(output / f"{name}.png", dpi=160)
        embedded.append(svg[svg.index("<svg") :])
        plt.close(fig)

    def forest(ax, tests, effect, bounds, title, xlabel):
        for index, test in enumerate(tests):
            value = test[effect]
            color = "#287d8e" if test["status"] == "tested" else "#777777"
            if value is None:
                ax.text(
                    0.98,
                    index,
                    "No estimate",
                    ha="right",
                    va="center",
                    transform=ax.get_yaxis_transform(),
                    fontsize=9,
                )
                continue
            low, high = test[f"{effect}_ci_low"], test[f"{effect}_ci_high"]
            if low is not None and high is not None:
                ax.hlines(index, low, high, color=color, linewidth=2)
            ax.scatter([value], [index], color=color)
            if low is None:
                ax.annotate(
                    "CI unavailable",
                    (value, index),
                    xytext=(0, 8),
                    textcoords="offset points",
                    fontsize=8,
                    ha="center",
                )
        ax.axvline(0, color="#aaaaaa", linestyle="--")
        ax.set(xlim=bounds, ylim=(len(tests) - 0.5, -0.5), title=title, xlabel=xlabel)
        ax.set_yticks(
            range(len(tests)),
            [
                f"{_label(t)} ({t['kev_scored_n']}/{t['non_kev_scored_n']})"
                for t in tests
            ],
        )

    with rc_context({"svg.hashsalt": "threatpulse-statistics-v1", "font.size": 10}):
        caption = (
            f"Nominal {(1 - result['plan']['alpha']) * 100:g}% percentile intervals "
            "(not simultaneous); n = KEV/non-KEV"
        )
        fig, ax = plt.subplots(figsize=(10, 5))
        fig.suptitle(caption, fontsize=10)
        forest(
            ax,
            result["tests"],
            "cliffs_delta",
            (-1.05, 1.05),
            "Cliff's delta: KEV minus non-KEV",
            "Delta (ties contribute zero)",
        )
        save("effect-sizes", fig)
        fig, axes = plt.subplots(1, 2, figsize=(12, 5))
        fig.suptitle(caption, fontsize=10)
        forest(
            axes[0],
            result["tests"][:1],
            "median_difference",
            (-105, 105),
            "EPSS median difference",
            "Percentage points",
        )
        forest(
            axes[1],
            result["tests"][1:],
            "median_difference",
            (-10.5, 10.5),
            "CVSS median differences",
            "CVSS points (same preferred version)",
        )
        save("median-differences", fig)
    return embedded


def findings(result):
    tested = sum(t["status"] == "tested" for t in result["tests"])
    rejected = sum(t["reject_null_holm"] is True for t in result["tests"])
    sentences = [
        f"{tested} of {result['family_size']} planned endpoints were tested; "
        f"{result['family_size'] - tested} did not meet the data requirements.",
        f"Holm correction at alpha={result['plan']['alpha']:g} rejected the "
        f"exchangeable-distribution null for {rejected} endpoints. "
        "This result is conditional on the stated assumptions and cohort selection.",
    ]
    for test in result["tests"]:
        name = _label(test)
        if test["status"] != "tested":
            sentences.append(f"{name}: {test['unavailable_reason']}.")
        else:
            sentences.append(
                f"{name}: {test['kev_scored_n']} KEV and "
                f"{test['non_kev_scored_n']} "
                "non-KEV scored CVEs; median difference "
                f"{test['median_difference']:.3g} "
                f"{test['difference_unit']}, Cliff's delta {test['cliffs_delta']:.3g}, "
                f"raw p={test['p_value']:.4g}, Holm p={test['p_value_holm']:.4g} "
                f"({test['permutation_method']})."
            )
    return sentences


def write_report(study, output: Path, plan=None):
    if output.exists():
        raise FileExistsError("Use a new output directory")
    study = ComparisonStudy.model_validate(study.model_dump(mode="json"))
    plan = StatisticalPlan.model_validate((plan or StatisticalPlan()).model_dump())
    result = analyze(study, plan)
    output.mkdir(parents=True, exist_ok=False)
    source = json.dumps(
        study.model_dump(mode="json"), sort_keys=True, indent=2, ensure_ascii=False
    )
    digest = hashlib.sha256(source.encode()).hexdigest()
    result["source_sha256"] = digest
    (output / "source.json").write_text(source)
    (output / "plan.json").write_text(plan.model_dump_json(indent=2))
    (output / "analysis.json").write_text(json.dumps(result, indent=2, allow_nan=False))
    hypotheses = {
        "family": list(ENDPOINTS),
        "null": result["tests"][0]["null_hypothesis"],
        "alternative": "two-sided",
        "statistic": "Mann-Whitney U using pooled midpoint ranks",
        "direction": "KEV minus non-KEV",
        "multiplicity": result["multiplicity_method"],
        "minimum_group_size": plan.minimum_group_size,
        "intervals": "Nominal within-group percentile bootstrap; not simultaneous",
        "requirements": [
            "Unique CVEs in one frozen publication window",
            "Exact common EPSS date",
            "Separate preferred CVSS versions",
            "Unknown scores excluded without imputation",
            "Minimum scored sample in each group and pooled score variation",
        ],
    }
    (output / "hypotheses.json").write_text(json.dumps(hypotheses, indent=2))
    for name, rows in (
        ("tests", result["tests"]),
        ("coverage", result["coverage"]),
        ("cohorts", result["rows"]),
    ):
        flat = [
            {
                k: json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else v
                for k, v in row.items()
            }
            for row in rows
        ]
        columns = (
            list(result["tests"][0])
            if name == "tests"
            else (
                list(result["coverage"][0])
                if name == "coverage"
                else [
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
                ]
            )
        )
        pd.DataFrame(flat, columns=columns).to_csv(output / f"{name}.csv", index=False)
    figures = charts(result, output)
    display = [
        {
            "endpoint": _label(t),
            "status": t["status"],
            "KEV scored": t["kev_scored_n"],
            "non-KEV scored": t["non_kev_scored_n"],
            "median difference": t["median_difference"],
            "units": t["difference_unit"],
            "Cliff's delta": t["cliffs_delta"],
            "raw p": t["p_value"],
            "Holm p": t["p_value_holm"],
            "reject null (Holm)": t["reject_null_holm"],
        }
        for t in result["tests"]
    ]
    intervals = [
        {
            "endpoint": _label(t),
            "confidence": t["ci_confidence"],
            "median low": t["median_difference_ci_low"],
            "median high": t["median_difference_ci_high"],
            "units": t["difference_unit"],
            "delta low": t["cliffs_delta_ci_low"],
            "delta high": t["cliffs_delta_ci_high"],
            "warnings": "; ".join(t["ci_warnings"]),
        }
        for t in result["tests"]
    ]
    definition = result["definition"]
    methods = LIMITATIONS + [COHORT_LIMITATIONS]
    document = f"""<!doctype html><html lang="en"><meta charset="utf-8">
<title>ThreatPulse statistical comparison</title>
<style>body{{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;
color:#203340}}table{{border-collapse:collapse;font-size:14px;display:block;
overflow-x:auto}}th,td{{padding:8px;border:1px solid #cbd5dc;text-align:left}}
svg{{width:100%;height:auto}}p{{line-height:1.6}}code{{overflow-wrap:anywhere}}</style>
<h1>ThreatPulse statistical comparison</h1>
<p>{html.escape(result["label"])}</p>
<p>Frozen study: {result["study_id"]}.
Publication window: {definition["published_start"]}
inclusive through {definition["published_end"]} exclusive, UTC. Exact EPSS date:
{definition["score_date"]}; KEV snapshot: {html.escape(result["kev_snapshot_at"])}.</p>
<h2>Findings</h2>{"".join("<p>" + html.escape(s) + "</p>" for s in findings(result))}
<h2>Plan</h2>{table([plan.model_dump()])}
<p>Five two-sided hypotheses compare scored EPSS and each preferred CVSS version.
The null assumes equal distributions with exchangeable group labels. Effects are
KEV minus non-KEV. All five endpoints remain in the Holm family; unavailable
endpoints contribute p=1 to correction and retain unknown results.</p>
<h2>Group coverage</h2>{table(result["coverage"])}
<h2>Exclusions</h2>{table([result["exclusions"]])}
<h2>Tests and effects</h2>{table(display)}
<p>Missing estimates stay unknown. No rejection establishes neither equality
nor equivalence. The tests CSV includes per-endpoint missingness and denominators.</p>
<h2>Nominal confidence intervals</h2>{table(intervals)}
<p>Intervals are not simultaneous or multiplicity-adjusted. Unknown intervals
may indicate insufficient data or a degenerate empirical bootstrap.</p>
<h2>Figures</h2>{"".join(figures)}
<p>Gray points are descriptive estimates from unavailable tests. Bars show nominal
confidence intervals; absent bars mean the interval is unavailable.</p>
<h2>Methods, assumptions, and selection limits</h2>
{"".join("<p>" + html.escape(s) + "</p>" for s in methods)}
<h2>Reproduce</h2><p>Source SHA-256: <code>{digest}</code>. Replay source.json with
plan.json and the same code and locked dependencies. All inputs, settings, seeds,
statistics, and file hashes are exported. This HTML requires no network access.</p>
</html>"""
    (output / "report.html").write_text(document)
    manifest = {
        "analysis_format": 1,
        "python": sys.version.split()[0],
        "study_id": str(study.study_id),
        "plan": plan.model_dump(),
        "definition": definition,
        "packages": {
            name: package_version(name)
            for name in (
                "threatpulse",
                "numpy",
                "scipy",
                "pandas",
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
            for name in (
                "statistics.py",
                "statistical_report.py",
                "comparison.py",
                "comparison_report.py",
                "exploration.py",
                "nvd.py",
                "models.py",
                "epss.py",
                "kev.py",
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
