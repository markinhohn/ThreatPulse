"""Descriptive KEV and EPSS calculations with explicit cohort semantics."""

from collections import Counter
from decimal import Decimal


def kev_counts(rows, *, products=False):
    """Count stored KEV CVEs, pairing product names with their vendor."""
    counts = Counter(
        (row["vendor"], row["product"]) if products else (row["vendor"],)
        for row in rows
        if row["kev_date"] is not None
    )
    return [
        dict(
            zip(["Vendor", "Product"] if products else ["Vendor"], key, strict=True),
            CVEs=count,
        )
        for key, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def epss_distribution(rows):
    """Fixed-width bins of latest available probability; 100% is included."""
    counts = [0] * 10
    missing = 0
    for row in rows:
        if row["epss"] is None:
            missing += 1
        else:
            counts[min(int(row["epss"] * 10), 9)] += 1
    return [
        {"EPSS probability": f"{i * 10}–{(i + 1) * 10}%", "CVEs": count}
        for i, count in enumerate(counts)
    ], missing


def cvss_epss_points(rows, version):
    """Keep complete score pairs from one preferred CVSS version only."""
    return [
        {
            "CVE": row["cve_id"],
            "Vendor": row["vendor"],
            "CVSS base score": float(row["base_score"]),
            "EPSS (%)": float(row["epss"]) * 100,
            "EPSS date": row["score_date"].isoformat(),
        }
        for row in rows
        if row["cvss_version"] == version
        and row["base_score"] is not None
        and row["epss"] is not None
    ]


def score_changes(rows):
    """Calculate percentage-point changes only for CVEs observed on both dates."""
    paired, first_only, second_only = [], 0, 0
    for row in rows:
        before, after = row["before"], row["after"]
        if before is None:
            second_only += 1
        elif after is None:
            first_only += 1
        else:
            delta = (after - before) * Decimal(100)
            paired.append(
                {
                    "CVE": row["cve_id"],
                    "Earlier EPSS (%)": float(before * 100),
                    "Later EPSS (%)": float(after * 100),
                    "Change (percentage points)": float(delta),
                }
            )
    paired.sort(key=lambda row: (-row["Change (percentage points)"], row["CVE"]))
    return paired, first_only, second_only
