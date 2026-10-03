"""Verify descriptive calculations, boundaries, and missing-data semantics."""

from datetime import date
from decimal import Decimal

from threatpulse.analytics import (
    cvss_epss_points,
    epss_distribution,
    kev_counts,
    score_changes,
)


def test_distribution_boundaries_zero_one_and_missing():
    scores = [
        None,
        Decimal("0"),
        Decimal("0.099"),
        Decimal("0.1"),
        Decimal("0.999"),
        Decimal("1"),
    ]
    bins, missing = epss_distribution([{"epss": score} for score in scores])
    assert missing == 1
    assert bins[0]["CVEs"] == 2
    assert bins[1]["CVEs"] == 1
    assert bins[-1]["CVEs"] == 2
    assert sum(row["CVEs"] for row in bins) == 5
    assert epss_distribution([])[1] == 0


def test_vendor_product_pairs_exclude_non_kev_and_do_not_merge_names():
    rows = [
        {"vendor": "A", "product": "Shared", "kev_date": date(2026, 1, 1)},
        {"vendor": "B", "product": "Shared", "kev_date": date(2026, 1, 1)},
        {"vendor": "A", "product": "Other", "kev_date": date(2026, 1, 1)},
        {"vendor": "C", "product": "Shared", "kev_date": None},
    ]
    assert kev_counts(rows) == [{"Vendor": "A", "CVEs": 2}, {"Vendor": "B", "CVEs": 1}]
    assert len(kev_counts(rows, products=True)) == 3
    assert sum(row["CVEs"] for row in kev_counts(rows, products=True)) == 3


def test_cvss_versions_and_missing_pairs_are_kept_separate():
    row = {
        "cve_id": "CVE-2026-1234",
        "vendor": "A",
        "cvss_version": "3.1",
        "base_score": Decimal("9.8"),
        "epss": Decimal("0.9"),
        "score_date": date(2026, 1, 1),
    }
    points = cvss_epss_points(
        [row, dict(row, cvss_version="4.0"), dict(row, epss=None)], "3.1"
    )
    assert len(points) == 1
    assert points[0]["EPSS (%)"] == 90.0
    assert points[0]["CVSS base score"] == 9.8


def test_percentage_point_changes_and_unpaired_coverage():
    rows = [
        {"cve_id": "increase", "before": Decimal("0.1"), "after": Decimal("0.2")},
        {"cve_id": "decrease", "before": Decimal("0.5"), "after": Decimal("0.4")},
        {"cve_id": "unchanged", "before": Decimal("0"), "after": Decimal("0")},
        {"cve_id": "earlier-only", "before": Decimal("0.1"), "after": None},
        {"cve_id": "later-only", "before": None, "after": Decimal("0.8")},
    ]
    paired, earlier, later = score_changes(rows)
    assert [row["Change (percentage points)"] for row in paired] == [10.0, 0.0, -10.0]
    assert earlier == later == 1
    assert score_changes([]) == ([], 0, 0)
