"""Render dedicated descriptive analytics; no inferred prioritization score."""

import altair as alt
import pandas as pd
import streamlit as st

from threatpulse.analytics import (
    cvss_epss_points,
    epss_distribution,
    kev_counts,
    score_changes,
)
from threatpulse.dashboard_data import load_epss_comparison, load_epss_dates


def show_kev_analytics(rows):
    st.subheader("KEV vendor and product counts")
    kev_rows = [row for row in rows if row["kev_date"] is not None]
    st.metric("Stored KEV CVEs", len(kev_rows))
    st.caption(
        "Counts cover stored KEV records, not vendor market share or product risk. "
        "Names are used as published; aliases and multi-product records are not split."
    )
    if not kev_rows:
        st.info("No stored KEV records are available for analytics.")
        return
    vendors = pd.DataFrame(kev_counts(rows))
    products = pd.DataFrame(kev_counts(rows, products=True))
    left, right = st.columns(2)
    with left:
        st.markdown("**Top 10 vendors**")
        st.bar_chart(vendors.head(10), x="Vendor", y="CVEs", sort=False)
        st.dataframe(vendors, hide_index=True)
    with right:
        st.markdown("**Top 10 vendor/product pairs**")
        chart = products.head(10).copy()
        chart["Vendor / product"] = chart["Vendor"] + " / " + chart["Product"]
        st.bar_chart(chart, x="Vendor / product", y="CVEs", sort=False)
        st.dataframe(products, hide_index=True)


def show_epss_analytics(rows, database_url):
    st.caption(
        "Charts describe stored CVEs. The current collection is KEV-based; "
        "it does not support a KEV versus non-KEV comparison."
    )
    st.subheader("EPSS probability distribution")
    bins, missing = epss_distribution(rows)
    st.metric("Scored CVEs", len(rows) - missing)
    st.caption(
        f"Latest available observation per CVE; {missing} CVEs lack EPSS. "
        "10-point bins include the lower bound, exclude the upper bound, "
        "and include 100% in the final bin. Dates may differ across CVEs."
    )
    st.bar_chart(pd.DataFrame(bins), x="EPSS probability", y="CVEs", sort=False)
    st.subheader("CVSS versus EPSS")
    versions = sorted({row["cvss_version"] for row in rows if row["cvss_version"]})
    if versions:
        default = max(
            versions, key=lambda v: sum(row["cvss_version"] == v for row in rows)
        )
        version = st.selectbox(
            "CVSS version for comparison",
            versions,
            index=versions.index(default),
            key="analytics_cvss",
        )
        points = cvss_epss_points(rows, version)
        eligible = sum(row["cvss_version"] == version for row in rows)
        st.caption(
            f"{len(points)} complete score pairs of {eligible} CVEs with preferred "
            f"CVSS {version}. Versions are kept separate. This is descriptive, "
            "not a correlation claim or a validated prioritization model."
        )
        if points:
            chart = (
                alt.Chart(pd.DataFrame(points))
                .mark_circle(size=45, opacity=0.5)
                .encode(
                    x=alt.X("CVSS base score:Q", scale=alt.Scale(domain=[0, 10])),
                    y=alt.Y("EPSS (%):Q", scale=alt.Scale(domain=[0, 100])),
                    tooltip=[
                        "CVE:N",
                        "Vendor:N",
                        "CVSS base score:Q",
                        "EPSS (%):Q",
                        "EPSS date:N",
                    ],
                )
                .interactive()
            )
            st.altair_chart(chart, width="stretch")
        else:
            st.info("No complete score pairs are available for this version.")
    else:
        st.info("No CVSS enrichment is available for comparison.")
    st.subheader("EPSS change between recorded dates")
    dates = load_epss_dates(database_url)
    if len(dates) < 2:
        st.info("Collect EPSS on at least two dates to compare changes.")
        return
    earlier = st.selectbox(
        "Earlier EPSS date", dates[:-1], index=len(dates) - 2, key="analytics_earlier"
    )
    later_dates = [day for day in dates if day > earlier]
    later = st.selectbox(
        "Later EPSS date",
        later_dates,
        index=len(later_dates) - 1,
        key="analytics_later",
    )
    compared = load_epss_comparison(database_url, earlier, later)
    cohort = {row["cve_id"] for row in rows}
    compared = [row for row in compared if row["cve_id"] in cohort]
    paired, first_only, second_only = score_changes(compared)
    cols = st.columns(3)
    cols[0].metric("Observed on both dates", len(paired))
    cols[1].metric("Earlier date only", first_only)
    cols[2].metric("Later date only", second_only)
    absent = len(rows) - len(compared)
    st.caption(
        f"{absent} stored CVEs are absent on both selected dates. "
        "Changes use only matched CVEs and are percentage-point differences, "
        "not percent growth, daily velocity, or evidence of increased exploitation. "
        "Missing scores are not replaced with zero; gaps are not interpolated. "
        "EPSS model changes can also affect scores."
    )
    if not paired:
        st.info("No CVEs have scores on both selected dates.")
        return
    increases = sum(row["Change (percentage points)"] > 0 for row in paired)
    decreases = sum(row["Change (percentage points)"] < 0 for row in paired)
    st.write(
        f"Increased: {increases} · Decreased: {decreases} · "
        f"Unchanged: {len(paired) - increases - decreases}"
    )
    st.dataframe(pd.DataFrame(paired), hide_index=True)
    st.caption(
        "Table is ordered by signed change, from largest increase to largest decrease."
    )
