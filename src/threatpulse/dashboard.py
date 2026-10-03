"""Streamlit entry point: run with streamlit run src/threatpulse/dashboard.py."""

import os

import pandas as pd
import psycopg
import streamlit as st

from threatpulse.dashboard_data import (
    filter_vulnerabilities,
    load_cve_details,
    load_vulnerabilities,
)


def display_table(rows):
    """Convert decimal fractions to explicitly labeled display percentages."""
    frame = pd.DataFrame(rows)
    result = frame[
        [
            "cve_id",
            "vendor",
            "product",
            "kev_date",
            "cvss_version",
            "base_score",
            "severity",
            "attack_vector",
            "score_date",
        ]
    ].copy()
    result["severity"] = result["severity"].fillna("UNKNOWN")
    result["EPSS (%)"] = frame["epss"].map(
        lambda x: float(x) * 100 if x is not None else None
    )
    result["EPSS percentile (%)"] = frame["percentile"].map(
        lambda x: float(x) * 100 if x is not None else None
    )
    result["base_score"] = result["base_score"].map(
        lambda x: float(x) if x is not None else None
    )
    return result.rename(
        columns={
            "cve_id": "CVE",
            "vendor": "Vendor",
            "product": "Product",
            "kev_date": "KEV date",
            "cvss_version": "CVSS version",
            "base_score": "CVSS base score",
            "severity": "Severity",
            "attack_vector": "Attack vector",
            "score_date": "EPSS date",
        }
    )


def show_details(database_url, cve_id):
    details = load_cve_details(database_url, cve_id)
    if details is None:
        st.info("This vulnerability is no longer available. Refresh the dashboard.")
        return
    st.subheader(cve_id)
    st.text(details["name"])
    st.text(details["nvd_description"] or details["description"])
    left, right = st.columns(2)
    with left:
        st.markdown("**CISA remediation**")
        st.text(details["required_action"] or "No KEV remediation available.")
        st.write("Due date:", details["due_date"] or "Unknown")
        st.write("Ransomware campaign use:", details["ransomware_use"] or "Unknown")
        if details["notes"]:
            st.text(details["notes"])
    with right:
        st.markdown("**NVD context**")
        st.write("Analysis status:", details["nvd_status"] or "Unknown")
        st.write("Published:", details["published_at"] or "Unknown")
        st.write("Modified:", details["modified_at"] or "Unknown")
        st.write("Weaknesses:", ", ".join(details["weaknesses"] or []) or "Unknown")
    st.markdown("**EPSS history**")
    history = details["epss_history"]
    if history:
        frame = pd.DataFrame(history)
        frame["EPSS (%)"] = frame["epss"].map(lambda x: float(x) * 100)
        st.line_chart(frame, x="score_date", y="EPSS (%)")
        st.caption(
            "Each point is an exploitation probability estimate for the next 30 days."
        )
        if len(history) == 1:
            st.caption(
                "One observation recorded; collect another date to show a trend."
            )
        st.dataframe(frame[["score_date", "EPSS (%)", "ingested_at"]], hide_index=True)
    else:
        st.info("No EPSS observations are stored for this CVE.")
    with st.expander("References and source timestamps"):
        # Source references remain plain text, including legacy FTP URLs.
        for url in details["reference_urls"] or []:
            st.text(url)
        st.write("KEV source:", details["kev_source"] or "Unknown")
        st.write("KEV ingested (UTC):", details["kev_ingested"] or "Unknown")
        st.write("NVD source:", details["nvd_source"] or "Unknown")
        st.write("NVD ingested (UTC):", details["nvd_ingested"] or "Unknown")
        if history:
            st.write("Latest EPSS source:", history[-1]["source_url"])
            st.write("Latest EPSS ingested (UTC):", history[-1]["ingested_at"])
    with st.expander("All CVSS source metrics"):
        if details["cvss_metrics"]:
            st.dataframe(pd.DataFrame(details["cvss_metrics"]), hide_index=True)
        else:
            st.info("No CVSS metrics are available.")


def main():
    st.set_page_config(page_title="ThreatPulse", page_icon="🛡️", layout="wide")
    st.title("ThreatPulse")
    st.caption(
        "Known exploited vulnerabilities, severity, and exploitation probability"
    )
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        st.error(
            "Set DATABASE_URL before starting the dashboard. See docs/development.md."
        )
        return
    try:
        rows = load_vulnerabilities(database_url)
    except psycopg.Error:
        st.error("Could not load data. Check database access and run migrations.")
        return
    st.sidebar.button("Refresh data")
    if not rows:
        st.info(
            "No vulnerabilities are stored yet. Run KEV ingestion to populate data."
        )
        return
    overview, explorer = st.tabs(["Overview", "Vulnerability explorer"])
    with overview:
        columns = st.columns(3)
        columns[0].metric("Stored vulnerabilities", len(rows))
        scored = sum(row["epss"] is not None for row in rows)
        columns[1].metric("EPSS coverage", f"{scored}/{len(rows)}")
        columns[2].metric(
            "CVSS coverage",
            f"{sum(row['base_score'] is not None for row in rows)}/{len(rows)}",
        )
        st.subheader("Severity distribution")
        counts = pd.Series([r["severity"] or "UNKNOWN" for r in rows]).value_counts()
        st.bar_chart(
            counts.reindex(
                ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"], fill_value=0
            )
        )
        dates = sorted({r["score_date"] for r in rows if r["score_date"] is not None})
        if dates:
            st.caption(
                f"Latest EPSS per CVE; dates range from {dates[0]} to {dates[-1]}."
            )
        st.caption(
            "Overview covers all stored CVEs. "
            "Scores across CVSS versions are not directly interchangeable."
        )
    with explorer:
        search = st.text_input("Search CVE, vendor, product, name, or description")
        vendors = st.multiselect("Vendor", sorted({r["vendor"] for r in rows}))
        severities = st.multiselect(
            "Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]
        )
        minimum = st.slider("Minimum EPSS probability (%)", 0.0, 100.0, 0.0, 0.1)
        include_missing = st.checkbox("Include CVEs without EPSS", value=True)
        filtered = filter_vulnerabilities(
            rows,
            search=search,
            vendors=vendors,
            severities=severities,
            min_epss=minimum / 100,
            include_missing_epss=include_missing,
        )
        st.caption(
            f"Showing {len(filtered)} of {len(rows)} vulnerabilities. "
            "Blank scores mean unknown."
        )
        if not filtered:
            st.info("No vulnerabilities match these filters.")
            return
        st.dataframe(display_table(filtered), hide_index=True, width="stretch")
        selected = st.selectbox("CVE details", [r["cve_id"] for r in filtered])
        try:
            show_details(database_url, selected)
        except psycopg.Error:
            st.error("Could not load CVE details. Check database access and refresh.")


if __name__ == "__main__":
    main()
