"""Scanner selection, local previews, CVE review queues, and evidence downloads."""

import base64
import inspect
from datetime import UTC, datetime
from importlib.resources import files

import pandas as pd
import psycopg
import streamlit as st

from threatpulse.daily import IngestionBusyError, ingestion_lock
from threatpulse.priority import PriorityDataset
from threatpulse.scan_import import FORMATS, MAX_BYTES, ScanImportError, parse_scan
from threatpulse.scan_worklist import (
    assess,
    cached_intelligence,
    csv_bytes,
    latest_assessment,
    load_scan,
    refresh_intelligence,
    save_assessment,
    save_scan,
    worklist,
)
from threatpulse.storage import migrate

LABELS = {"Nessus": "nessus", "OpenVAS / Greenbone": "openvas", "Nmap": "nmap"}


def resources():
    return files("threatpulse").joinpath("examples/scans")


def set_current(scan, *, assessment=None):
    st.session_state["active_scan"] = scan
    st.session_state["scan_assessment"] = assessment or assess(scan)


def sample(scanner, format):
    raw = resources().joinpath(f"{scanner}.{format}").read_bytes()
    scan = parse_scan(
        raw,
        scanner,
        format,
        filename=f"synthetic-{scanner}.{format}",
        synthetic=True,
        scanned_at=datetime(2026, 1, 10, 11, tzinfo=UTC),
    )
    intel = PriorityDataset.model_validate_json(
        resources().joinpath("intelligence.json").read_text()
    )
    return scan, assess(scan, intel, decision_at=intel.captured_at)


def show_scan_imports(database_url=None):
    if "pending_saved_scan" in st.session_state:
        scan, assessment = st.session_state.pop("pending_saved_scan")
        st.session_state["scan_scanner"] = next(
            k for k, v in LABELS.items() if v == scan.scanner
        )
        st.session_state[f"scan_format_{scan.scanner}"] = scan.format
        set_current(scan, assessment=assessment)
    st.header("Scan imports")
    st.write(
        "Import scanner findings, inspect their evidence, and export "
        "an asset review worklist."
    )
    left, right = st.columns(2)
    scanner = LABELS[left.selectbox("Scanner", list(LABELS), key="scan_scanner")]
    format = right.selectbox(
        "Export format",
        FORMATS[scanner],
        format_func=lambda v: (
            "XML (.nessus)" if scanner == "nessus" and v == "xml" else v.upper()
        ),
        key=f"scan_format_{scanner}",
    )
    current = st.session_state.get("active_scan")
    if current and (current.scanner, current.format) != (scanner, format):
        st.session_state.pop("active_scan", None)
        st.session_state.pop("scan_assessment", None)
        current = None
    st.caption(
        "Nessus: XML/CSV · OpenVAS/Greenbone: XML/CSV · Nmap: XML "
        "(-oX). Maximum 25 MiB. Importing a file does not contact "
        "scanned hosts."
    )
    with st.form("scanner_upload"):
        extra = (
            {"max_upload_size": 25}
            if "max_upload_size" in inspect.signature(st.file_uploader).parameters
            else {}
        )
        upload = st.file_uploader(
            "Scan export",
            type=["nessus", "xml"] if format == "xml" else ["csv"],
            key=f"file_{scanner}_{format}",
            **extra,
        )
        timestamp = st.text_input(
            "Scan completed at (optional)",
            placeholder="2026-11-11T10:00:00-05:00",
            help=(
                "Use ISO 8601 with a timezone when the export has no "
                "unambiguous scan time. This is a declared override."
            ),
        )
        declared_demo = st.checkbox(
            "This file is synthetic demonstration data", value=False
        )
        submitted = st.form_submit_button("Preview scan")
    if submitted:
        st.session_state.pop("active_scan", None)
        st.session_state.pop("scan_assessment", None)
        try:
            if upload is None:
                raise ScanImportError("Choose a scan export before previewing it.")
            if upload.size > MAX_BYTES:
                raise ScanImportError("Scan exceeds the 25 MiB import limit.")
            scan = parse_scan(
                upload.getvalue(),
                scanner,
                format,
                filename=upload.name,
                scanned_at=datetime.fromisoformat(timestamp)
                if timestamp.strip()
                else None,
                synthetic=declared_demo,
            )
            set_current(scan)
        except (ValueError, OSError) as exc:
            st.error(
                str(exc)
                if isinstance(exc, ScanImportError)
                else (
                    "Could not read this export. Check format and scan time, "
                    "including timezone."
                )
            )
    if st.button("Load synthetic sample", key="load_scan_sample"):
        scan, assessment = sample(scanner, format)
        set_current(scan, assessment=assessment)
    if database_url:
        with st.expander("Saved imports"):
            if st.button("List saved imports"):
                try:
                    with psycopg.connect(database_url, connect_timeout=10) as conn:
                        conn.execute("SET TRANSACTION READ ONLY")
                        st.session_state["saved_scans"] = conn.execute(
                            "SELECT scan_id,filename,scanner,format FROM scan_imports "
                            "ORDER BY imported_at DESC LIMIT 100"
                        ).fetchall()
                except psycopg.Error:
                    st.info(
                        "Saved imports are unavailable. Check database access and "
                        "apply migrations."
                    )
            options = st.session_state.get("saved_scans", [])
            if options:
                chosen = st.selectbox(
                    "Saved scan",
                    options,
                    format_func=lambda r: f"{r[1]} ({r[2]}/{r[3]}, {str(r[0])[:8]})",
                )
                if st.button("Open selected import"):
                    try:
                        with psycopg.connect(database_url, connect_timeout=10) as conn:
                            conn.execute("SET TRANSACTION READ ONLY")
                            scan = load_scan(conn, chosen[0])
                            previous = latest_assessment(conn, scan.scan_id)
                        st.session_state["pending_saved_scan"] = (scan, previous)
                        st.rerun()
                    except (ValueError, psycopg.Error):
                        st.error("Could not load this saved import and its assessment.")
    current = st.session_state.get("active_scan")
    if current is None:
        st.info(
            "Upload a scan or load a synthetic sample to start. Samples "
            "include invented CVEs and frozen intelligence."
        )
        return
    st.text("Source: " + current.filename)
    if current.synthetic:
        st.warning(
            "SYNTHETIC DEMO — assets, vulnerabilities, and intelligence "
            "are invented. See the recorded decision time below."
        )
    for warning in current.warnings:
        st.warning(warning.replace("_", " ").capitalize())
    a, b, c = st.columns(3)
    a.metric("Imported assets", len(current.assets))
    b.metric("Scanner findings", len(current.findings))
    c.metric("Reported CVEs", len({c for f in current.findings for c in f.cves}))
    assessment = st.session_state["scan_assessment"]
    if database_url:
        buttons = st.columns(3)
        cached = buttons[0].button(
            "Use cached CVE intelligence", disabled=current.synthetic
        )
        refreshed = buttons[1].button(
            "Refresh public CVE intelligence",
            disabled=current.synthetic,
            help=(
                "Only CVE identifiers go to CISA/FIRST/NVD. Limit: 200 "
                "unique active CVEs; NVD lookups can take time."
            ),
        )
        saved = buttons[2].button("Save import and assessment")
        if cached or refreshed or saved:
            try:
                with (
                    st.spinner("Preparing scan assessment…"),
                    psycopg.connect(
                        database_url, autocommit=True, connect_timeout=10
                    ) as conn,
                ):
                    migrate(conn)
                    with ingestion_lock(conn):
                        current = save_scan(conn, current)
                        prior = latest_assessment(conn, current.scan_id) or assessment
                        if cached or refreshed:
                            intelligence, outcomes = (
                                refresh_intelligence(conn, current)
                                if refreshed
                                else (cached_intelligence(conn, current), [])
                            )
                            assessment = assess(
                                current, intelligence, previous=prior, outcomes=outcomes
                            )
                        save_assessment(conn, assessment)
                set_current(current, assessment=assessment)
                st.success("Import and frozen assessment saved.")
            except (ValueError, psycopg.Error, IngestionBusyError) as exc:
                st.error(
                    f"Could not complete this operation ({type(exc).__name__}). "
                    "Check database access, the CVE limit, and ingestion activity."
                )
        st.caption(
            "Database operations save this import and its assessment. "
            "Only CVE identifiers are sent to public intelligence providers."
        )
    else:
        st.caption(
            "Local preview and downloads work without a database. Set "
            "DATABASE_URL to enable saved imports and public CVE "
            "enrichment."
        )
    st.caption(
        "Intelligence decision (UTC): "
        + assessment.decision_at.astimezone(UTC).isoformat()
        + (
            ". CVE intelligence priority is separate from confidence "
            "that an asset is affected."
        )
    )
    failed = [o["source"] for o in assessment.source_outcomes if o["state"] == "failed"]
    if failed:
        st.warning(
            "Some intelligence sources could not be refreshed: "
            + ", ".join(failed)
            + ". Retained evidence and unknown-data flags remain visible."
        )
    rows = worklist(current, assessment)
    queues = sorted({r["priority"] for r in rows})
    selected = st.multiselect(
        "Priority queues",
        queues,
        default=[q for q in queues if q != "NOT_RANKED"] or queues,
    )
    visible = [r for r in rows if r["priority"] in selected]
    columns = [
        "asset",
        "cve_id",
        "priority",
        "scanner_severity",
        "kev_confirmed",
        "match_basis",
        "scan_age",
        "priority_reasons",
        "quality_flags",
        "next_action",
    ]
    display = pd.DataFrame(visible)
    display["EPSS (%) latest known"] = [
        float(r["epss"]) * 100 if r["epss"] is not None else None for r in visible
    ]
    columns.insert(5, "EPSS (%) latest known")
    st.dataframe(display.reindex(columns=columns), hide_index=True, width="stretch")
    st.caption(
        f"Showing {len(visible)} of {len(rows)} review items. Downloads contain "
        "all items, including informational/negative results. "
        "Assign owners in the CSV worklist."
    )
    st.download_button(
        "Download complete worklist CSV",
        csv_bytes(rows),
        file_name=f"worklist-{current.scan_id}.csv",
        mime="text/csv",
        on_click="ignore",
    )
    st.download_button(
        "Download normalized scan JSON",
        current.model_dump_json(indent=2),
        file_name=f"scan-{current.scan_id}.json",
        mime="application/json",
        on_click="ignore",
    )
    st.download_button(
        "Download frozen assessment JSON",
        assessment.model_dump_json(indent=2),
        file_name=f"assessment-{assessment.assessment_id}.json",
        mime="application/json",
        on_click="ignore",
    )
    st.download_button(
        "Download CVE intelligence JSON",
        assessment.intelligence.model_dump_json(indent=2),
        file_name=f"intelligence-{assessment.assessment_id}.json",
        mime="application/json",
        on_click="ignore",
    )
    st.download_button(
        "Download original scan",
        base64.b64decode(current.raw_base64),
        file_name=current.filename,
        mime="application/xml" if current.format == "xml" else "text/csv",
        on_click="ignore",
    )
    with st.expander("Asset/service inventory and source evidence"):
        inventory = [
            {
                "asset": a.address,
                "port": s.port,
                "protocol": s.protocol,
                "state": s.state,
                "service": s.name,
                "product": s.product,
                "version": s.version,
                "CPEs": s.cpes,
            }
            for a in current.assets
            for s in a.services
        ]
        st.dataframe(pd.DataFrame(inventory), hide_index=True)
        if current.findings:
            chosen = st.selectbox(
                "Finding evidence",
                current.findings,
                format_func=lambda f: f"{f.asset_key}: {f.title} ({f.source_locator})",
            )
            st.json(chosen.model_dump(mode="json"))
    st.info(
        "Nmap service fingerprints are inventory evidence. Only "
        "explicit script CVE references enter candidate review; "
        "automatic CPE/version-to-CVE matching is a later milestone. "
        "Scan-age review uses a provisional seven-day threshold."
    )
