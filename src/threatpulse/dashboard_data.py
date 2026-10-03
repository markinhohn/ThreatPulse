"""Read-only PostgreSQL queries and filters for the ThreatPulse dashboard."""

import re
from typing import Any

import psycopg
from psycopg.rows import dict_row


def load_vulnerabilities(database_url: str) -> list[dict[str, Any]]:
    """Return one row per CVE, using its latest available EPSS observation."""
    with psycopg.connect(
        database_url, row_factory=dict_row, connect_timeout=10
    ) as conn:
        conn.execute("SET TRANSACTION READ ONLY")
        return conn.execute(
            """
            SELECT v.cve_id, v.vendor, v.product, v.name, v.description,
                   k.date_added AS kev_date, n.cvss_version, n.base_score,
                   n.severity, n.attack_vector, e.score_date, e.epss, e.percentile
            FROM vulnerabilities v
            LEFT JOIN kev_entries k USING (cve_id)
            LEFT JOIN nvd_enrichments n USING (cve_id)
            LEFT JOIN LATERAL (
                SELECT score_date, epss, percentile FROM epss_observations
                WHERE cve_id = v.cve_id ORDER BY score_date DESC LIMIT 1
            ) e ON true
            ORDER BY e.epss DESC NULLS LAST, v.cve_id
            """
        ).fetchall()


def load_cve_details(database_url: str, cve_id: str) -> dict[str, Any] | None:
    """Read source details and all EPSS dates for a single CVE."""
    with psycopg.connect(
        database_url, row_factory=dict_row, connect_timeout=10
    ) as conn:
        conn.execute("SET TRANSACTION READ ONLY")
        record = conn.execute(
            """
            SELECT v.*, k.required_action, k.due_date, k.ransomware_use,
                   k.notes, k.source_url AS kev_source, k.ingested_at AS kev_ingested,
                   n.description AS nvd_description, n.published_at, n.modified_at,
                   n.status AS nvd_status, n.reference_urls, n.weaknesses,
                   n.cvss_metrics, n.source_url AS nvd_source,
                   n.ingested_at AS nvd_ingested
            FROM vulnerabilities v
            LEFT JOIN kev_entries k USING (cve_id)
            LEFT JOIN nvd_enrichments n USING (cve_id)
            WHERE v.cve_id = %s
            """,
            (cve_id,),
        ).fetchone()
        if record is None:
            return None
        record["epss_history"] = conn.execute(
            """
            SELECT score_date, epss, percentile, source_url, ingested_at
            FROM epss_observations WHERE cve_id = %s ORDER BY score_date
            """,
            (cve_id,),
        ).fetchall()
        return record


def filter_vulnerabilities(
    rows: list[dict[str, Any]],
    *,
    search: str = "",
    vendors: list[str] | None = None,
    severities: list[str] | None = None,
    min_epss: float = 0,
    include_missing_epss: bool = True,
) -> list[dict[str, Any]]:
    """Apply independent filters without converting unknown scores to zero."""
    if not 0 <= min_epss <= 1:
        raise ValueError("min_epss must be between 0 and 1")
    needle = search.strip().casefold()
    exact_cve = bool(re.fullmatch(r"cve-[0-9]{4}-[0-9]{4,}", needle))
    return [
        row
        for row in rows
        if (
            not needle
            or (
                row["cve_id"].casefold() == needle
                if exact_cve
                else any(
                    needle in str(row[field]).casefold()
                    for field in ("cve_id", "vendor", "product", "name", "description")
                )
            )
        )
        and (not vendors or row["vendor"] in vendors)
        and (not severities or (row["severity"] or "UNKNOWN") in severities)
        and (
            (row["epss"] is None and include_missing_epss)
            or (row["epss"] is not None and row["epss"] >= min_epss)
        )
    ]
