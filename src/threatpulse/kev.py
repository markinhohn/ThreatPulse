"""Fetch and validate the CISA Known Exploited Vulnerabilities catalog."""

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx
from pydantic import BaseModel, ValidationError

from threatpulse.models import KevEntry, Vulnerability, parse_cisa_kev_record

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


class KevCollectionError(Exception):
    """A catalog could not be fetched or fully validated."""


class CollectedVulnerability(BaseModel):
    vulnerability: Vulnerability
    kev: KevEntry


class KevCatalog(BaseModel):
    records: list[CollectedVulnerability]


def collect_kev(
    *, client: httpx.Client | None = None, timeout: float = 30.0
) -> KevCatalog:
    """Return a fully validated batch or fail without returning partial data.

    An injected client remains owned by the caller. Every request has an explicit
    timeout. Redirects are followed for the official catalog; TLS verification
    remains enabled. Retries are left to the caller or scheduler.
    """
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if client is None:
        with httpx.Client() as owned_client:
            return collect_kev(client=owned_client, timeout=timeout)
    try:
        response = client.get(CISA_KEV_URL, timeout=timeout, follow_redirects=True)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise KevCollectionError(
            f"CISA KEV request failed with HTTP {exc.response.status_code}"
        ) from exc
    except httpx.RequestError as exc:
        raise KevCollectionError(
            f"CISA KEV request failed ({type(exc).__name__})"
        ) from exc
    try:
        payload = response.json()
    except ValueError as exc:
        raise KevCollectionError("CISA KEV response is not valid JSON") from exc
    if not isinstance(payload, dict) or not isinstance(
        payload.get("vulnerabilities"), list
    ):
        raise KevCollectionError(
            "CISA KEV catalog must contain a vulnerabilities array"
        )
    records = payload["vulnerabilities"]
    if not records:
        raise KevCollectionError("CISA KEV catalog is unexpectedly empty")
    if "count" in payload and (
        type(payload["count"]) is not int or payload["count"] != len(records)
    ):
        raise KevCollectionError("CISA KEV catalog count does not match its records")
    collected = []
    seen = set()
    ingested_at = datetime.now(UTC)
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise KevCollectionError(f"CISA KEV record {index} must be an object")
        try:
            vulnerability, entry = parse_cisa_kev_record(
                record, source_url=CISA_KEV_URL, ingested_at=ingested_at
            )
        except ValidationError as exc:
            raise KevCollectionError(
                f"CISA KEV record {index} failed validation"
            ) from exc
        if vulnerability.cve_id in seen:
            raise KevCollectionError(
                f"Duplicate CVE in CISA KEV: {vulnerability.cve_id}"
            )
        seen.add(vulnerability.cve_id)
        collected.append(CollectedVulnerability(vulnerability=vulnerability, kev=entry))
    return KevCatalog(records=collected)


def main(argv: list[str] | None = None) -> int:
    """Fetch the catalog, optionally writing validated records as JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write JSON to a new file")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        catalog = collect_kev(timeout=args.timeout)
        if args.output:
            # Exclusive creation protects existing exports from accidental overwrite.
            with args.output.open("x", encoding="utf-8") as output:
                output.write(catalog.model_dump_json(indent=2) + "\n")
    except (KevCollectionError, OSError) as exc:
        print(f"Collection failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"source": CISA_KEV_URL, "records": len(catalog.records)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
