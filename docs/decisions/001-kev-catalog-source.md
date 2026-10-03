# Decision: use CISA's official GitHub KEV publication

## Reason

The original source was:

`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

The first request was blocked by the cloud environment's network proxy.
After allowing `www.cisa.gov`, the HTTPS tunnel succeeded, but the upstream
server returned HTTP 403 and an HTML Access Denied response. That response
prevented live ingestion; changing JSON parsing or disabling TLS verification
would not address it.

## Choice

Use the catalog published by CISA under its `cisagov` GitHub organization:

`https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json`

Repository: <https://github.com/cisagov/kev-data>

This keeps the source with the original publisher and uses the same catalog
format. It also uses a hostname already included in this environment's package
manager network preset. No credentials are required.

## Modifications

- Change the collector's `CISA_KEV_URL` constant to the GitHub publication.
- Preserve that URL in every KEV entry's `source_url` and the command summary.
- Assert source provenance in collector and command tests.
- Update the development guide's parsing example and network requirement.

The data models, validation rules, timeout, TLS verification, and export format
remain unchanged. There is no automatic fallback: failures still surface to the
caller, and the source stays explicit rather than changing silently.

## Tradeoffs and operational behavior

The `main` branch supplies the latest published catalog, so its content can
change between requests. Raw records and UTC ingestion timestamps remain in
exports for traceability. This does not preserve the entire original catalog or
its Git commit; exact whole-catalog snapshot tracking is future work.

Availability now depends on GitHub's raw-content service. A successful fetch
does not prove publication freshness; future ingestion monitoring should track
catalog publication metadata and detect stale data. We have not compared the
two endpoints byte-for-byte because the original endpoint is inaccessible.

Tests remain offline and deterministic. Live validation must fetch and validate
the complete catalog, verify unique CVEs and advertised count, and confirm the
export's source URL. PostgreSQL persistence remains a separate next step.

## Validation outcome

On October 3, 2026, a live collector run successfully fetched and validated
1,733 records from the GitHub source. The JSON export was read back through the
catalog model; all CVEs were unique, all original CVE identifiers matched the
normalized records, and every source URL identified the GitHub publication.
All 49 offline tests passed, as did Ruff lint and formatting checks. The record
count is an observation of that run, not a fixed expectation for future catalogs.
