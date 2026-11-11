# Scanner imports and asset review worklists

ThreatPulse imports existing scan exports, preserves their evidence, and joins
reported CVEs to the baseline intelligence policy. The default Streamlit workspace
is **Scan imports**. File preview and synthetic demonstrations work without
PostgreSQL or API credentials.

## Supported inputs

| Scanner selection | Export format | Recognized profile |
| --- | --- | --- |
| Nessus | XML | Native `NessusClientData_v2` `.nessus`/XML reports |
| Nessus | CSV | UTF-8 CSV with `Host`/`IP` and `Plugin ID` columns |
| OpenVAS / Greenbone | XML | Native report XML or GMP `get_reports_response` containing results |
| OpenVAS / Greenbone | CSV | UTF-8 CSV with `IP`/`Host` and `NVT OID` columns |
| Nmap | XML | Native `nmaprun` XML produced with `-oX` |

Common CSV columns include `CVE`/`CVEs`, `Name`/`NVT Name`, `Risk`/`Threat`,
`Severity`, `Port`, `Protocol`/`Port Protocol`, `Description`/`Summary`, `Solution`/
`Solution Description`, plugin output, QoD, and explicitly named CVSS base scores.
Header comparison tolerates case, spaces, punctuation, and a UTF-8 BOM. Quoted
commas, multiple CVEs, and multiline fields are supported. Export CVE columns
when available; their absence produces a visible warning. Arbitrary custom CSV
layouts and other scanners need an adapter rather than guessed column mappings.

These adapters do not start scanners or contact imported hosts. Nmap service
fingerprints and CPEs remain inventory evidence. Only explicit NSE CVE references
enter candidate review. Structured script states are scoped to their vulnerability
table; explicit negative results stay outside active CVE ranking. References from
scripts such as `vulners` still require applicability verification. Automatic
product/CPE/version-to-CVE matching is a later milestone.

## Run a local demo

From the repository root:

```sh
uv sync --locked
uv run --locked streamlit run src/threatpulse/dashboard.py \
  --server.address=127.0.0.1 --server.port=8501 --browser.gatherUsageStats=false
```

Open `http://localhost:8501`:

1. Select **Scanner** and **Export format**.
2. Click **Load synthetic sample**, or upload an export and click **Preview scan**.
3. Inspect assets, scanner findings, and reported CVE counts.
4. Review priority queues, reasons, missing-data flags, and next actions.
5. Download the complete worklist CSV, normalized scan, frozen assessment,
   intelligence dataset, or original input.

Each supported scanner/format has a bundled sample under
`src/threatpulse/examples/scans/`. All sample assets, findings, CVEs, and scores are
invented. Built-in samples use frozen January 10, 2026 UTC intelligence and are
marked synthetic in the UI and worklist exports. Synthetic and ordinary imports
have distinct identities. Demo intelligence cannot be applied to an undeclared
ordinary scan. Live/cached enrichment buttons are disabled for synthetic samples.

Select **Vulnerability intelligence** in the sidebar to use the existing KEV,
EPSS, explorer, and historical detail dashboard. That workspace still needs
`DATABASE_URL` and populated dashboard tables. Scanner imports do not insert
non-KEV assets or findings into those tables or the ML research cohort.

## Understand the worklist

A scan finding can reference multiple CVEs, and several rules can reference the
same CVE on an asset. Active findings are grouped by asset/CVE while retaining
rule IDs, ports, finding IDs, evidence, and remediation text. Non-CVE configuration
findings remain in **SCANNER_REVIEW**. Informational and negative results remain
in **NOT_RANKED**, available in downloads and the queue filter. A service-only
Nmap import shows its inventory review items even when it reports no CVEs.

P1–P4 and UNDETERMINED describe **CVE intelligence review priority**. They do not
prove the imported asset is affected or compromised. Scanner-reported matches,
NSE candidate references, credentialed-scan metadata, and OpenVAS QoD retain
their distinct meanings. QoD is not an exploitation probability. The scanner's
severity/score remains separate from NVD's preferred CVSS metric and EPSS.
Always verify applicability before assigning remediation.

Without intelligence, active CVEs are UNDETERMINED rather than receiving invented
scores. The scanner's severity, evidence, and proposed solution remain available.
Worklist rows include a next action and blank owner field for assignment after
export. This version does not manage tickets, owners, remediation status, or infer
that a finding disappeared because it was fixed.

## Scan times and quality

Unambiguous epoch/offset-bearing timestamps are imported when available. Naive
dates such as Nessus's human-readable host time do not silently become UTC.
Use **Scan completed at** with an explicit offset when needed; this is a recorded
override. CSV exports often omit scan timestamps.

Scan age is separate from intelligence freshness. The provisional asset review
threshold is seven days: unknown, future, or older scan times receive visible
flags and verification actions. Intelligence uses the existing policy's CISA,
EPSS, NVD, and optional Threat Velocity gates. Missing CVE references, partial
OpenVAS exports, and truncated evidence previews remain visible. The original
file always retains the complete source evidence.

## Saved imports and public intelligence

Configure `DATABASE_URL` using [the development guide](development.md). Migration 7
adds `scan_imports` and `scan_assessments`, with append-only SQL guards and hashes.
The dashboard offers:

- **Save import and assessment**: preserve source bytes and the current assessment.
- **Use cached CVE intelligence**: assess using the existing stored public-source
  evidence, with its original capture/freshness limitations.
- **Refresh public CVE intelligence**: request NVD, EPSS, and a final complete
  KEV catalog for the reported active CVE set.
- **Saved imports**: list the latest 100 imports and restore an import/assessment.

Database operations save the import and assessment to the configured database.
Only CVE identifiers go to public providers; internal hosts, ports, plugin output,
and original files are not sent to them. Existing optional `NVD_API_KEY` setup is
reused. Refresh is limited to 200 unique CVEs by default, with an explicit CLI
budget override. NVD's pacing/retries apply; larger imports remain previewable
without silently enriching only an arbitrary first subset.

Collection uses the shared ingestion lock. Each successful source is selected
atomically into a new frozen assessment; source failures retain previous cached
evidence or unknown values and expose sanitized failure categories. Scanner
imports do not overwrite the existing dashboard's latest tables. An assessment
records its decision time; opening an old assessment displays that frozen decision.
Reassess to apply current freshness checks.

Repeated imports with identical bytes, scanner, format, declared time override,
and synthetic status reuse the original saved import. Assessments remain separate
immutable versions. Refreshing the same saved import carries previous CVE decisions
and preserves the baseline downgrade guard. New imports start a new baseline;
cross-scan asset history and closure verification are later work. The existing
[priority review workflow](prioritization.md) explains evidence-bound downgrade
acknowledgements; this UI surfaces the guard without adding a review-approval editor.

## Command line and replay

An offline synthetic example:

```sh
uv run --locked python -m threatpulse.scan_worklist import \
  --scanner nessus --format xml \
  --input src/threatpulse/examples/scans/nessus.xml --synthetic \
  --intelligence src/threatpulse/examples/scans/intelligence.json \
  --decision-at 2026-01-10T12:00:00Z --output data/scan-demo
```

A real file, with optional database persistence and live enrichment:

```sh
uv run --locked python -m threatpulse.scan_worklist import \
  --scanner openvas --format csv --input YOUR_EXPORT.csv \
  --scanned-at 2026-11-11T10:00:00-05:00 \
  --save --enrich --max-cves 200 --output data/scan-review
```

Use the actual scan time. Omit `--save`/`--enrich` for local-only import; provide
`--intelligence SOURCE_JSON` for a frozen baseline dataset. Each output directory
must be new. Reports include original bytes, `scan.json`, `assessment.json`,
`intelligence.json`, full `worklist.json`/CSV, standalone HTML, and a file/code/package
checksum manifest. Local replay needs no database or network:

```sh
uv run --locked python -m threatpulse.scan_worklist replay \
  --scan data/scan-demo/scan.json --assessment data/scan-demo/assessment.json \
  --output data/scan-demo-replay
```

CSV output neutralizes spreadsheet-formula prefixes; the original strings remain
in JSON/source evidence. Treat scan artifacts as sensitive: they can contain
internal addresses and plugin output. Generated `data/` artifacts are gitignored.

## Limits and future adapters

Imports are bounded to 25 MiB, 100,000 normalized findings/relationships/services,
5,000 CVEs per finding, 500,000 XML nodes, and XML depth 128. Entity expansion and
external entity references are blocked; Nmap's ordinary harmless DOCTYPE is
accepted. Compressed archives and generic Nmap text/grepable output are unsupported.
Normalized evidence previews are capped at 20,000 characters; raw input is retained.
Reports load data into memory, so larger-scale streaming import remains future work.

The scanner/format registry and common asset/finding model allow additional
adapters for Qualys, Rapid7, Defender, Trivy, or Grype without changing the baseline
priority policy. Those formats are not implemented by this milestone. See
[decision 015](decisions/015-scanner-imports.md).
