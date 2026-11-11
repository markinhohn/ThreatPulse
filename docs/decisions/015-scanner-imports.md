# 015 — Native scanner imports and an analyst review workspace

Status: implemented initial scanner adapters and worklist.

Add explicit scanner and format selection for Nessus XML/CSV, Greenbone/OpenVAS
XML/CSV, and Nmap XML. Normalize assets, service inventory, findings, CVE
references, scanner severity, evidence, remediation, and source timestamps.
Retain original input bytes and stable source locators. Multiple CVEs and repeated
rules aggregate into asset/CVE work items without losing their original findings.
Configuration, informational, and negative findings remain visible.

Keep scanner evidence distinct from CVE intelligence. Service fingerprints do not
prove applicability; NSE CVE references are candidates, with scoped negative states
excluded from active ranking. Do not guess vulnerabilities from open ports or
service names. Preserve scanner scores/versions and QoD rather than treating them
as calibrated probabilities. Automatic CPE/version matching remains planned.

Reuse the existing baseline priority engine for imported CVEs, with frozen inputs,
source outcomes, reasons, quality flags, and next actions. Unknown intelligence
remains UNDETERMINED. Cached or explicitly refreshed public intelligence can
enrich reports; only CVE identifiers leave for public APIs. Keep legacy dashboard
and longitudinal populations separate. Preserve the same-import downgrade guard;
do not infer closure from a later export's absence.

Migration 7 provides immutable source imports and assessment versions with checksums.
Preview, synthetic examples, and downloads work without PostgreSQL. The default
dashboard workspace guides users from scanner selection through a worklist; the
existing vulnerability-intelligence views remain accessible in the sidebar.
Use packaged synthetic native exports for a reproducible first demo.

Bound untrusted input size/structure, block XML entities, validate source formats,
escape displayed text, and neutralize CSV spreadsheet formulas. Preserve actual
scan times or explicit overrides; unknown times stay unknown. Test native profiles,
negative/candidate semantics, missing scores, immutable storage, offline replay,
fresh-process startup, and real-browser upload/download/save/restore flows.

Browser validation exposed a script-path collision between the project statistics
module and Python's standard library statistics import in Threat Velocity. Use
an exact rational median locally, retaining existing numeric behavior and testing
fresh-process imports under Streamlit's path arrangement.

See [the guide](../scan-imports.md). Further adapters, owner/status management,
service-to-CVE matching, and coverage-aware rescan comparison remain later work.
