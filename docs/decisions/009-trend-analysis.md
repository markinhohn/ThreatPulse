# 009 — Historical vulnerability trend reports

Status: accepted.

The latest KEV and NVD tables cannot establish historical changes: they retain
absent KEV entries, and NVD freshness guards can suppress stale writes. Use
immutable daily KEV/NVD snapshots and committed source checkpoints instead.
Use one consistent read-only export, preserving provenance and recovery state.
No schema migration or collection changes are required.

Set differences between adjacent full KEV captures establish observed membership
events. The first selected capture is a baseline; preserve CISA dateAdded and
flag reappearances without claiming exact exploitation dates. NVD comparisons
require adjacent-capture overlap and separate coverage from severity. Numeric
changes require the same preferred CVSS version/source/type, non-Rejected status,
and no source modification-time regression. Other transitions retain both
metrics but no cross-version or cross-source numeric delta.

EPSS uses a fixed export-time cohort with a daily coverage calendar, explicit
gaps, available-score summaries, and a complete panel across nonempty dates.
Matched interval deltas retain missingness and elapsed days. Missing values are
never filled or treated as zero. Lines break at whole missing dates; individual
histories also break at per-CVE gaps. Balanced-panel selection is explicit and
does not resolve all missingness or selection bias.

Standalone HTML, CSV, SVG/PNG, frozen JSON, and hash/version manifests support
offline replay. Deterministic serialization and plotting metadata allow exact
replay in the same environment. A bounded calendar window limits generated
output, but full source history currently resides in memory. This is descriptive
analysis; statistical testing and Threat Velocity remain separate roadmap work.
