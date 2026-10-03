# Decision: provide a read-only Streamlit view of collected intelligence

## Scope and choices

The pipeline now stores KEV, EPSS, and NVD data, but analysts need a visual way
to inspect them. Streamlit is the visualization technology planned in the
README, and it provides an interactive initial dashboard without adding a
separate API/frontend stack. Pandas supports display transformations and chart
data; database NUMERIC values remain unchanged, while displayed probabilities
are converted to explicitly labeled percentages.

The overview covers all stored CVEs: counts, score coverage, and severity
distribution including an unknown bucket. The explorer supports literal
case-insensitive search across CVE/vendor/product/name/description, vendor and
severity selections, a probability threshold, and explicit handling of missing
EPSS. CVE details show remediation, source context, references, all CVSS metrics,
and dated EPSS probability history. This step does not invent a prioritization
score, claim trend significance, or implement automation.

Complete CVE identifiers match the identifier exactly, rather than also finding
other vulnerabilities whose descriptions mention that CVE. Other searches
remain literal substring matches. A live search surfaced this ambiguity, so
the exact-identifier behavior has its own regression test.

## Query semantics and data access

Use left joins so CVEs without enrichment remain visible. A lateral query picks
the latest EPSS date per CVE rather than multiplying table rows or dropping
older-only observations. Latest score dates can differ across CVEs, so the date
range is visible. Numeric NULLs remain unknown; they are never silently scored
as zero. CVE detail queries bind the identifier as a SQL parameter.

Database operations use read-only transactions with bounded connection timeouts.
The app does not write data, migrate schemas, ingest, or require upstream API
keys. Every Streamlit rerun reloads the dataset; explicit refresh avoids stale
shared caches and credentials in cached keys. The initial KEV-sized dataset is
loaded in memory and filtered locally. Server-side pagination and indexed search
are future scaling work. Detail queries can observe a newer ingestion than the
table if collection runs concurrently; there is no dashboard-wide snapshot lock.

The documented service binds to loopback, with telemetry disabled. PostgreSQL
remains in Compose; Python/Streamlit run on the host for now. A deployed dashboard
container and remote hosting are separate work. Source descriptions, notes, and
reference URLs are rendered as plain text to preserve original content without
interpreting source markup. CVSS versions remain visible because their numerical
scores are not directly interchangeable.

## Tests and runtime validation

Move the isolated PostgreSQL connection fixture into `tests/conftest.py` so
storage and dashboard tests share the same schema isolation. Test latest-score
selection, missing enrichment, filters, literal search, detail queries, and
SQL parameterization with real PostgreSQL. Streamlit AppTest exercises metrics,
tables, searching, threshold controls, unknown scores, empty matches, and
missing-configuration/database-error messages.

A fixture failure exposed a generated local development connection password in
pytest diagnostics. That password was rotated, and dashboard connection fixture
representations now redact credentials. No API key or checked-in credential was
used in the diagnostic. The fixture was corrected to give its second record
distinct searchable text rather than unintentionally matching the first vendor.

Live validation uses the collected database: 1,733 CVEs, full current CVSS/EPSS
coverage, successful exact-CVE searching, and a two-date history view. The actual
Streamlit service also returns its health response and web application shell.
Browser interaction behavior is checked through AppTest rather than inferred
from an open port alone.

All 135 tests passed with real PostgreSQL integration enabled and no skips.
Ruff lint, formatting, and diff checks passed. Source and wheel distributions
built successfully. The database container was restarted with its rotated local
password and remained healthy with its persistent data intact.
