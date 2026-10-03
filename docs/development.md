# Python development

Install Python 3.12 and uv, then run these commands from the repository root:

```bash
uv sync --locked
uv run --locked pytest
uv run --locked ruff check .
uv run --locked ruff format --check .
```

`uv sync` installs the package in editable mode and includes development tools.
Application code belongs in `src/threatpulse/`; tests belong in `tests/`.
Pydantic validates the data models. There are no running services yet.

To add a dependency, use `uv add <package>` (or `uv add --dev <package>`
for a development tool), and commit both `pyproject.toml` and `uv.lock`.

In a cloud environment where the default uv cache is read-only, set a writable
cache before running the commands above:

```bash
export UV_CACHE_DIR=/tmp/threatpulse-uv-cache
export UV_LINK_MODE=copy
```

## Vulnerability data model

`Vulnerability` holds shared CVE attributes; `KevEntry` holds CISA remediation
fields and ingestion provenance. Parse one CISA catalog record with:

```python
from datetime import UTC, datetime

from threatpulse.models import parse_cisa_kev_record

vulnerability, kev_entry = parse_cisa_kev_record(
    record,  # One dictionary from the catalog's vulnerabilities array.
    source_url="https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
    ingested_at=datetime.now(UTC),
)
```

Invalid records raise `pydantic.ValidationError`. Required text is trimmed and
must be nonempty; CVE IDs use uppercase `CVE-YYYY-NNNN` with at least four
sequence digits. Dates must parse successfully. Ingestion timestamps must have
a timezone and are normalized to UTC. Ransomware use is `Known` or `Unknown`;
`Unknown` is not evidence that a vulnerability has never been used in ransomware.

The mapper retains a deep copy of the original record, including additional
source fields, without trimming its values. Notes are optional. Direct model
construction rejects unexpected fields to catch misspelled attributes. These
models do not fetch data or persist it; database uniqueness and history will be
implemented with storage.

## CISA KEV collector

Fetch and validate the official catalog:

```bash
uv run --locked python -m threatpulse.kev
```

Export normalized vulnerabilities, KEV observations, and original records:

```bash
mkdir -p data
uv run --locked python -m threatpulse.kev --output data/kev.json --timeout 30
```

The command prints the source URL and validated record count. Exports use a
new file; an existing destination is never overwritten. The `data/` directory
is ignored by Git. No database writes happen yet.

Requests retain TLS verification, follow redirects, and use a 30-second timeout
per network operation. Failures exit with status 1. Malformed JSON, invalid
records, empty catalogs, count mismatches, and duplicate CVEs reject the entire
batch rather than silently returning incomplete data. There are no automatic
retries; a caller or scheduler can rerun a failed collection.

The environment must allow HTTPS access to `raw.githubusercontent.com`. Tests use mock HTTP
responses and a synthetic CISA-format fixture, so they work without live access.

The collector reads CISA's official `cisagov/kev-data` GitHub publication.
The former `www.cisa.gov` endpoint returned an upstream HTTP 403 from this
cloud environment even after its network allowance was enabled. See
[the source decision](decisions/001-kev-catalog-source.md) for evidence,
tradeoffs, and the exact modifications.
