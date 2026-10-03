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
    source_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
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
