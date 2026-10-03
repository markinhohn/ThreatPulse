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
There are no application dependencies or running services yet.

To add a dependency, use `uv add <package>` (or `uv add --dev <package>`
for a development tool), and commit both `pyproject.toml` and `uv.lock`.

In a cloud environment where the default uv cache is read-only, set a writable
cache before running the commands above:

```bash
export UV_CACHE_DIR=/tmp/threatpulse-uv-cache
export UV_LINK_MODE=copy
```
