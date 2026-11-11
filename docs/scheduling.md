# Daily ingestion and recovery

Run from the installed repository with DATABASE_URL exported:

```bash
uv run --locked python -m threatpulse.storage ingest-daily
# Resume or collect an explicitly selected UTC day:
uv run --locked python -m threatpulse.storage ingest-daily --date 2026-01-01
```

The runner migrates automatically and collects KEV, EPSS, then NVD. EPSS uses
that exact score date. KEV and NVD always fetch current source data: `--date`
does not request historical KEV/NVD data. Never use it to claim a retrospective
source snapshot. The default date is captured once in UTC at invocation.

A PostgreSQL session advisory lock spans all collection and writes. All storage
CLI commands share it, including manual enrichment, so concurrent commands fail
with status 1 before collecting. The lock releases on exit or connection loss.
Direct Python storage functions and other API clients must coordinate separately;
the lock cannot pace unrelated clients sharing an NVD key or egress address.

Each source writes its latest tables, snapshots, and completed checkpoint in one
transaction. Earlier successful sources remain committed if a later source fails.
Rerun the same date to resume at the first incomplete source. Completed sources
are not refetched. A successful date returns `already_succeeded` without fetching.
Failure stores only the exception category, never driver connection details.
If the connection dies before failure recording, the run remains `running`;
the next lock holder marks unfinished runs interrupted, then resumes the selected
one. No elapsed-time guess or manual lock deletion is necessary. A resumed run
reuses its ID and resets its terminal status/error; journal logs retain individual
invocation failures. There is no automatic backfill of missed days.

## Install a daily systemd timer

The templates in `deploy/systemd/` run daily at **06:00 UTC**, with up to four
starts per 12 hours and a 15-minute delay after failure. Persistent timers run
once after downtime, not once for each missed date. The service has a four-hour
limit; interruption is recoverable on the next invocation. Retry windows crossing
UTC midnight target the new day; explicitly rerun an older date when needed.

1. Install the checkout in `/opt/ThreatPulse` and run `uv sync --locked` there.
2. Create a dedicated `threatpulse` service user with read/execute access to the
   checkout and its virtual environment. Adjust template paths/user if needed.
3. Create `/etc/threatpulse/ingestion.env`, readable by root only (mode 0600),
   containing `DATABASE_URL=...` and optional `NVD_API_KEY=...`. Python does not
   load the project's `.env`. Do not commit the credential file.
4. Copy the service and timer files into `/etc/systemd/system/`, then run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now threatpulse-ingest.timer
systemctl list-timers threatpulse-ingest.timer
sudo systemctl start threatpulse-ingest.service
journalctl -u threatpulse-ingest.service
```

After exhausting retries, correct the configuration/source failure, then use
`sudo systemctl reset-failed threatpulse-ingest.service` and start again. Disable
with `sudo systemctl disable --now threatpulse-ingest.timer`. Monitor failed units
and ingestion run status through your operations tooling. This repository does
not install or activate a host timer automatically.

Allow HTTPS to `raw.githubusercontent.com`, `api.first.org`, and
`services.nvd.nist.gov`. Keep NVD's existing pacing/retries and configure a key
where available. Missing enrichment results are reported in checkpoints and
count as successful collection, not zero scores or deletion of existing data.

## Inspect runs and historical observations

```sql
SELECT * FROM ingestion_runs ORDER BY id DESC LIMIT 20;
SELECT * FROM ingestion_steps ORDER BY run_id DESC, source;
SELECT r.run_date, r.status, s.cve_id, s.observation
FROM ingestion_runs r JOIN kev_snapshots s ON s.run_id = r.id
WHERE s.cve_id = 'CVE-2021-44228' ORDER BY r.id;
```

Migration 4 adds run tracking and KEV/NVD JSONB snapshots without changing existing
data. Each snapshot contains the normalized fetched record, original source JSON,
source URL, and ingestion timestamp. KEV also includes vulnerability attributes.
Snapshots describe observations made by the daily runner, not source revision
history, and have no automatic retention/deletion. Manual source commands keep
updating current tables without producing daily snapshots. Existing rows are not
backfilled with fabricated observation dates.

KEV snapshots contain exactly the validated catalog membership for that run;
latest KEV tables still retain absent CVEs for compatibility. Missing NVD CVEs
have no snapshot in that run and are listed in its checkpoint. A fetched stale
NVD record remains observable in history even when the latest-table freshness
guard rejects its overwrite. EPSS already retains history by score date.

Partial/failed runs may contain valid source snapshots; join with run status and
step completion before making cross-source comparisons. Resumption can collect
sources at different times, so a run is not a simultaneous snapshot. The dashboard
continues to use current tables and EPSS history. Database integration tests
require TEST_DATABASE_URL and exercise resume, crash recovery, snapshot retention,
rollback, and overlapping connections in isolated schemas.
