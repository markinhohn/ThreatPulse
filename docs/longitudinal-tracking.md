# Prospective longitudinal cohort tracking

This implements the collection milestone from [the ML study design](ml-study-design.md).
It freezes a defined NVD non-KEV publication cohort alongside KEV reference CVEs.
It supplies source history for the next feature/label milestone; it does not
train a classifier, create prediction samples, or generate outcome labels.

## Enroll a publication census

Install the locked environment and configure `DATABASE_URL` as described in
[development](development.md). The existing optional `NVD_API_KEY` is strongly
recommended for larger cohorts. No additional credentials are required.

Choose a half-open publication interval at UTC midnight spanning 1–120 completed
days. The following example chooses November 8, excluding November 9, 2026:

```sh
uv run --locked python -m threatpulse.tracking enroll \
  --published-start 2026-11-08 --published-end 2026-11-09 \
  --max-records 1000 --label "November publication cohort"
```

The command applies migration 6 and prints stable cohort/run identifiers. It
collects every NVD page; `--max-records` is a rejection threshold, never a sample
size or truncation instruction. Equal definitions reuse the same cohort and
resume an incomplete enrollment. A completed enrollment is idempotent. Different
overlapping definitions retain separate membership records and share one global
CVE registry. The initial label is retained with the immutable definition.
Enrollment freezes records visible during collection; delayed NVD additions do
not retroactively enter a completed cohort. Pagination is not an atomic provider
snapshot: changed totals/duplicates are rejected, but equal-count concurrent
changes can remain undetected. Source/vendor/age coverage and these selection
effects must accompany later research results. Raw NVD configurations are retained
for later structured vendor/product analysis; no vendor features are inferred here.

All census CVEs are retained. Eligibility excludes Rejected records, confirmed
current/historical KEV, and unconfirmed positive NVD exploitation metadata.
Missing EPSS/CVSS does not remove an otherwise eligible member. Exclusion reasons
and source facts remain available. No source-score threshold chooses controls.
The registry also retains complete current KEV catalogs and historical KEV IDs
from existing storage as reference CVEs. These do not become new primary samples.

Research tables are separate from the existing KEV dashboard and comparison
studies. Enrollment/daily tracking does not change their population or upsert
their latest EPSS/NVD values. Continue the existing ingestion job for that app.

## Run daily monitoring

After at least one successful enrollment:

```sh
uv run --locked python -m threatpulse.tracking run
```

Each nominal UTC day has one recoverable daily run. A successful rerun performs
no collection. The run records its date once, even if collection crosses midnight.
It monitors all registered CVEs, including exclusions and KEV references, with
the following ordering:

1. Capture a complete CISA catalog to discover current reference CVEs.
2. Freeze the registry's exact requested CVE set.
3. Capture EPSS, pinning the whole batch to one actual provider score date.
4. Capture NVD versions, reusing the census on enrollment only.
5. Capture a second complete CISA catalog after the feature-source commits.

The final catalog's validated availability is the enrollment absence boundary.
The next milestone will define an actual index prediction after enrollment;
this collector does not invent past predictions. Original enrollment eligibility
is immutable. Later KEV inclusion remains in the daily source history rather
than deleting or relabeling the original member.

Source `captured_at` is the collector's batch timestamp. `available_at` is after
complete source validation; individual HTTP start/receipt times are also retained.
These clocks must be synchronized. Availability does not claim PostgreSQL had
already committed at that exact instant; feature-source commits precede the
final CISA request. NVD publication/modification and EPSS score dates remain
separate fields. Provider publication delays can yield an EPSS date before the
nominal run date. A later retry can return a newer score date, with its actual
availability recorded. Future dates and mixed-date batches are rejected.
Current source data cannot reconstruct earlier source versions.

Historical KEV exclusions also freeze their positive proofs. References to new
immutable observations are preferred; inherited legacy entries/snapshots retain
the original CISA record, capture/source provenance, and a canonical raw hash.
Their availability is conservatively bounded by this export into research
storage, rather than claimed to have been known on their original ingestion date.
The exact historical-positive set is frozen before the final catalog request.

A new KEV entry arriving between discovery and the final catalog is retained
immediately, with no fabricated EPSS/NVD request. Its feature coverage begins on
the next plan. New enrollments after a completed daily run likewise wait for the
next daily plan, in addition to their own enrollment captures.

The default request-plan cap is 20,000 registered CVEs. Use `--max-cves NUMBER`
on `enroll` or `run` to set an explicit budget. Exceeding the cap fails without
silently dropping CVEs; a larger cap can resume a failed planning step. A committed
plan is never expanded on retry. NVD refresh uses bulk KEV queries followed by
individual remaining-CVE lookups with existing pacing/retries. Each non-KEV lookup
costs roughly 0.65 seconds with a key, or 6.1 seconds without one, before network
latency/retries. Start with a narrow publication window and budget runtime/storage.
No random subsampling, concurrent NVD workers, or automatic cohort retirement is used.

## Failures and recovery

All ingestion commands share the existing PostgreSQL session lock. Overlap fails
before research collection; scheduler retries can run after the lock is released.
The Python `enroll`/`run_daily` APIs require an idle autocommit connection and the caller
to hold `ingestion_lock`, matching the existing ingestion API contract.

Validated observations and source checkpoint commit together. Earlier successful
steps survive a later failure and are skipped on retry. Failed source attempts
and interrupted requests remain visible. A successful empty response records
explicit per-CVE `missing`; transport errors, malformed responses, and stages
never attempted do not become missing values or zero probabilities.

The current day's run resumes automatically. An older run can be explicitly
repaired, including an incomplete enrollment:

```sh
uv run --locked python -m threatpulse.tracking run --resume-run RUN_ID
```

Actual later capture times and provider score dates are retained; a late retry
does not recreate past availability. No `--date`
or automatic historical backfill is supported. A new invocation marks abandoned
running attempts interrupted once it acquires the shared lock. If finalization
fails after the final catalog committed, retry uses that frozen baseline and
historical-positive set rather than later source knowledge.

## Optional systemd schedule

Templates are supplied in `deploy/systemd/threatpulse-tracking.*`. They run at
07:00 UTC (02:00 New York standard time; 03:00 during daylight saving), after
the existing dashboard ingestion timer. They retry failures after 15 minutes,
allow four starts per 12 hours, and have an eight-hour invocation limit. A
persistent timer runs once after downtime; it does not reconstruct missed days.

Follow [the existing service setup](scheduling.md) for installation, user,
`/opt/ThreatPulse`, and the protected `/etc/threatpulse/ingestion.env` file. Enroll
the chosen cohort first. Copy both tracking templates and enable explicitly:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now threatpulse-tracking.timer
systemctl list-timers threatpulse-tracking.timer
journalctl -u threatpulse-tracking.service
```

The repository does not activate a timer automatically. Configure service
`--max-cves` and timeout for the intended population. Monitor lock contention,
failed runs, and gaps; calendar scheduling alone does not prove successful daily
collection. Keep monitoring through at least the 30-day horizon plus two-day
latency window, and retain later observations for audit. There is no automatic
purge; write-protected history requires an explicit administrative retention policy.

## Export, inspect, and replay

```sh
uv run --locked python -m threatpulse.tracking export --output data/tracking
uv run --locked python -m threatpulse.tracking export \
  --input data/tracking/source.json --output data/tracking-replay
```

Database export is REPEATABLE READ, READ ONLY, without collection or migration.
Offline replay needs no database or network. Output directories must be new.

- `source.json`: complete definitions, registry, memberships, run/attempt history,
  frozen request plans, request/response journal, checkpoints, and observations.
- `analysis.json`: eligibility counts, source coverage, unanswered requests, daily
  dates without runs, catalog intervals exceeding 48 hours, and latest catalog age.
- `coverage.csv`: source states including explicit missing, failed, interrupted,
  and not attempted. Full-catalog/census request cardinality is unknown before
  collection, rather than reported as a zero-CVE request.
- `report.html`: standalone coverage overview and limitations.
- `manifest.json`: file/code/schema SHA-256 hashes and Python/package versions.

Successful public HTTP response bytes are stored as base64 with their exact byte
hash, even if later validation fails. Error response bodies and all headers are
omitted; errors store categories only. A request without a response is recorded
as unanswered, not an invented successful lookup. Normalized observations and
canonical raw records have separate hashes. Same-date EPSS revisions on different
captures remain separate rows; current-table upserts cannot rewrite them.

Offline validation checks hashes, source coverage partitions, enrollment
classifications, and provenance/time relationships. Original artifacts and the
locked environment support deterministic replay. SQL triggers reject ordinary
UPDATE, DELETE, and TRUNCATE of research evidence; database administrators can
disable them, so hashes/triggers do not authenticate the data's author.

Exports load all history and raw responses into memory. Keep initial cohorts
small; incremental/partitioned exports and scalable retention are later work.
The [synthetic fixture](../tests/fixtures/tracking_dataset.json) demonstrates
missing/zero scores, retained membership after KEV inclusion, request failures,
and catalog gaps without asserting real vulnerability findings. Replay it with
`--input tests/fixtures/tracking_dataset.json`. Coverage diagnostics do not produce labels: source gaps,
boundary censoring, mature negatives, first-index samples, temporal feature
construction, and model training remain explicit subsequent milestones.
