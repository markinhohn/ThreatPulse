"""Prospective, immutable NVD publication-cohort and KEV reference monitoring."""

import argparse
import base64
import hashlib
import json
import os
import sys
from contextlib import contextmanager
from datetime import UTC, date, datetime, time
from pathlib import Path
from typing import Literal
from uuid import NAMESPACE_URL, uuid4, uuid5

import httpx
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, Field, model_validator

from threatpulse.daily import IngestionBusyError, ingestion_lock
from threatpulse.epss import EPSS_URL, EpssBatch, EpssCollectionError, collect_epss
from threatpulse.kev import CISA_KEV_URL, KevCatalog, KevCollectionError, collect_kev
from threatpulse.models import parse_cisa_kev_record
from threatpulse.nvd import (
    NVD_URL,
    NvdBatch,
    NvdCollectionError,
    collect_nvd,
    collect_nvd_window,
)
from threatpulse.storage import migrate

MAX_DAILY_CVES = 20000
STAGES = ("discovery", "plan", "epss", "nvd", "final_kev")


def now():
    return datetime.now(UTC)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class EnrollmentDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    sampling: Literal["complete_publication_census"] = "complete_publication_census"
    eligibility_policy: Literal["non_kev_enrollment_v1"] = "non_kev_enrollment_v1"
    target: Literal["kev_inclusion_30d_v1"] = "kev_inclusion_30d_v1"
    minimum_followup_days: Literal[32] = 32
    published_start: date
    published_end: date
    max_records: int = Field(default=10000, gt=0)

    @model_validator(mode="after")
    def validate_window(self):
        if not 0 < (self.published_end - self.published_start).days <= 120:
            raise ValueError("Publication window must span 1–120 days")
        return self


def rows(connection, query, parameters=()):
    with connection.cursor(row_factory=dict_row) as cursor:
        return cursor.execute(query, parameters).fetchall()


def checkpoint(connection, run_id, stage):
    found = rows(
        connection,
        "SELECT * FROM tracking_checkpoints WHERE run_id = %s AND stage = %s",
        (run_id, stage),
    )
    return found[0] if found else None


@contextmanager
def recording_client(connection, attempt_id):
    """Persist request starts and exact public response bytes before parsing.

    No headers or authentication values are recorded. A crash leaves a request
    without a response, rather than a fabricated missing-CVE observation.
    """
    ordinal = 0

    def request_hook(request):
        nonlocal ordinal
        request_id = uuid4()
        request.extensions["tracking_request_id"] = request_id
        connection.execute(
            "INSERT INTO tracking_requests "
            "(request_id, attempt_id, ordinal, source_url, started_at) "
            "VALUES (%s,%s,%s,%s,%s)",
            (request_id, attempt_id, ordinal, str(request.url), now()),
        )
        ordinal += 1

    def response_hook(response):
        response.read()
        connection.execute(
            "INSERT INTO tracking_responses "
            "(request_id, received_at, status_code, body_sha256, body_base64) "
            "VALUES (%s,%s,%s,%s,%s)",
            (
                response.request.extensions["tracking_request_id"],
                now(),
                response.status_code,
                hashlib.sha256(response.content).hexdigest(),
                base64.b64encode(response.content).decode()
                if 200 <= response.status_code < 300
                else None,
            ),
        )

    with httpx.Client(
        event_hooks={"request": [request_hook], "response": [response_hook]}
    ) as client:
        yield client


def register(connection, ids, origin, timestamp):
    with connection.cursor() as cursor:
        cursor.executemany(
            "INSERT INTO tracking_registry (cve_id, first_seen_at, origin) "
            "VALUES (%s,%s,%s) ON CONFLICT (cve_id) DO NOTHING",
            [(cve, timestamp, origin) for cve in sorted(set(ids))],
        )


def historical_kev_ids(connection):
    return sorted(
        r[0]
        for r in connection.execute(
            "SELECT cve_id FROM kev_entries UNION SELECT cve_id FROM kev_snapshots "
            "UNION SELECT cve_id FROM tracking_observations "
            "WHERE source = 'kev' AND state = 'observed'"
        )
    )


def observations(connection, step):
    return rows(
        connection,
        "SELECT * FROM tracking_observations WHERE attempt_id = %s ORDER BY cve_id",
        (step["attempt_id"],),
    )


def historical_kev_evidence(connection, cutoff):
    """One frozen positive proof per CVE, preferring immutable new observations."""
    proofs = {
        row["cve_id"]: {
            "basis": "tracking_observation",
            "cve_id": row["cve_id"],
            "observation_id": row["observation_id"],
        }
        for row in rows(
            connection,
            "SELECT DISTINCT ON (cve_id) cve_id,observation_id "
            "FROM tracking_observations WHERE source='kev' AND state='observed' "
            "AND available_at <= %s "
            "ORDER BY cve_id,available_at DESC,observation_id DESC",
            (cutoff,),
        )
    }

    def retain(cve, source_url, captured, raw, basis):
        if cve in proofs:
            return
        _, entry = parse_cisa_kev_record(
            raw, source_url=source_url, ingested_at=captured
        )
        if entry.cve_id != cve or captured > cutoff or entry.date_added > cutoff.date():
            raise ValueError("Invalid historical KEV provenance")
        proofs[cve] = {
            "basis": basis,
            "cve_id": cve,
            "source_url": source_url,
            "captured_at": captured.isoformat(),
            "available_at": cutoff.isoformat(),
            "raw_record": raw,
            "raw_sha256": digest(raw),
        }

    for row in rows(
        connection,
        "SELECT cve_id,source_url,ingested_at,raw_record FROM kev_entries "
        "WHERE cve_id <> ALL(%s) ORDER BY cve_id",
        (sorted(proofs),),
    ):
        retain(
            row["cve_id"],
            row["source_url"],
            row["ingested_at"],
            row["raw_record"],
            "legacy_kev_entry_export",
        )
    for row in rows(
        connection,
        "SELECT DISTINCT ON (cve_id) cve_id,observation "
        "FROM kev_snapshots WHERE cve_id <> ALL(%s) ORDER BY cve_id,run_id DESC",
        (sorted(proofs),),
    ):
        entry = row["observation"]["kev"]
        retain(
            row["cve_id"],
            entry["source_url"],
            datetime.fromisoformat(entry["ingested_at"]),
            entry["raw_record"],
            "legacy_kev_snapshot_export",
        )
    return [proofs[cve] for cve in sorted(proofs)]


def validate_batch(batch, source, requested, started, available, definition):
    """Revalidate mutable model instances and exact coverage before committing."""
    model = {"kev": KevCatalog, "nvd": NvdBatch, "epss": EpssBatch}[source]
    batch = model.model_validate(batch.model_dump(mode="json"))
    records = batch.observations if source == "epss" else batch.records
    ids, entries = [], []
    for record in records:
        item = record.kev if source == "kev" else record
        ids.append(item.cve_id)
        if not started <= item.ingested_at <= available:
            raise ValueError("Capture timestamp outside this collection attempt")
        if source == "kev" and (
            record.vulnerability.cve_id != item.cve_id
            or item.date_added > available.date()
        ):
            raise ValueError("Invalid KEV provenance")
        if source == "nvd" and max(record.published_at, record.modified_at) > available:
            raise ValueError("Future NVD timestamp")
        if source == "epss" and record.score_date > available.date():
            raise ValueError("Future EPSS score date")
        entries.append((item, record))
    if len(ids) != len(set(ids)) or (source == "kev" and not ids):
        raise ValueError("Duplicate or empty catalog")
    if source == "epss" and len({record.score_date for _, record in entries}) > 1:
        raise ValueError("EPSS batch must use one source date")
    missing = [] if source == "kev" else batch.missing_cves
    if len(missing) != len(set(missing)) or set(missing) & set(ids):
        raise ValueError("Ambiguous source coverage")
    if requested is not None and set(ids) | set(missing) != set(requested):
        raise ValueError("Source coverage does not partition requested CVEs")
    if definition is not None:
        start = datetime.combine(definition.published_start, time(), tzinfo=UTC)
        end = datetime.combine(definition.published_end, time(), tzinfo=UTC)
        if (
            missing
            or len(ids) > definition.max_records
            or any(not start <= item.published_at < end for item, _ in entries)
        ):
            raise ValueError("Invalid or incomplete enrollment census")
    return entries, missing


def collect_step(
    connection, run, stage, source, requested, collect, *, definition=None
):
    existing = checkpoint(connection, run["run_id"], stage)
    if existing:
        return existing
    attempt_id, started = uuid4(), now()
    connection.execute(
        "INSERT INTO tracking_attempts "
        "(attempt_id, run_id, stage, requested_ids, started_at, status) "
        "VALUES (%s,%s,%s,%s,%s,'running')",
        (attempt_id, run["run_id"], stage, Jsonb(requested or []), started),
    )
    try:
        metadata = {}
        if stage == "final_kev":
            # Freeze what was already known before the final catalog fetch.
            metadata["historical_kev_evidence"] = historical_kev_evidence(
                connection, started
            )
            metadata["historical_kev_ids"] = [
                p["cve_id"] for p in metadata["historical_kev_evidence"]
            ]
        with recording_client(connection, attempt_id) as client:
            batch = collect(client)
        available = now()
        entries, missing = validate_batch(
            batch, source, requested, started, available, definition
        )
        available = now()
        values = []
        for item, record in entries:
            data = record.model_dump(mode="json")
            values.append(
                (
                    attempt_id,
                    source,
                    item.cve_id,
                    "observed",
                    item.ingested_at,
                    available,
                    str(item.source_url),
                    Jsonb(data),
                    digest(data),
                    digest(item.raw_record),
                )
            )
        source_url = {"kev": CISA_KEV_URL, "nvd": NVD_URL, "epss": EPSS_URL}[source]
        values.extend(
            (
                attempt_id,
                source,
                cve,
                "missing",
                available,
                available,
                source_url,
                None,
                None,
                None,
            )
            for cve in missing
        )
        with connection.transaction():
            register(
                connection,
                [item.cve_id for item, _ in entries],
                "kev" if source == "kev" else "nvd_window",
                available,
            )
            with connection.cursor() as cursor:
                cursor.executemany(
                    "INSERT INTO tracking_observations "
                    "(attempt_id,source,cve_id,state,captured_at,available_at,"
                    "source_url,observation,observation_sha256,raw_sha256) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    values,
                )
            metadata.update(
                observed=len(entries),
                missing=len(missing),
                complete_catalog=source == "kev",
                complete_publication_census=stage == "census",
            )
            if source == "epss":
                metadata["score_date"] = (
                    entries[0][0].score_date.isoformat() if entries else None
                )
            connection.execute(
                "INSERT INTO tracking_checkpoints "
                "(run_id,stage,attempt_id,available_at,metadata) "
                "VALUES (%s,%s,%s,%s,%s)",
                (run["run_id"], stage, attempt_id, available, Jsonb(metadata)),
            )
            connection.execute(
                "UPDATE tracking_attempts SET status='succeeded', finished_at=%s "
                "WHERE attempt_id=%s",
                (available, attempt_id),
            )
    except Exception as exc:
        connection.execute(
            "UPDATE tracking_attempts SET status='failed', finished_at=%s, "
            "error_type=%s WHERE attempt_id=%s",
            (now(), type(exc).__name__, attempt_id),
        )
        raise
    return checkpoint(connection, run["run_id"], stage)


def freeze_plan(connection, run, max_cves):
    if not checkpoint(connection, run["run_id"], "plan"):
        timestamp, attempt_id = now(), uuid4()
        legacy = historical_kev_ids(connection)
        ids = sorted(
            set(legacy)
            | {
                r[0]
                for r in connection.execute(
                    "SELECT cve_id FROM tracking_registry ORDER BY cve_id"
                )
            }
        )
        connection.execute(
            "INSERT INTO tracking_attempts "
            "(attempt_id,run_id,stage,requested_ids,started_at,status) "
            "VALUES (%s,%s,'plan',%s,%s,'running')",
            (attempt_id, run["run_id"], Jsonb(ids), timestamp),
        )
        try:
            if len(ids) > max_cves:
                raise ValueError("Tracking registry exceeds the daily request cap")
            with connection.transaction():
                register(connection, legacy, "legacy_kev", timestamp)
                with connection.cursor() as cursor:
                    cursor.executemany(
                        "INSERT INTO tracking_run_members VALUES (%s,%s)",
                        [(run["run_id"], cve) for cve in ids],
                    )
                available = now()
                connection.execute(
                    "INSERT INTO tracking_checkpoints VALUES (%s,'plan',%s,%s,%s)",
                    (
                        run["run_id"],
                        attempt_id,
                        available,
                        Jsonb({"requested": len(ids), "request_cap": max_cves}),
                    ),
                )
                connection.execute(
                    "UPDATE tracking_attempts SET status='succeeded', finished_at=%s "
                    "WHERE attempt_id=%s",
                    (available, attempt_id),
                )
        except Exception as exc:
            connection.execute(
                "UPDATE tracking_attempts SET status='failed', finished_at=%s, "
                "error_type=%s WHERE attempt_id=%s",
                (now(), type(exc).__name__, attempt_id),
            )
            raise
    return [
        r[0]
        for r in connection.execute(
            "SELECT cve_id FROM tracking_run_members WHERE run_id=%s ORDER BY cve_id",
            (run["run_id"],),
        )
    ]


def enrollment_reasons(record, cve_id, present, known):
    reasons = []
    if record["status"].casefold() == "rejected":
        reasons.append("REJECTED")
    if cve_id in present:
        reasons.append("CURRENT_KEV")
    elif cve_id in known:
        reasons.append("HISTORICAL_KEV")
    if cve_id not in known and any(
        record["raw_record"].get(key)
        for key in (
            "cisaExploitAdd",
            "cisaActionDue",
            "cisaRequiredAction",
            "cisaVulnerabilityName",
        )
    ):
        reasons.append("UNCONFIRMED_EXPLOITATION")
    return reasons


def finalize_enrollment(connection, run, census, final):
    present = {r["cve_id"] for r in observations(connection, final)}
    known = present | set(final["metadata"]["historical_kev_ids"])
    memberships = []
    for item in observations(connection, census):
        record = item["observation"]
        reasons = enrollment_reasons(record, item["cve_id"], present, known)
        memberships.append(
            (
                run["cohort_id"],
                item["cve_id"],
                item["observation_id"],
                final["attempt_id"],
                final["available_at"],
                "excluded" if reasons else "eligible",
                Jsonb(reasons),
            )
        )
    with connection.transaction():
        with connection.cursor() as cursor:
            cursor.executemany(
                "INSERT INTO tracking_memberships VALUES (%s,%s,%s,%s,%s,%s,%s)",
                memberships,
            )
        connection.execute(
            "UPDATE tracking_runs SET status='succeeded', finished_at=%s "
            "WHERE run_id=%s",
            (now(), run["run_id"]),
        )


def recover(connection):
    timestamp = now()
    for table in ("tracking_attempts", "tracking_runs"):
        # Table names are fixed literals, never user input.
        connection.execute(
            f"UPDATE {table} SET status='interrupted', finished_at=%s, "
            "error_type='ProcessInterrupted' WHERE status='running'",
            (timestamp,),
        )


def execute_run(connection, run, max_cves):
    """Caller holds the shared ingestion lock on an autocommit connection."""
    if run["status"] == "succeeded":
        return {"run_id": run["run_id"], "status": "already_succeeded"}
    connection.execute(
        "UPDATE tracking_runs SET status='running', finished_at=NULL, error_type=NULL "
        "WHERE run_id=%s",
        (run["run_id"],),
    )
    try:
        census = None
        if run["kind"] == "enrollment":
            definition = EnrollmentDefinition.model_validate(
                rows(
                    connection,
                    "SELECT definition FROM tracking_cohorts WHERE cohort_id=%s",
                    (run["cohort_id"],),
                )[0]["definition"]
            )
            census = collect_step(
                connection,
                run,
                "census",
                "nvd",
                None,
                lambda client: collect_nvd_window(
                    definition.published_start,
                    definition.published_end,
                    max_records=definition.max_records,
                    client=client,
                ),
                definition=definition,
            )
        collect_step(
            connection,
            run,
            "discovery",
            "kev",
            None,
            lambda client: collect_kev(client=client),
        )
        ids = freeze_plan(connection, run, max_cves)
        collect_step(
            connection,
            run,
            "epss",
            "epss",
            ids,
            lambda client: collect_epss(ids, client=client),
        )
        # The complete enrollment census already supplies these NVD versions.
        census_ids = (
            {r["cve_id"] for r in observations(connection, census)} if census else set()
        )
        remaining = sorted(set(ids) - census_ids)
        collect_step(
            connection,
            run,
            "nvd",
            "nvd",
            remaining,
            lambda client: collect_nvd(remaining, client=client),
        )
        final = collect_step(
            connection,
            run,
            "final_kev",
            "kev",
            None,
            lambda client: collect_kev(client=client),
        )
        if census:
            finalize_enrollment(connection, run, census, final)
        else:
            connection.execute(
                "UPDATE tracking_runs SET status='succeeded', finished_at=%s "
                "WHERE run_id=%s",
                (now(), run["run_id"]),
            )
    except Exception as exc:
        connection.execute(
            "UPDATE tracking_runs SET status='failed', finished_at=%s, error_type=%s "
            "WHERE run_id=%s",
            (now(), type(exc).__name__, run["run_id"]),
        )
        raise
    return {"run_id": run["run_id"], "status": "succeeded"}


def enroll(
    connection, definition, label="NVD publication cohort", *, max_cves=MAX_DAILY_CVES
):
    """Freeze an enrollment census; caller holds ingestion_lock."""
    if (
        not connection.autocommit
        or connection.info.transaction_status != psycopg.pq.TransactionStatus.IDLE
    ):
        raise ValueError("Tracking requires an idle autocommit connection")
    if type(max_cves) is not int or max_cves <= 0:
        raise ValueError("Request cap must be positive")
    timestamp = now()
    definition = EnrollmentDefinition.model_validate(definition.model_dump(mode="json"))
    if definition.published_end > timestamp.date():
        raise ValueError("Enrollment requires completed UTC publication days")
    recover(connection)
    data = definition.model_dump(mode="json")
    sha = digest(data)
    cohort_id = uuid5(NAMESPACE_URL, f"threatpulse:longitudinal:v1:{sha}")
    with connection.transaction():
        connection.execute(
            "INSERT INTO tracking_cohorts VALUES (%s,%s,%s,%s,%s) "
            "ON CONFLICT (cohort_id) DO NOTHING",
            (cohort_id, Jsonb(data), sha, label, timestamp),
        )
        connection.execute(
            "INSERT INTO tracking_runs "
            "(kind,cohort_id,run_date,started_at,status) "
            "VALUES ('enrollment',%s,%s,%s,'running') "
            "ON CONFLICT (cohort_id) WHERE kind='enrollment' DO NOTHING",
            (cohort_id, timestamp.date(), timestamp),
        )
    run = rows(
        connection, "SELECT * FROM tracking_runs WHERE cohort_id=%s", (cohort_id,)
    )[0]
    return {"cohort_id": str(cohort_id), **execute_run(connection, run, max_cves)}


def run_daily(connection, resume_run=None, *, max_cves=MAX_DAILY_CVES):
    """Observe today's frozen registry, or explicitly resume an existing run.

    No date parameter creates retrospective observations. Actual source times
    are retained even when a failed run is resumed on a later UTC day.
    """
    if (
        not connection.autocommit
        or connection.info.transaction_status != psycopg.pq.TransactionStatus.IDLE
    ):
        raise ValueError("Tracking requires an idle autocommit connection")
    if type(max_cves) is not int or max_cves <= 0:
        raise ValueError("Request cap must be positive")
    timestamp = now()
    recover(connection)
    if resume_run is None:
        if not connection.execute(
            "SELECT 1 FROM tracking_runs WHERE kind='enrollment' "
            "AND status='succeeded' LIMIT 1"
        ).fetchone():
            raise ValueError(
                "Enroll a defined publication cohort before daily tracking"
            )
        connection.execute(
            "INSERT INTO tracking_runs (kind,run_date,started_at,status) "
            "VALUES ('daily',%s,%s,'running') "
            "ON CONFLICT (run_date) WHERE kind='daily' DO NOTHING",
            (timestamp.date(), timestamp),
        )
        found = rows(
            connection,
            "SELECT * FROM tracking_runs WHERE kind='daily' AND run_date=%s",
            (timestamp.date(),),
        )
    else:
        found = rows(
            connection, "SELECT * FROM tracking_runs WHERE run_id=%s", (resume_run,)
        )
    if not found:
        raise ValueError("Run not found")
    return execute_run(connection, found[0], max_cves)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    enrollment = commands.add_parser("enroll")
    enrollment.add_argument("--published-start", type=date.fromisoformat, required=True)
    enrollment.add_argument("--published-end", type=date.fromisoformat, required=True)
    enrollment.add_argument("--max-records", type=int, default=10000)
    enrollment.add_argument("--label", default="NVD publication cohort")
    enrollment.add_argument("--max-cves", type=int, default=MAX_DAILY_CVES)
    daily = commands.add_parser("run")
    daily.add_argument("--resume-run", type=int)
    daily.add_argument("--max-cves", type=int, default=MAX_DAILY_CVES)
    export = commands.add_parser("export")
    export.add_argument("--output", type=Path, required=True)
    export.add_argument(
        "--input", type=Path, help="Replay a frozen tracking source.json"
    )
    args = parser.parse_args(argv)
    try:
        from threatpulse.tracking_report import read_dataset, write_report

        if args.command == "export" and args.input:
            result = write_report(json.loads(args.input.read_text()), args.output)
        else:
            url = os.environ.get("DATABASE_URL")
            if not url:
                raise ValueError("Set DATABASE_URL, or replay an export with --input")
            definition = (
                EnrollmentDefinition(
                    published_start=args.published_start,
                    published_end=args.published_end,
                    max_records=args.max_records,
                )
                if args.command == "enroll"
                else None
            )
            with psycopg.connect(
                url, autocommit=True, connect_timeout=10
            ) as connection:
                if args.command == "export":
                    with connection.transaction():
                        connection.execute(
                            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
                        )
                        dataset = read_dataset(connection)
                    result = write_report(dataset, args.output)
                else:
                    migrate(connection)
                    with ingestion_lock(connection):
                        result = (
                            enroll(
                                connection,
                                definition,
                                args.label,
                                max_cves=args.max_cves,
                            )
                            if definition
                            else run_daily(
                                connection, args.resume_run, max_cves=args.max_cves
                            )
                        )
        print(json.dumps(result, default=str))
        return 0
    except (
        psycopg.Error,
        httpx.HTTPError,
        IngestionBusyError,
        ValueError,
        OSError,
        RuntimeError,
        NvdCollectionError,
        EpssCollectionError,
        KevCollectionError,
        KeyError,
        TypeError,
    ) as exc:
        print(
            f"Tracking failed ({type(exc).__name__}). Check database/source access, "
            "definition, run ID, and output destination.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
