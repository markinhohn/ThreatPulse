"""Prospective cohort capture, immutable SQL history, recovery, and offline replay."""

import base64
import copy
import hashlib
import json
import os
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import httpx
import psycopg
import pytest
from psycopg import sql
from psycopg.types.json import Jsonb

from threatpulse import epss, kev, nvd, tracking
from threatpulse.daily import IngestionBusyError, ingestion_lock
from threatpulse.kev import CISA_KEV_URL
from threatpulse.storage import ingest_catalog, migrate
from threatpulse.tracking import EnrollmentDefinition, enroll, main, run_daily
from threatpulse.tracking_report import (
    read_dataset,
    summarize,
    validate_dataset,
    write_report,
)

ROOT = Path(__file__).parents[1]
A, B, C, D, E, F, G = [f"CVE-2026-{1001 + i}" for i in range(7)]
DEFINITION = EnrollmentDefinition(
    published_start=date(2026, 1, 1), published_end=date(2026, 1, 2)
)


class Sources:
    def __init__(self):
        self.current = datetime(2026, 1, 10, 12, tzinfo=UTC)
        self.window_ids = [A, B, C, D, E, F]
        self.kev_ids = [B, G]
        self.missing_epss = {A}
        self.missing_nvd = set()
        self.probability = "0.20"
        self.provider_date = None
        self.calls = []
        self.failure = None
        self.nvd_raw = json.loads((ROOT / "tests/fixtures/nvd_cve.json").read_text())
        self.kev_raw = json.loads(
            (ROOT / "tests/fixtures/cisa_kev_record.json").read_text()
        )

    def now(self):
        result = self.current
        self.current += timedelta(seconds=1)
        return result

    def raw_nvd(self, cve):
        raw = copy.deepcopy(self.nvd_raw)
        raw.update(
            id=cve,
            published="2026-01-01T00:00:00.000",
            lastModified="2026-01-02T00:00:00.000",
        )
        raw.pop("cisaExploitAdd", None)
        raw.pop("cisaActionDue", None)
        raw.pop("cisaRequiredAction", None)
        raw.pop("cisaVulnerabilityName", None)
        if cve == A:
            raw["metrics"] = {}
        if cve == C:
            raw["vulnStatus"] = "Rejected"
        if cve == D:
            raw["cisaExploitAdd"] = "2026-01-01"
        return raw

    def raw_kev(self, cve):
        return self.kev_raw | {
            "cveID": cve,
            "dateAdded": "2026-01-01",
            "dueDate": "2026-02-01",
        }

    def handle(self, request):
        if request.url.host == "raw.githubusercontent.com":
            stage = "kev"
            payload = {
                "count": len(self.kev_ids),
                "vulnerabilities": [self.raw_kev(c) for c in self.kev_ids],
            }
        elif request.url.host == "api.first.org":
            stage = "epss"
            ids = request.url.params["cve"].split(",")
            data = [
                {
                    "cve": c,
                    "date": request.url.params.get(
                        "date", self.provider_date or self.current.date().isoformat()
                    ),
                    "epss": "0" if c == F else self.probability,
                    "percentile": "0.5",
                }
                for c in ids
                if c not in self.missing_epss
            ]
            payload = {"status": "OK", "total": len(data), "offset": 0, "data": data}
        else:
            stage = "census" if "pubStartDate" in request.url.params else "nvd"
            ids = (
                self.window_ids
                if stage == "census"
                else [request.url.params["cveId"]]
                if "cveId" in request.url.params
                else self.kev_ids
            )
            data = [{"cve": self.raw_nvd(c)} for c in ids if c not in self.missing_nvd]
            payload = {
                "totalResults": len(data),
                "startIndex": 0,
                "resultsPerPage": len(data),
                "vulnerabilities": data,
            }
        self.calls.append(stage)
        if self.failure == ("http", stage):
            return httpx.Response(503, text="do-not-log-credential")
        if self.failure == ("invalid", stage):
            return httpx.Response(200, content=b"not-json")
        if self.failure == stage:
            # This secret-like text must never enter stored exception categories.
            raise httpx.ConnectError("do-not-log-credential", request=request)
        return httpx.Response(200, json=payload)


@pytest.fixture
def sources(connection, monkeypatch):
    migrate(connection)
    source = Sources()
    monkeypatch.setattr(tracking, "now", source.now)

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return source.now()

    for module in (nvd, epss, kev):
        monkeypatch.setattr(module, "datetime", FrozenDatetime)
    original_client = httpx.Client
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: original_client(
            transport=httpx.MockTransport(source.handle), **kwargs
        ),
    )
    original_window, original_nvd = nvd.collect_nvd_window, nvd.collect_nvd
    monkeypatch.setattr(
        tracking,
        "collect_nvd_window",
        lambda *a, **k: original_window(
            *a, **k, api_key="unit-test-api-key", sleep=lambda _: None
        ),
    )
    monkeypatch.setattr(
        tracking,
        "collect_nvd",
        lambda *a, **k: original_nvd(
            *a, **k, api_key="unit-test-api-key", sleep=lambda _: None
        ),
    )
    # Retained historical KEV evidence must exclude E despite current absence.
    vulnerability, entry = kev.parse_cisa_kev_record(
        source.raw_kev(E), source_url=CISA_KEV_URL, ingested_at=source.now()
    )
    ingest_catalog(
        connection,
        kev.KevCatalog(
            records=[kev.CollectedVulnerability(vulnerability=vulnerability, kev=entry)]
        ),
    )
    return source


def capture(connection, sources):
    with ingestion_lock(connection):
        return enroll(connection, DEFINITION, "Synthetic publication cohort")


def export(connection, sources):
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        payload = read_dataset(connection)
    payload["captured_at"] = sources.current.isoformat()
    return payload


def test_enrollment_census_exclusions_missingness_order_and_separation(
    connection, sources
):
    result = capture(connection, sources)
    assert result["status"] == "succeeded"
    members = connection.execute(
        "SELECT cve_id,eligibility,exclusion_reasons "
        "FROM tracking_memberships ORDER BY cve_id"
    ).fetchall()
    assert members == [
        (A, "eligible", []),
        (B, "excluded", ["CURRENT_KEV"]),
        (C, "excluded", ["REJECTED"]),
        (D, "excluded", ["UNCONFIRMED_EXPLOITATION"]),
        (E, "excluded", ["HISTORICAL_KEV"]),
        (F, "eligible", []),
    ]
    assert connection.execute("SELECT count(*) FROM tracking_registry").fetchone() == (
        7,
    )
    assert connection.execute("SELECT count(*) FROM vulnerabilities").fetchone() == (1,)
    assert connection.execute("SELECT count(*) FROM epss_observations").fetchone() == (
        0,
    )
    assert connection.execute("SELECT count(*) FROM nvd_enrichments").fetchone() == (0,)
    assert sources.calls[0:3] == ["census", "kev", "epss"]
    assert sources.calls[-1] == "kev"
    payload = export(connection, sources)
    validate_dataset(payload)
    snapshots = payload["tables"]["observations"]
    assert any(
        r["cve_id"] == A and r["source"] == "epss" and r["state"] == "missing"
        for r in snapshots
    )
    assert any(
        r["cve_id"] == F and r["source"] == "epss" and r["observation"]["epss"] == "0"
        for r in snapshots
    )
    assert "unit-test-api-key" not in json.dumps(payload)
    assert payload["tables"]["responses"]
    assert all(r["body_base64"] for r in payload["tables"]["responses"])
    final = next(
        s for s in payload["tables"]["checkpoints"] if s["stage"] == "final_kev"
    )
    proof = next(
        p for p in final["metadata"]["historical_kev_evidence"] if p["cve_id"] == E
    )
    assert proof["basis"] == "legacy_kev_entry_export"
    assert proof["raw_record"]["cveID"] == E
    prior_calls = list(sources.calls)
    assert capture(connection, sources)["status"] == "already_succeeded"
    assert sources.calls == prior_calls


def test_daily_revisions_preserve_enrollment_and_membership_after_kev_addition(
    connection, sources
):
    capture(connection, sources)
    original = connection.execute(
        "SELECT observation_sha256 FROM tracking_observations ORDER BY observation_id"
    ).fetchall()
    baseline = connection.execute(
        "SELECT * FROM tracking_memberships ORDER BY cve_id"
    ).fetchall()
    sources.current += timedelta(days=1)
    sources.probability = "0.8"
    sources.provider_date = "2026-01-10"
    sources.kev_ids.append(A)
    sources.missing_nvd.add(F)
    with ingestion_lock(connection):
        daily = run_daily(connection)
        assert run_daily(connection)["status"] == "already_succeeded"
    assert (
        connection.execute(
            "SELECT * FROM tracking_memberships ORDER BY cve_id"
        ).fetchall()
        == baseline
    )
    assert (
        connection.execute(
            "SELECT observation_sha256 FROM tracking_observations "
            "ORDER BY observation_id LIMIT %s",
            (len(original),),
        ).fetchall()
        == original
    )
    assert connection.execute(
        "SELECT count(*) FROM tracking_observations WHERE cve_id=%s AND source='kev'",
        (A,),
    ).fetchone() == (2,)
    assert connection.execute(
        "SELECT count(*) FROM tracking_observations "
        "WHERE source='nvd' AND cve_id=%s AND state='missing'",
        (F,),
    ).fetchone() == (1,)
    points = connection.execute(
        "SELECT observation->>'epss' FROM tracking_observations "
        "WHERE source='epss' AND cve_id=%s ORDER BY available_at",
        (B,),
    ).fetchall()
    assert points == [("0.20",), ("0.8",)]
    assert connection.execute(
        "SELECT DISTINCT observation->>'score_date' FROM tracking_observations "
        "WHERE source='epss' AND cve_id=%s",
        (B,),
    ).fetchall() == [("2026-01-10",)]
    assert daily["status"] == "succeeded"
    validate_dataset(export(connection, sources))


def test_overlap_windows_deduplicate_global_registry_but_preserve_memberships(
    connection, sources
):
    first = capture(connection, sources)
    overlapping = DEFINITION.model_copy(update={"published_end": date(2026, 1, 3)})
    with ingestion_lock(connection):
        second = enroll(connection, overlapping)
    assert first["cohort_id"] != second["cohort_id"]
    assert connection.execute("SELECT count(*) FROM tracking_registry").fetchone() == (
        7,
    )
    assert connection.execute(
        "SELECT count(*) FROM tracking_memberships"
    ).fetchone() == (12,)
    validate_dataset(export(connection, sources))


def test_historical_kev_proof_can_be_frozen_from_legacy_snapshot(connection, sources):
    vulnerability, entry = kev.parse_cisa_kev_record(
        sources.raw_kev(E),
        source_url=CISA_KEV_URL,
        ingested_at=sources.now(),
    )
    run_id = connection.execute(
        "INSERT INTO ingestion_runs(run_date,status) "
        "VALUES ('2026-01-09','succeeded') RETURNING id"
    ).fetchone()[0]
    data = kev.CollectedVulnerability(
        vulnerability=vulnerability, kev=entry
    ).model_dump(mode="json")
    connection.execute(
        "INSERT INTO kev_snapshots VALUES (%s,%s,%s)", (run_id, E, Jsonb(data))
    )
    connection.execute("DELETE FROM kev_entries WHERE cve_id=%s", (E,))
    capture(connection, sources)
    payload = export(connection, sources)
    final = next(
        s for s in payload["tables"]["checkpoints"] if s["stage"] == "final_kev"
    )
    proof = next(
        p for p in final["metadata"]["historical_kev_evidence"] if p["cve_id"] == E
    )
    assert proof["basis"] == "legacy_kev_snapshot_export"
    validate_dataset(payload)


def test_failure_recovery_skips_committed_steps_and_retains_request_attempts(
    connection, sources
):
    sources.failure = "epss"
    with pytest.raises(epss.EpssCollectionError):
        capture(connection, sources)
    before = list(sources.calls)
    assert before == ["census", "kev", "epss"]
    sources.failure = None
    assert capture(connection, sources)["status"] == "succeeded"
    assert sources.calls[: len(before)] == before
    assert sources.calls[len(before)] == "epss"
    assert sources.calls.count("census") == 1
    assert sources.calls.count("kev") == 2
    attempts = connection.execute(
        "SELECT status,error_type FROM tracking_attempts "
        "WHERE stage='epss' ORDER BY started_at"
    ).fetchall()
    assert attempts == [("failed", "EpssCollectionError"), ("succeeded", None)]
    payload = export(connection, sources)
    assert summarize(payload)["unanswered_requests"] == 1
    assert "do-not-log-credential" not in json.dumps(payload)


def test_interrupted_attempt_recovery_and_atomic_source_rollback(connection, sources):
    connection.execute(
        "ALTER TABLE tracking_observations ADD CONSTRAINT reject_epss "
        "CHECK (source <> 'epss')"
    )
    with pytest.raises(psycopg.errors.CheckViolation):
        capture(connection, sources)
    assert connection.execute(
        "SELECT count(*) FROM tracking_checkpoints WHERE stage='epss'"
    ).fetchone() == (0,)
    assert connection.execute(
        "SELECT count(*) FROM tracking_observations WHERE source='epss'"
    ).fetchone() == (0,)
    connection.execute("ALTER TABLE tracking_observations DROP CONSTRAINT reject_epss")
    # Model a process dying after the next attempt was started.
    original = tracking.collect_epss

    def crash(*args, **kwargs):
        raise KeyboardInterrupt()

    sources_calls = sources.calls.count("census")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(tracking, "collect_epss", crash)
        with pytest.raises(KeyboardInterrupt):
            capture(connection, sources)
    assert tracking.collect_epss is original
    capture(connection, sources)
    assert sources.calls.count("census") == sources_calls
    assert connection.execute(
        "SELECT count(*) FROM tracking_attempts WHERE status='interrupted'"
    ).fetchone() == (1,)


@pytest.mark.parametrize("mode", ["date", "duplicates", "coverage", "future_nvd"])
def test_invalid_source_batch_cannot_publish_a_checkpoint(
    connection, sources, monkeypatch, mode
):
    original_epss, original_nvd = tracking.collect_epss, tracking.collect_nvd

    def corrupt_epss(*args, **kwargs):
        batch = original_epss(*args, **kwargs)
        if mode == "date":
            batch.observations[0].score_date += timedelta(days=2)
        elif mode == "duplicates":
            batch.observations.append(batch.observations[0])
        elif mode == "coverage":
            batch.missing_cves = []
        return batch

    def corrupt_nvd(*args, **kwargs):
        batch = original_nvd(*args, **kwargs)
        batch.records[0].modified_at = sources.current + timedelta(days=1)
        return batch

    monkeypatch.setattr(tracking, "collect_epss", corrupt_epss)
    if mode == "future_nvd":
        monkeypatch.setattr(tracking, "collect_nvd", corrupt_nvd)
    with pytest.raises(ValueError):
        capture(connection, sources)
    stage = "nvd" if mode == "future_nvd" else "epss"
    assert connection.execute(
        "SELECT count(*) FROM tracking_checkpoints WHERE stage=%s", (stage,)
    ).fetchone() == (0,)
    assert connection.execute(
        "SELECT count(*) FROM tracking_checkpoints WHERE stage='final_kev'"
    ).fetchone() == (0,)


@pytest.mark.parametrize("failure", [("http", "kev"), ("invalid", "kev")])
def test_invalid_catalog_never_establishes_absence_and_preserves_request_evidence(
    connection, sources, failure
):
    sources.failure = failure
    with pytest.raises(kev.KevCollectionError):
        capture(connection, sources)
    assert connection.execute(
        "SELECT count(*) FROM tracking_memberships"
    ).fetchone() == (0,)
    status, body = connection.execute(
        "SELECT status_code,body_base64 FROM tracking_responses "
        "ORDER BY received_at DESC LIMIT 1"
    ).fetchone()
    assert (
        (status, body) == (503, None)
        if failure[0] == "http"
        else (status == 200 and base64.b64decode(body) == b"not-json")
    )
    assert "do-not-log-credential" not in json.dumps(export(connection, sources))


def test_finalization_retry_reuses_frozen_boundary_without_later_evidence_leakage(
    connection, sources
):
    connection.execute(
        "ALTER TABLE tracking_memberships ADD CONSTRAINT block_finalization "
        "CHECK(false)"
    )
    with pytest.raises(psycopg.errors.CheckViolation):
        capture(connection, sources)
    boundary = connection.execute(
        "SELECT available_at FROM tracking_checkpoints WHERE stage='final_kev'"
    ).fetchone()[0]
    original_calls = list(sources.calls)
    connection.execute(
        "ALTER TABLE tracking_memberships DROP CONSTRAINT block_finalization"
    )
    sources.current += timedelta(days=3)
    vulnerability, entry = kev.parse_cisa_kev_record(
        sources.raw_kev(A), source_url=CISA_KEV_URL, ingested_at=sources.now()
    )
    ingest_catalog(
        connection,
        kev.KevCatalog(
            records=[kev.CollectedVulnerability(vulnerability=vulnerability, kev=entry)]
        ),
    )
    capture(connection, sources)
    assert sources.calls == original_calls
    assert connection.execute(
        "SELECT eligibility,baseline_at FROM tracking_memberships WHERE cve_id=%s", (A,)
    ).fetchone() == ("eligible", boundary)
    validate_dataset(export(connection, sources))


@pytest.mark.parametrize(
    "table,column",
    [
        ("tracking_cohorts", "label"),
        ("tracking_registry", "origin"),
        ("tracking_observations", "state"),
        ("tracking_checkpoints", "stage"),
        ("tracking_requests", "source_url"),
        ("tracking_responses", "body_sha256"),
        ("tracking_run_members", "cve_id"),
        ("tracking_memberships", "eligibility"),
    ],
)
def test_sql_history_rejects_update_delete_and_truncate(
    connection, sources, table, column
):
    capture(connection, sources)
    for query in (
        sql.SQL("UPDATE {} SET {}={}").format(
            sql.Identifier(table), sql.Identifier(column), sql.Identifier(column)
        ),
        sql.SQL("DELETE FROM {}").format(sql.Identifier(table)),
        sql.SQL("TRUNCATE {} CASCADE").format(sql.Identifier(table)),
    ):
        with (
            pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState),
            connection.transaction(),
        ):
            connection.execute(query)


def test_shared_lock_and_explicit_request_cap(connection, sources):
    with psycopg.connect(os.environ["TEST_DATABASE_URL"], autocommit=True) as other:
        with ingestion_lock(other):
            with pytest.raises(IngestionBusyError), ingestion_lock(connection):
                pass
    with ingestion_lock(connection):
        with pytest.raises(ValueError, match="request cap"):
            enroll(connection, DEFINITION, max_cves=1)
        assert enroll(connection, DEFINITION, max_cves=10)["status"] == "succeeded"
    assert sources.calls.count("census") == 1
    assert connection.execute(
        "SELECT status FROM tracking_attempts WHERE stage='plan' ORDER BY started_at"
    ).fetchall() == [("failed",), ("succeeded",)]


def test_collection_rejects_outer_transaction_to_preserve_source_commit_boundaries(
    connection, sources
):
    with ingestion_lock(connection), connection.transaction():
        with pytest.raises(ValueError, match="idle autocommit"):
            enroll(connection, DEFINITION)
    assert sources.calls == []


def test_over_cap_census_and_invalid_windows_are_not_truncated(connection, sources):
    with ingestion_lock(connection):
        with pytest.raises(nvd.NvdCollectionError, match="exceeds"):
            enroll(connection, DEFINITION.model_copy(update={"max_records": 1}))
    assert connection.execute(
        "SELECT count(*) FROM tracking_memberships"
    ).fetchone() == (0,)
    assert connection.execute(
        "SELECT count(*) FROM tracking_observations"
    ).fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM tracking_responses").fetchone() == (
        1,
    )
    for start, end in (
        (date(2026, 1, 2), date(2026, 1, 2)),
        (date(2025, 1, 1), date(2026, 1, 1)),
    ):
        with pytest.raises(ValueError):
            EnrollmentDefinition(published_start=start, published_end=end)
    with pytest.raises(ValueError, match="completed UTC"):
        enroll(
            connection,
            DEFINITION.model_copy(update={"published_end": date(2026, 1, 11)}),
        )


def test_resume_on_later_day_retains_real_times_and_provider_epss_date(
    connection, sources
):
    sources.failure = "epss"
    with pytest.raises(epss.EpssCollectionError):
        capture(connection, sources)
    run_id = connection.execute("SELECT run_id FROM tracking_runs").fetchone()[0]
    sources.current += timedelta(days=3)
    sources.failure = None
    with ingestion_lock(connection):
        run_daily(connection, resume_run=run_id)
    score_date, captured = connection.execute(
        "SELECT observation->>'score_date',available_at "
        "FROM tracking_observations WHERE source='epss' LIMIT 1"
    ).fetchone()
    assert score_date == "2026-01-13"
    assert captured.date() == date(2026, 1, 13)
    assert all(
        m[0].date() == date(2026, 1, 13)
        for m in connection.execute("SELECT baseline_at FROM tracking_memberships")
    )


def test_daily_date_frozen_once_at_midnight(connection, sources):
    capture(connection, sources)
    sources.current = datetime(2026, 1, 10, 23, 59, 59, tzinfo=UTC)
    with ingestion_lock(connection):
        result = run_daily(connection)
    assert connection.execute(
        "SELECT run_date FROM tracking_runs WHERE run_id=%s", (result["run_id"],)
    ).fetchone() == (date(2026, 1, 10),)


def test_new_kevs_after_plan_remain_visible_without_fabricated_feature_coverage(
    connection, sources, monkeypatch
):
    capture(connection, sources)
    sources.current += timedelta(days=1)
    original = tracking.collect_nvd
    new = "CVE-2026-9999"

    def late_kev(*args, **kwargs):
        batch = original(*args, **kwargs)
        sources.kev_ids.append(new)
        return batch

    monkeypatch.setattr(tracking, "collect_nvd", late_kev)
    with ingestion_lock(connection):
        result = run_daily(connection)
    assert connection.execute(
        "SELECT count(*) FROM tracking_registry WHERE cve_id=%s", (new,)
    ).fetchone() == (1,)
    assert connection.execute(
        "SELECT count(*) FROM tracking_run_members WHERE run_id=%s AND cve_id=%s",
        (result["run_id"], new),
    ).fetchone() == (0,)
    assert connection.execute(
        "SELECT source FROM tracking_observations WHERE cve_id=%s", (new,)
    ).fetchall() == [("kev",)]


def test_export_replays_exactly_with_hashes_and_coverage_gaps(
    connection, sources, tmp_path
):
    capture(connection, sources)
    sources.current += timedelta(days=4)
    with ingestion_lock(connection):
        run_daily(connection)
    payload = export(connection, sources)
    result = summarize(payload)
    assert result["registry_cves"] == 7
    assert result["cohorts"][0]["eligible"] == 2
    assert len(result["daily_dates_without_run"]) == 4
    assert result["catalog_gaps_over_48h"]
    assert not result["labels_generated"]
    first, second = tmp_path / "first", tmp_path / "second"
    write_report(payload, first)
    assert (
        main(["export", "--input", str(first / "source.json"), "--output", str(second)])
        == 0
    )
    for file in first.iterdir():
        assert file.read_bytes() == (second / file.name).read_bytes()
    manifest = json.loads((first / "manifest.json").read_text())
    for file, sha in manifest["files_sha256"].items():
        assert hashlib.sha256((first / file).read_bytes()).hexdigest() == sha
    with pytest.raises(FileExistsError):
        write_report(payload, first)


@pytest.mark.parametrize(
    "corruption",
    [
        "raw_response",
        "observation",
        "definition",
        "boundary",
        "eligibility",
        "counts",
        "legacy_kev_proof",
    ],
)
def test_offline_export_rejects_corrupted_evidence(connection, sources, corruption):
    capture(connection, sources)
    payload = export(connection, sources)
    tables = payload["tables"]
    if corruption == "raw_response":
        tables["responses"][0]["body_base64"] = base64.b64encode(b"changed").decode()
    elif corruption == "observation":
        tables["observations"][0]["observation"]["status"] = "Changed"
    elif corruption == "definition":
        tables["cohorts"][0]["definition"]["max_records"] = 100
    elif corruption == "boundary":
        tables["memberships"][0]["baseline_at"] = "2026-01-01T00:00:00Z"
    elif corruption == "eligibility":
        tables["memberships"][0]["eligibility"] = "excluded"
    elif corruption == "counts":
        tables["checkpoints"][0]["metadata"]["observed"] = 99
    else:
        final = next(s for s in tables["checkpoints"] if s["stage"] == "final_kev")
        final["metadata"]["historical_kev_evidence"] = []
    with pytest.raises(ValueError):
        validate_dataset(payload)


def test_cli_missing_database_and_source_errors_are_redacted(
    connection, sources, monkeypatch, capsys
):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert main(["run"]) == 1
    assert "ValueError" in capsys.readouterr().err
    schema = connection.execute("SELECT current_schema()").fetchone()[0]
    original_connect = psycopg.connect
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr(
        psycopg,
        "connect",
        lambda *a, **kw: original_connect(*a, **kw, options=f"-c search_path={schema}"),
    )
    sources.failure = "epss"
    assert (
        main(
            [
                "enroll",
                "--published-start",
                "2026-01-01",
                "--published-end",
                "2026-01-02",
            ]
        )
        == 1
    )
    assert "do-not-log-credential" not in capsys.readouterr().err


def test_empty_export_has_explicit_schema_and_requires_enrollment(
    connection, sources, tmp_path
):
    with ingestion_lock(connection):
        with pytest.raises(ValueError, match="Enroll"):
            run_daily(connection)
    payload = export(connection, sources)
    assert summarize(payload)["registry_cves"] == 0
    write_report(payload, tmp_path / "empty")
    assert (tmp_path / "empty" / "coverage.csv").read_text().startswith("run_id,")


def test_public_synthetic_fixture_replays_without_database(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    source = ROOT / "tests/fixtures/tracking_dataset.json"
    assert (
        main(["export", "--input", str(source), "--output", str(tmp_path / "demo")])
        == 0
    )
    result = json.loads((tmp_path / "demo/analysis.json").read_text())
    assert result["registry_cves"] == 4
    assert result["cohorts"][0]["eligible"] == 2
    assert result["attempt_status_counts"]["failed"] == 1
    assert result["catalog_gaps_over_48h"]
