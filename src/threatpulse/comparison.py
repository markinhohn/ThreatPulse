"""Frozen publication-window KEV/non-KEV studies with same-date EPSS."""

import argparse
import json
import os
import sys
from datetime import UTC, date, datetime, time
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Jsonb
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from threatpulse.daily import IngestionBusyError, ingestion_lock
from threatpulse.epss import EpssBatch, EpssCollectionError, collect_epss
from threatpulse.kev import CISA_KEV_URL, KevCollectionError, collect_kev
from threatpulse.models import CveId
from threatpulse.nvd import NvdCollectionError, NvdRecord, collect_nvd_window
from threatpulse.storage import migrate


class CohortDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    published_start: date
    published_end: date
    score_date: date
    max_records: int = Field(default=10000, gt=0)

    @model_validator(mode="after")
    def window(self):
        if not 0 < (self.published_end - self.published_start).days <= 120:
            raise ValueError("Publication window must be between 1 and 120 days")
        return self


def classify(record: NvdRecord, kev_ids: set[str]) -> str:
    """Current CISA membership; quarantine positive NVD/CISA disagreements."""
    if record.status.casefold() == "rejected":
        return "excluded_rejected"
    if record.cve_id in kev_ids:
        return "kev"
    if any(
        record.raw_record.get(key)
        for key in (
            "cisaExploitAdd",
            "cisaActionDue",
            "cisaRequiredAction",
            "cisaVulnerabilityName",
        )
    ):
        return "excluded_kev_conflict"
    return "non_kev"


class ComparisonStudy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    study_id: UUID = Field(default_factory=uuid4)
    label: str = "NVD publication-window KEV/non-KEV study"
    definition: CohortDefinition
    collected_at: AwareDatetime
    kev_snapshot_at: AwareDatetime
    kev_source_url: Literal[CISA_KEV_URL] = CISA_KEV_URL
    kev_ids: list[CveId]
    nvd_records: list[NvdRecord]
    epss: EpssBatch

    @model_validator(mode="after")
    def complete_study(self):
        if len(self.kev_ids) != len(set(self.kev_ids)):
            raise ValueError("Duplicate catalog CVEs")
        ids = {record.cve_id for record in self.nvd_records}
        if len(ids) != len(self.nvd_records) or len(ids) > self.definition.max_records:
            raise ValueError("Duplicate or over-limit study CVEs")
        start = datetime.combine(self.definition.published_start, time(), tzinfo=UTC)
        end = datetime.combine(self.definition.published_end, time(), tzinfo=UTC)
        if any(not start <= r.published_at < end for r in self.nvd_records):
            raise ValueError("Record outside publication window")
        kev_ids = set(self.kev_ids)
        eligible = {
            r.cve_id
            for r in self.nvd_records
            if classify(r, kev_ids) in {"kev", "non_kev"}
        }
        scored = [observation.cve_id for observation in self.epss.observations]
        missing = self.epss.missing_cves
        if (
            len(scored) != len(set(scored))
            or len(missing) != len(set(missing))
            or set(scored) & set(missing)
            or set(scored) | set(missing) != eligible
        ):
            raise ValueError("EPSS coverage does not partition eligible study CVEs")
        if any(
            o.score_date != self.definition.score_date for o in self.epss.observations
        ):
            raise ValueError("EPSS score dates disagree with study definition")
        return self


def collect_study(definition: CohortDefinition) -> ComparisonStudy:
    """Caller holds the common ingestion lock for all network work."""
    batch = collect_nvd_window(
        definition.published_start,
        definition.published_end,
        max_records=definition.max_records,
    )
    catalog = collect_kev()
    kev_ids = sorted(r.kev.cve_id for r in catalog.records)
    kev_set = set(kev_ids)
    eligible = [
        r.cve_id for r in batch.records if classify(r, kev_set) in {"kev", "non_kev"}
    ]
    # One union request pins every EPSS chunk to the same explicit date.
    epss = collect_epss(eligible, score_date=definition.score_date)
    return ComparisonStudy(
        definition=definition,
        collected_at=datetime.now(UTC),
        kev_snapshot_at=catalog.records[0].kev.ingested_at,
        kev_ids=kev_ids,
        nvd_records=batch.records,
        epss=epss,
    )


def save_study(connection, study: ComparisonStudy):
    """Insert a complete frozen dataset atomically; duplicate IDs never overwrite."""
    study = ComparisonStudy.model_validate(study.model_dump(mode="json"))
    with connection.transaction():
        connection.execute(
            "INSERT INTO comparison_studies "
            "(study_id, published_start, published_end, score_date, dataset) "
            "VALUES (%s, %s, %s, %s, %s)",
            (
                study.study_id,
                study.definition.published_start,
                study.definition.published_end,
                study.definition.score_date,
                Jsonb(study.model_dump(mode="json")),
            ),
        )


def load_study(connection, study_id: UUID) -> ComparisonStudy:
    row = connection.execute(
        "SELECT dataset FROM comparison_studies WHERE study_id = %s", (study_id,)
    ).fetchone()
    if row is None:
        raise ValueError("Study not found")
    return ComparisonStudy.model_validate(row[0])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collect = commands.add_parser(
        "collect", help="Collect, persist, and report a study"
    )
    collect.add_argument("--published-start", type=date.fromisoformat, required=True)
    collect.add_argument(
        "--published-end",
        type=date.fromisoformat,
        required=True,
        help="Exclusive end date at UTC midnight",
    )
    collect.add_argument("--score-date", type=date.fromisoformat, required=True)
    collect.add_argument("--max-records", type=int, default=10000)
    collect.add_argument("--output", type=Path, required=True)
    report = commands.add_parser("report", help="Replay a saved study")
    source = report.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", type=Path)
    source.add_argument("--study-id", type=UUID)
    report.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    from threatpulse.comparison_report import write_report

    study = None
    try:
        if args.output.exists():
            raise FileExistsError("Use a new output directory")
        if args.command == "report" and args.input:
            study = ComparisonStudy.model_validate_json(args.input.read_text())
        else:
            database_url = os.environ.get("DATABASE_URL")
            if not database_url:
                print(
                    "Set DATABASE_URL for collection or stored study replay.",
                    file=sys.stderr,
                )
                return 1
            # Validate definition before migration or network work.
            definition = (
                CohortDefinition(
                    published_start=args.published_start,
                    published_end=args.published_end,
                    score_date=args.score_date,
                    max_records=args.max_records,
                )
                if args.command == "collect"
                else None
            )
            with psycopg.connect(
                database_url, autocommit=True, connect_timeout=10
            ) as conn:
                if args.command == "collect":
                    migrate(conn)
                    with ingestion_lock(conn):
                        study = collect_study(definition)
                        save_study(conn, study)
                else:
                    with conn.transaction():
                        conn.execute("SET TRANSACTION READ ONLY")
                        study = load_study(conn, args.study_id)
        write_report(study, args.output)
    except (
        psycopg.Error,
        NvdCollectionError,
        KevCollectionError,
        EpssCollectionError,
        IngestionBusyError,
        ValueError,
        OSError,
    ) as exc:
        # Persisted studies can be replayed even if filesystem rendering fails.
        print(
            f"Comparison failed ({type(exc).__name__}). Check the configured "
            "database, source access, window, dates, and output destination.",
            file=sys.stderr,
        )
        if study is not None:
            print(f"Study ID: {study.study_id}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "study_id": str(study.study_id),
                "report": str(args.output / "report.html"),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
