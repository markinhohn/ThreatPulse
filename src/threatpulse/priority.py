"""Transparent baseline priority decisions with source and review provenance."""

import argparse
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal

import psycopg
from psycopg.rows import dict_row
from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    TypeAdapter,
    model_validator,
)

from threatpulse.epss import Probability
from threatpulse.kev import CISA_KEV_URL
from threatpulse.models import CveId, KevEntry, RequiredText
from threatpulse.nvd import NvdRecord
from threatpulse.trends import read_dataset as read_history
from threatpulse.velocity import (
    ModelRegistry,
    VelocityDataset,
    VelocityObservation,
)
from threatpulse.velocity import (
    analyze as velocity,
)

Tier = Literal["P1", "P2", "P3", "P4", "UNDETERMINED", "OUT_OF_SCOPE"]
RANK = {tier: index for index, tier in enumerate(("P1", "P2", "P3", "P4"))}
POLICY = {
    "policy_version": "0.1",
    "engine_format": 1,
    "purpose": "intelligence_review_tiers",
    "validated_risk_model": False,
    "epss_high_probability": "0.10",
    "epss_elevated_probability": "0.01",
    "severe_cvss_labels": ["HIGH", "CRITICAL"],
    "accepted_cvss_versions": ["2.0", "3.0", "3.1", "4.0"],
    "epss_max_source_calendar_age_days_utc": 2,
    "nvd_max_capture_age_hours": 168,
    "cisa_absence_max_capture_age_hours": 48,
    "confirmed_kev_evidence_expires_automatically": False,
    "tier_order": list(RANK),
    "within_tier_display_order": "cve_identifier",
    "non_ranked_states": ["UNDETERMINED", "OUT_OF_SCOPE"],
    "ordered_rules": [
        {"id": "R0", "tier": "OUT_OF_SCOPE", "reason": "REJECTED_RECORD"},
        {"id": "R1", "tier": "P1", "reason": "CONFIRMED_KEV"},
        {"id": "R2", "tier": "P2", "reason": "EPSS_HIGH"},
        {"id": "R3", "tier": "P2", "reason": "SEVERITY_AND_EPSS"},
        {"id": "R4", "tier": "P3", "reason": "EPSS_ELEVATED"},
        {"id": "R5", "tier": "P3", "reason": "HIGH_SEVERITY"},
        {"id": "R6", "tier": "P4", "reason": "LOWER_SIGNALS_COMPLETE"},
        {"id": "R7", "tier": "UNDETERMINED", "reason": "INSUFFICIENT_EVIDENCE"},
    ],
    "review_floors": ["EXPLOITATION_CONFLICT", "SEVERITY_WITH_UNKNOWN_EPSS"],
    "trend_promotion": {"P3": "P2"},
    "automatic_trend_downgrades": False,
    "downgrade_guard": "retain_previous_ranked_tier_until_matching_recorded_review",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence_id: RequiredText
    captured_at: AwareDatetime
    available_at: AwareDatetime
    source_url: HttpUrl

    @model_validator(mode="after")
    def validate_availability(self):
        if self.available_at < self.captured_at:
            raise ValueError("Availability cannot precede capture")
        return self


class CatalogEvidence(Evidence):
    cve_ids: list[CveId]
    complete: bool = True
    validated: bool = True

    @model_validator(mode="after")
    def validate_ids(self):
        if len(set(self.cve_ids)) != len(self.cve_ids):
            raise ValueError("Duplicate catalog CVE")
        self.cve_ids.sort()
        return self


class KevEvidence(Evidence):
    cve_id: CveId
    entry: dict[str, Any]


class NvdEvidence(Evidence):
    cve_id: CveId
    record: dict[str, Any]


class EpssEvidence(Evidence):
    cve_id: CveId
    # A malformed provider row becomes unknown for this CVE, not a lost P1.
    score_date: Any
    epss: Any
    percentile: Any = None
    raw_record: dict[str, Any] = Field(default_factory=dict)


class DecisionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    cve_id: CveId
    decision_at: AwareDatetime
    policy_version: str
    policy_sha256: str
    input_sha256: str
    previous_decision_id: str | None
    rule_id: str
    candidate_tier: Tier
    effective_tier: Tier
    reason_codes: list[str]
    quality_flags: list[str]
    needs_review: bool
    values: dict[str, Any]
    quality_details: dict[str, Any]
    trend: dict[str, Any]
    approved_review_id: str | None
    review_status: str
    review_audit: list[dict[str, Any]]

    @model_validator(mode="after")
    def validate_integrity(self):
        if self.decision_id != digest(
            self.model_dump(mode="json", exclude={"decision_id"})
        ):
            raise ValueError("Previous decision checksum mismatch")
        return self


class DowngradeReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    review_id: RequiredText
    reviewer: RequiredText
    reviewed_at: AwareDatetime
    rationale: RequiredText
    cve_id: CveId
    policy_version: str
    policy_sha256: str
    previous_decision_id: str
    input_sha256: str
    approved_candidate: Tier


class KevWithdrawal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    correction_id: RequiredText
    cve_id: CveId
    evidence_ids: list[RequiredText] = Field(min_length=1)
    reviewed_at: AwareDatetime
    reviewer: RequiredText
    rationale: RequiredText
    source_url: HttpUrl

    @model_validator(mode="after")
    def validate_ids(self):
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("Duplicate withdrawn evidence")
        self.evidence_ids.sort()
        return self


class PriorityDataset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dataset_kind: Literal["baseline_priority"] = "baseline_priority"
    schema_version: Literal[1] = 1
    captured_at: AwareDatetime
    label: str = "Stored ThreatPulse baseline priorities"
    cohort: list[CveId]
    catalogs: list[CatalogEvidence] = Field(default_factory=list)
    kev_entries: list[KevEvidence] = Field(default_factory=list)
    nvd_records: list[NvdEvidence] = Field(default_factory=list)
    epss_observations: list[EpssEvidence] = Field(default_factory=list)
    model_registry: ModelRegistry = Field(default_factory=ModelRegistry)
    previous_decisions: list[DecisionRecord] = Field(default_factory=list)
    reviews: list[DowngradeReview] = Field(default_factory=list)
    kev_withdrawals: list[KevWithdrawal] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_keys(self):
        if len(set(self.cohort)) != len(self.cohort):
            raise ValueError("Duplicate cohort CVE")
        all_evidence = [
            *self.catalogs,
            *self.kev_entries,
            *self.nvd_records,
            *self.epss_observations,
        ]
        ids = [e.evidence_id for e in all_evidence]
        if len(set(ids)) != len(ids):
            raise ValueError("Duplicate evidence identifier")
        for group, key in (
            (self.previous_decisions, "cve_id"),
            (self.reviews, "review_id"),
            (self.kev_withdrawals, "correction_id"),
        ):
            if len({getattr(e, key) for e in group}) != len(group):
                raise ValueError("Duplicate decision/review/correction")
        if any(
            e.cve_id not in self.cohort
            for e in [
                *self.kev_entries,
                *self.nvd_records,
                *self.epss_observations,
                *self.previous_decisions,
                *self.reviews,
                *self.kev_withdrawals,
            ]
        ):
            raise ValueError("Evidence or decision outside cohort")
        keys = [(e.cve_id, canonical(e.score_date)) for e in self.epss_observations]
        if len(set(keys)) != len(keys):
            raise ValueError("Duplicate EPSS CVE/date")
        return self


def read_dataset(connection):
    """Read a consistent existing snapshot; never collect, migrate, or write."""
    history = read_history(connection)
    with connection.cursor(row_factory=dict_row) as cursor:
        kev = cursor.execute(
            "SELECT cve_id, source_url, ingested_at, raw_record "
            "FROM kev_entries ORDER BY cve_id"
        ).fetchall()
        nvd = cursor.execute(
            "SELECT cve_id, published_at, modified_at, status, description, "
            "reference_urls AS references, weaknesses, cvss_metrics, source_url, "
            "ingested_at, raw_record FROM nvd_enrichments ORDER BY cve_id"
        ).fetchall()
        captured = cursor.execute("SELECT clock_timestamp() AS t").fetchone()["t"]
    by_run = defaultdict(list)
    for snapshot in history.kev_snapshots:
        by_run[snapshot.run_id].append(snapshot.observation.kev)
    catalogs, entries = [], []
    for step in history.steps:
        if step.source != "kev":
            continue
        records = by_run[step.run_id]
        catalogs.append(
            CatalogEvidence(
                evidence_id=f"catalog-run-{step.run_id}",
                captured_at=step.finished_at,
                available_at=max(captured, step.finished_at),
                source_url=CISA_KEV_URL,
                cve_ids=sorted(r.cve_id for r in records),
            )
        )
        for record in records:
            entries.append(
                KevEvidence(
                    evidence_id=f"kev-run-{step.run_id}-{record.cve_id}",
                    cve_id=record.cve_id,
                    captured_at=record.ingested_at,
                    available_at=max(captured, record.ingested_at),
                    source_url=record.source_url,
                    entry=record.model_dump(mode="json"),
                )
            )
    for record in kev:
        # The retained row is evidence of inclusion, not current membership.
        raw = record["raw_record"]
        entry = {
            "cve_id": record["cve_id"],
            "date_added": raw.get("dateAdded"),
            "required_action": raw.get("requiredAction"),
            "due_date": raw.get("dueDate"),
            "ransomware_use": raw.get("knownRansomwareCampaignUse"),
            "notes": raw.get("notes"),
            "source_url": record["source_url"],
            "ingested_at": record["ingested_at"].isoformat(),
            "raw_record": raw,
        }
        entries.append(
            KevEvidence(
                evidence_id=f"kev-latest-{record['cve_id']}",
                cve_id=record["cve_id"],
                captured_at=record["ingested_at"],
                available_at=max(captured, record["ingested_at"]),
                source_url=record["source_url"],
                entry=entry,
            )
        )
    return PriorityDataset(
        captured_at=captured,
        cohort=history.cohort,
        catalogs=catalogs,
        kev_entries=entries,
        nvd_records=[
            NvdEvidence(
                evidence_id=f"nvd-run-{s.run_id}-{s.observation.cve_id}",
                cve_id=s.observation.cve_id,
                captured_at=s.observation.ingested_at,
                available_at=max(captured, s.observation.ingested_at),
                source_url=s.observation.source_url,
                record=s.observation.model_dump(mode="json"),
            )
            for s in history.nvd_snapshots
        ]
        + [
            NvdEvidence(
                evidence_id=f"nvd-latest-{r['cve_id']}",
                cve_id=r["cve_id"],
                captured_at=r["ingested_at"],
                available_at=max(captured, r["ingested_at"]),
                source_url=r["source_url"],
                record=r,
            )
            for r in nvd
        ],
        epss_observations=[
            EpssEvidence(
                evidence_id=f"epss-{e.cve_id}-{e.score_date}",
                cve_id=e.cve_id,
                captured_at=e.ingested_at,
                available_at=max(captured, e.ingested_at),
                source_url=e.source_url,
                score_date=e.score_date.isoformat(),
                epss=str(e.epss),
                percentile=str(e.percentile),
                raw_record=e.raw_record,
            )
            for e in history.epss_observations
        ],
    )


def _available(evidence, decision):
    return evidence.captured_at <= decision and evidence.available_at <= decision


def _metric_key(metric):
    return [metric.version, metric.source, metric.metric_type] if metric else None


def _nvd_state(evidence, decision):
    if evidence is None:
        return None, None, "missing"
    if not _available(evidence, decision):
        return None, None, "unavailable"
    try:
        record = NvdRecord.model_validate(evidence.record)
        if record.cve_id != evidence.cve_id:
            raise ValueError("NVD identifier mismatch")
    except (ValueError, TypeError):
        try:
            record = NvdRecord.model_validate(evidence.record | {"cvss_metrics": []})
            if (
                record.cve_id != evidence.cve_id
                or record.ingested_at > evidence.captured_at
                or max(record.ingested_at, record.published_at, record.modified_at)
                > decision
            ):
                return None, None, "invalid"
        except (ValueError, TypeError):
            return None, None, "invalid"
        return record, None, "invalid"
    if record.ingested_at > evidence.captured_at:
        return None, None, "invalid"
    if max(record.ingested_at, record.published_at, record.modified_at) > decision:
        return None, None, "future"
    metric = record.preferred_cvss
    if record.status == "Rejected":
        return record, None, "rejected"
    if decision - evidence.captured_at > timedelta(
        hours=POLICY["nvd_max_capture_age_hours"]
    ):
        return record, None, "stale"
    return record, metric, "fresh" if metric else "unscored"


def _epss(evidence):
    return VelocityObservation(
        cve_id=evidence.cve_id,
        score_date=evidence.score_date,
        epss=TypeAdapter(Probability).validate_python(evidence.epss),
        percentile=TypeAdapter(Probability).validate_python(evidence.percentile)
        if evidence.percentile is not None
        else None,
        source_url=evidence.source_url,
        ingested_at=evidence.captured_at,
        available_at=evidence.available_at,
        availability_basis="validated_capture",
        raw_record=evidence.raw_record,
    )


def analyze(dataset, decision_at=None):
    dataset = PriorityDataset.model_validate(dataset.model_dump(mode="json"))
    dataset.model_registry.regimes.sort(key=lambda r: r.score_date_start)
    decision = decision_at or dataset.captured_at
    if decision.tzinfo is None or decision.utcoffset() is None:
        raise ValueError("Decision requires a timezone")
    decision = decision.astimezone(UTC)
    prior = {p.cve_id: p for p in dataset.previous_decisions}
    if any(p.decision_at > decision for p in prior.values()):
        raise ValueError("Previous decision follows current decision")
    groups = {}
    for name in ("kev_entries", "nvd_records", "epss_observations"):
        grouped = defaultdict(list)
        for evidence in getattr(dataset, name):
            grouped[evidence.cve_id].append(evidence)
        groups[name] = grouped
    catalogs = sorted(
        [c for c in dataset.catalogs if _available(c, decision) and c.validated],
        key=lambda c: (c.captured_at, c.evidence_id),
    )
    catalog = catalogs[-1] if catalogs else None
    catalog_members = {c.evidence_id: set(c.cve_ids) for c in catalogs}
    catalog_history_sha = digest([c.model_dump(mode="json") for c in catalogs])
    absence_valid = bool(
        catalog
        and catalog.complete
        and catalog.cve_ids
        and decision - catalog.captured_at
        <= timedelta(hours=POLICY["cisa_absence_max_capture_age_hours"])
    )
    valid_epss, invalid_epss = [], defaultdict(list)
    for evidence in dataset.epss_observations:
        try:
            valid_epss.append(_epss(evidence))
        except (ValueError, TypeError):
            if _available(evidence, decision):
                invalid_epss[evidence.cve_id].append(evidence.evidence_id)
    vdataset = VelocityDataset(
        captured_at=dataset.captured_at,
        cohort=dataset.cohort,
        epss_observations=valid_epss,
        model_registry=dataset.model_registry,
    )
    velocity_result = velocity(vdataset, decision, allow_after_export=True)
    epss_by_cve = defaultdict(list)
    for observation in valid_epss:
        epss_by_cve[observation.cve_id].append(observation)
    trends = {r["cve_id"]: r for r in velocity_result["cves"]}
    policy = json.loads(canonical(POLICY))
    policy["velocity_policy"] = velocity_result["policy"]
    policy_sha = digest(policy)
    results = []
    for cve in sorted(dataset.cohort):
        previous = prior.get(cve)
        corrections = [
            w
            for w in dataset.kev_withdrawals
            if w.cve_id == cve and w.reviewed_at <= decision
        ]
        corrections.sort(key=lambda w: w.correction_id)
        withdrawn = {e for w in corrections for e in w.evidence_ids}
        positives = []
        for capture in catalogs:
            if cve in catalog_members[capture.evidence_id]:
                positives.append(
                    {
                        "evidence_id": f"{capture.evidence_id}:{cve}",
                        "source_url": str(capture.source_url),
                        "captured_at": capture.captured_at.isoformat(),
                    }
                )
        invalid_kev = []
        for evidence in groups["kev_entries"][cve]:
            if not _available(evidence, decision):
                continue
            try:
                entry = KevEntry.model_validate(evidence.entry)
                if (
                    entry.cve_id != cve
                    or entry.ingested_at > evidence.captured_at
                    or entry.date_added > decision.date()
                ):
                    raise ValueError("KEV provenance invalid")
            except (ValueError, TypeError):
                invalid_kev.append(evidence.evidence_id)
                continue
            positives.append(
                {
                    "evidence_id": evidence.evidence_id,
                    "source_url": str(evidence.source_url),
                    "captured_at": evidence.captured_at.isoformat(),
                }
            )
        if previous:
            positives.extend(previous.values.get("kev", {}).get("evidence", []))
        unique_positive = {p["evidence_id"]: p for p in positives}
        if withdrawn - unique_positive.keys():
            raise ValueError("Correction references unknown KEV evidence")
        for correction in corrections:
            if any(
                datetime.fromisoformat(unique_positive[e]["captured_at"])
                > correction.reviewed_at
                for e in correction.evidence_ids
            ):
                raise ValueError("Correction precedes its KEV evidence")
        positives = [
            unique_positive[k] for k in sorted(unique_positive) if k not in withdrawn
        ]
        confirmed = bool(positives)
        present = bool(catalog and cve in catalog_members[catalog.evidence_id])
        catalog_conflict = (
            len(
                {
                    cve in catalog_members[c.evidence_id]
                    for c in catalogs
                    if c.captured_at == catalog.captured_at
                }
            )
            > 1
            if catalog
            else False
        )
        current_known = not catalog_conflict and (present or absence_valid)
        nvd_list = sorted(
            groups["nvd_records"][cve], key=lambda e: (e.captured_at, e.evidence_id)
        )
        available_nvd = [e for e in nvd_list if _available(e, decision)]
        latest_nvd = available_nvd[-1] if available_nvd else None
        record, metric, nvd_quality = _nvd_state(latest_nvd, decision)
        nvd_positive = bool(
            record
            and any(
                record.raw_record.get(k) not in (None, "")
                for k in (
                    "cisaExploitAdd",
                    "cisaActionDue",
                    "cisaRequiredAction",
                    "cisaVulnerabilityName",
                )
            )
        )
        rejected = bool(record and record.status == "Rejected")
        conflict = (
            (nvd_positive and not confirmed)
            or (rejected and (confirmed or present))
            or (present and not confirmed)
            or catalog_conflict
            or bool(invalid_kev)
        )
        point = sorted(
            [
                e
                for e in epss_by_cve[cve]
                if e.available_at <= decision and e.score_date <= decision.date()
            ],
            key=lambda e: e.score_date,
        )
        latest_epss = point[-1] if point else None
        epss_quality = "fresh" if latest_epss else "missing"
        if (
            latest_epss
            and (decision.date() - latest_epss.score_date).days
            > POLICY["epss_max_source_calendar_age_days_utc"]
        ):
            epss_quality = "stale"
        invalid_current, invalid_window = [], []
        for evidence in groups["epss_observations"][cve]:
            if evidence.evidence_id not in invalid_epss[cve]:
                continue
            try:
                source_date = TypeAdapter(date).validate_python(evidence.score_date)
            except (ValueError, TypeError):
                source_date = None
            if (
                source_date is None
                or latest_epss is None
                or source_date >= latest_epss.score_date
            ):
                invalid_current.append(evidence.evidence_id)
            if (
                source_date is None
                or latest_epss is None
                or source_date >= latest_epss.score_date - timedelta(days=7)
            ):
                invalid_window.append(evidence.evidence_id)
        if invalid_current or any(
            e["reason"] == "FUTURE_SCORE_DATE"
            for e in trends[cve]["excluded_observations"]
        ):
            epss_quality = "invalid"
        if invalid_window:
            trends[cve]["rising_signal"] = False
            trends[cve]["eligibility_reasons"] = [
                r for r in trends[cve]["eligibility_reasons"] if r != "ELIGIBLE_RISING"
            ] + ["INVALID_EPSS_IN_WINDOW"]
        probability = latest_epss.epss if epss_quality == "fresh" else None
        severe = bool(metric and metric.severity in POLICY["severe_cvss_labels"])
        matches = [
            rejected and not confirmed and not nvd_positive and not conflict,
            confirmed,
            probability is not None
            and probability >= Decimal(POLICY["epss_high_probability"]),
            probability is not None
            and probability >= Decimal(POLICY["epss_elevated_probability"])
            and severe,
            probability is not None
            and probability >= Decimal(POLICY["epss_elevated_probability"]),
            severe,
            probability is not None
            and probability < Decimal(POLICY["epss_elevated_probability"])
            and metric is not None
            and metric.severity in ("NONE", "LOW", "MEDIUM")
            and absence_valid
            and current_known
            and not present
            and not conflict,
            True,
        ]
        rule = POLICY["ordered_rules"][matches.index(True)]
        candidate, reasons, flags = rule["tier"], [rule["reason"]], []
        preference_changed = bool(
            previous
            and metric
            and previous.values.get("cvss", {}).get("preferred_key")
            and _metric_key(metric) != previous.values["cvss"]["preferred_key"]
        )
        if rule["id"] != "R0":
            if probability is None:
                flags.append("EPSS_UNKNOWN")
            if metric is None:
                flags.append("CVSS_UNKNOWN")
            if not current_known:
                flags.append("KEV_COVERAGE_UNKNOWN")
            if (
                confirmed
                and catalog
                and catalog.complete
                and catalog.cve_ids
                and not present
                and not catalog_conflict
            ):
                flags.append("KEV_MEMBERSHIP_CHANGED")
            if conflict:
                flags.append("EXPLOITATION_CONFLICT")
            if preference_changed:
                flags.append("CVSS_PREFERENCE_CHANGED")
            if (
                candidate == "P3"
                and probability is not None
                and trends[cve]["rising_signal"]
            ):
                candidate = "P2"
                reasons.append("TREND_RISING")
            for applies, reason in (
                (conflict, "EXPLOITATION_CONFLICT"),
                (severe and probability is None, "SEVERITY_WITH_UNKNOWN_EPSS"),
            ):
                if applies:
                    if candidate not in RANK or RANK[candidate] > RANK["P2"]:
                        candidate = "P2"
                    reasons.append(reason)
        values = {
            "kev": {
                "confirmed": confirmed,
                "current_membership": present if current_known else None,
                "catalog_id": catalog.evidence_id if catalog else None,
                "evidence": positives,
                "withdrawals": [w.correction_id for w in corrections],
            },
            "epss": latest_epss.model_dump(mode="json") if latest_epss else None,
            "cvss": {
                "preferred_key": _metric_key(metric),
                "metric": record.preferred_cvss.model_dump(mode="json")
                if record and record.preferred_cvss
                else None,
                "usable": metric is not None,
                "nvd_status": record.status if record else None,
                "evidence_id": latest_nvd.evidence_id if latest_nvd else None,
            },
        }
        quality = {
            "epss": epss_quality,
            "cvss": nvd_quality,
            "catalog": "conflicting"
            if catalog_conflict
            else "fresh"
            if absence_valid
            else "partial"
            if catalog and not catalog.complete
            else "stale"
            if catalog
            else "missing",
            "invalid_epss_evidence": sorted(invalid_epss[cve]),
            "invalid_kev_evidence": sorted(invalid_kev),
        }
        inputs = {
            "cve_id": cve,
            "policy_sha256": policy_sha,
            "previous_decision_id": previous.decision_id if previous else None,
            "catalog": catalog.model_dump(mode="json") if catalog else None,
            "catalog_history_sha256": catalog_history_sha,
            "kev_evidence": sorted(
                [e.model_dump(mode="json") for e in groups["kev_entries"][cve]],
                key=lambda e: e["evidence_id"],
            ),
            "nvd_evidence": latest_nvd.model_dump(mode="json") if latest_nvd else None,
            "epss_evidence": sorted(
                [e.model_dump(mode="json") for e in groups["epss_observations"][cve]],
                key=lambda e: e["evidence_id"],
            ),
            "model_registry": dataset.model_registry.model_dump(mode="json"),
            "positive_evidence": positives,
            "quality": quality,
            "trend_eligible": trends[cve]["rising_signal"],
            "withdrawals": [w.model_dump(mode="json") for w in corrections],
        }
        input_sha = digest(inputs)
        downgrade = (
            previous
            and previous.effective_tier in RANK
            and (
                candidate not in RANK or RANK[candidate] > RANK[previous.effective_tier]
            )
        )
        reviews = sorted(
            [r for r in dataset.reviews if r.cve_id == cve],
            key=lambda r: r.review_id,
        )
        matches_review, review_audit = [], []
        for review in reviews:
            errors = []
            for matches, reason in (
                (bool(downgrade), "NOT_A_DOWNGRADE"),
                (
                    previous is not None
                    and review.previous_decision_id == previous.decision_id,
                    "PREVIOUS_DECISION_MISMATCH",
                ),
                (review.input_sha256 == input_sha, "INPUT_VERSION_MISMATCH"),
                (
                    review.policy_version == POLICY["policy_version"]
                    and review.policy_sha256 == policy_sha,
                    "POLICY_MISMATCH",
                ),
                (review.approved_candidate == candidate, "CANDIDATE_MISMATCH"),
                (review.reviewed_at <= decision, "FUTURE_REVIEW"),
                (
                    review.reviewed_at >= dataset.captured_at
                    and (
                        previous is None or review.reviewed_at >= previous.decision_at
                    ),
                    "REVIEW_PRECEDES_EVIDENCE",
                ),
            ):
                if not matches:
                    errors.append(reason)
            review_audit.append(
                {
                    "review_id": review.review_id,
                    "matched": not errors,
                    "reasons": errors,
                    "record": review.model_dump(mode="json"),
                }
            )
            if not errors:
                matches_review.append(review)
        approval = (
            max(
                matches_review, key=lambda r: (r.reviewed_at, r.review_id), default=None
            )
            if downgrade
            else None
        )
        effective = candidate
        if downgrade and approval is None:
            effective = previous.effective_tier
            flags.append("DOWNGRADE_REVIEW_REQUIRED")
        payload = {
            "cve_id": cve,
            "decision_at": TypeAdapter(AwareDatetime).dump_python(
                decision, mode="json"
            ),
            "policy_version": POLICY["policy_version"],
            "policy_sha256": policy_sha,
            "input_sha256": input_sha,
            "previous_decision_id": previous.decision_id if previous else None,
            "rule_id": rule["id"],
            "candidate_tier": candidate,
            "effective_tier": effective,
            "reason_codes": reasons,
            "quality_flags": flags,
            "needs_review": bool(flags),
            "values": values,
            "quality_details": quality,
            "trend": trends[cve],
            "approved_review_id": approval.review_id if approval else None,
            "review_status": "approved"
            if approval
            else "required"
            if downgrade
            else "not_required",
            "review_audit": review_audit,
        }
        results.append(
            DecisionRecord(decision_id=digest(payload), **payload).model_dump(
                mode="json"
            )
        )
    return {
        "analysis_kind": "baseline_priority",
        "analysis_format": 1,
        "label": dataset.label,
        "captured_at": dataset.captured_at.isoformat(),
        "decision_at": decision.isoformat(),
        "policy": policy,
        "policy_sha256": policy_sha,
        "cohort_cves": len(dataset.cohort),
        "tier_counts": {
            t: sum(r["effective_tier"] == t for r in results)
            for t in [*RANK, "UNDETERMINED", "OUT_OF_SCOPE"]
        },
        "needs_review_cves": sum(r["needs_review"] for r in results),
        "quality_flag_counts": dict(
            sorted(Counter(f for r in results for f in r["quality_flags"]).items())
        ),
        "decisions": results,
    }


def attach_previous(dataset, payload):
    if (
        not isinstance(payload, dict)
        or payload.get("analysis_kind") != "baseline_priority"
        or payload.get("analysis_format") != 1
    ):
        raise ValueError("Expected a baseline priority analysis")
    decisions = [DecisionRecord.model_validate(p) for p in payload["decisions"]]
    dataset.cohort = sorted(set(dataset.cohort) | {p.cve_id for p in decisions})
    dataset.previous_decisions = decisions
    return PriorityDataset.model_validate(dataset.model_dump(mode="json"))


def main(argv=None):
    from threatpulse.priority_report import write_report

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--input", type=Path, help="Frozen priority source.json")
    parser.add_argument("--previous", type=Path, help="Previous priority analysis.json")
    parser.add_argument(
        "--reviews", type=Path, help="JSON array of downgrade acknowledgements"
    )
    parser.add_argument("--model-regimes", type=Path)
    parser.add_argument("--decision-at", type=datetime.fromisoformat)
    args = parser.parse_args(argv)
    try:
        if args.input:
            dataset = PriorityDataset.model_validate_json(args.input.read_text())
        else:
            url = os.environ.get("DATABASE_URL")
            if not url:
                print("Set DATABASE_URL or pass --input source.json.", file=sys.stderr)
                return 1
            with psycopg.connect(url, connect_timeout=10) as connection:
                connection.execute(
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
                )
                dataset = read_dataset(connection)
        if args.previous:
            dataset = attach_previous(dataset, json.loads(args.previous.read_text()))
        if args.reviews:
            dataset.reviews = TypeAdapter(list[DowngradeReview]).validate_json(
                args.reviews.read_text()
            )
        if args.model_regimes:
            dataset.model_registry = ModelRegistry.model_validate_json(
                args.model_regimes.read_text()
            )
        write_report(dataset, args.output, decision_at=args.decision_at)
    except (psycopg.Error, ValueError, OSError, KeyError, TypeError) as exc:
        print(
            f"Priority evaluation failed ({type(exc).__name__}). Check database "
            "setup, input, decision time, previous decisions, reviews, and use "
            "a new output directory.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps({"report": str(args.output / "report.html")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
