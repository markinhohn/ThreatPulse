"""Validated vulnerability records and CISA KEV source observations."""

from copy import deepcopy
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    HttpUrl,
    StringConstraints,
    field_validator,
)

CveId = Annotated[str, StringConstraints(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")]
RequiredText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class Vulnerability(BaseModel):
    """Shared CVE attributes, initially populated from CISA KEV."""

    model_config = ConfigDict(extra="forbid")

    cve_id: CveId
    vendor: RequiredText
    product: RequiredText
    name: RequiredText
    description: RequiredText


class RansomwareUse(StrEnum):
    """CISA's reported campaign use; Unknown does not mean no use."""

    KNOWN = "Known"
    UNKNOWN = "Unknown"


class KevEntry(BaseModel):
    """CISA-specific remediation information and ingestion provenance."""

    model_config = ConfigDict(extra="forbid")

    cve_id: CveId
    date_added: date
    required_action: RequiredText
    due_date: date
    ransomware_use: RansomwareUse
    notes: str | None = None
    source_url: HttpUrl
    ingested_at: AwareDatetime
    raw_record: dict[str, Any]

    @field_validator("ingested_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        """Store all aware ingestion timestamps in UTC."""
        return value.astimezone(UTC)


def parse_cisa_kev_record(
    record: dict[str, Any], *, source_url: str, ingested_at: datetime
) -> tuple[Vulnerability, KevEntry]:
    """Validate a CISA record and retain its original fields for traceability.

    Missing required source fields produce Pydantic validation errors.
    Additional source fields are retained in raw_record for forward compatibility.
    The caller supplies the fetch URL and timestamp once per ingestion batch.
    """
    vulnerability = Vulnerability.model_validate(
        {
            "cve_id": record.get("cveID"),
            "vendor": record.get("vendorProject"),
            "product": record.get("product"),
            "name": record.get("vulnerabilityName"),
            "description": record.get("shortDescription"),
        }
    )
    entry = KevEntry.model_validate(
        {
            "cve_id": vulnerability.cve_id,
            "date_added": record.get("dateAdded"),
            "required_action": record.get("requiredAction"),
            "due_date": record.get("dueDate"),
            "ransomware_use": record.get("knownRansomwareCampaignUse"),
            "notes": record.get("notes"),
            "source_url": source_url,
            "ingested_at": ingested_at,
            "raw_record": deepcopy(record),
        }
    )
    return vulnerability, entry
