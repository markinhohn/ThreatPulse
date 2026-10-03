"""Exercise the CISA mapping, validation, and provenance contract offline."""

import json
from datetime import UTC, date, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from threatpulse.models import KevEntry, RansomwareUse, parse_cisa_kev_record

SOURCE_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
INGESTED_AT = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture
def record():
    return json.loads(
        (Path(__file__).parent / "fixtures" / "cisa_kev_record.json").read_text()
    )


def parse(record, **overrides):
    return parse_cisa_kev_record(
        record,
        source_url=overrides.get("source_url", SOURCE_URL),
        ingested_at=overrides.get("ingested_at", INGESTED_AT),
    )


def test_cisa_mapping_and_json_round_trip(record):
    vulnerability, entry = parse(record)
    assert vulnerability.cve_id == entry.cve_id == "CVE-2021-44228"
    assert vulnerability.vendor == "Apache"
    assert vulnerability.product == "Log4j"
    assert vulnerability.name == record["vulnerabilityName"]
    assert vulnerability.description == record["shortDescription"]
    assert entry.date_added == date(2021, 12, 10)
    assert entry.due_date == date(2021, 12, 24)
    assert entry.required_action == record["requiredAction"]
    assert entry.ransomware_use is RansomwareUse.KNOWN
    assert str(entry.source_url) == SOURCE_URL
    assert entry.ingested_at == INGESTED_AT
    assert entry.raw_record == record
    assert KevEntry.model_validate_json(entry.model_dump_json()) == entry


@pytest.mark.parametrize(
    "field",
    [
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "shortDescription",
        "dateAdded",
        "requiredAction",
        "dueDate",
        "knownRansomwareCampaignUse",
    ],
)
def test_missing_required_fields(record, field):
    del record[field]
    with pytest.raises(ValidationError):
        parse(record)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cveID", "CVE-2021-123"),
        ("cveID", "CVE-2021-44228\n"),
        ("cveID", "cve-2021-44228"),
        ("vendorProject", "   "),
        ("product", ""),
        ("vulnerabilityName", ""),
        ("shortDescription", ""),
        ("requiredAction", ""),
        ("dateAdded", "2021-02-30"),
        ("dueDate", "not-a-date"),
        ("knownRansomwareCampaignUse", "No"),
    ],
)
def test_invalid_source_values(record, field, value):
    record[field] = value
    with pytest.raises(ValidationError):
        parse(record)


def test_optional_notes_unknown_use_and_long_cve(record):
    record.pop("notes")
    record["knownRansomwareCampaignUse"] = "Unknown"
    record["cveID"] = "CVE-2026-1234567"
    vulnerability, entry = parse(record)
    assert vulnerability.cve_id == "CVE-2026-1234567"
    assert entry.notes is None
    assert entry.ransomware_use is RansomwareUse.UNKNOWN


def test_raw_record_is_preserved_without_shared_nested_data(record):
    record["vendorProject"] = " Apache "
    vulnerability, entry = parse(record)
    assert vulnerability.vendor == "Apache"
    assert entry.raw_record["vendorProject"] == " Apache "
    record["cwes"].append("CWE-20")
    assert entry.raw_record["cwes"] == ["CWE-502"]


def test_timestamp_is_normalized_to_utc(record):
    timestamp = datetime(2026, 1, 1, 5, tzinfo=timezone(timedelta(hours=5)))
    _, entry = parse(record, ingested_at=timestamp)
    assert entry.ingested_at == INGESTED_AT
    assert entry.ingested_at.tzinfo == UTC


def test_naive_timestamp_rejected(record):
    with pytest.raises(ValidationError):
        parse(record, ingested_at=datetime(2026, 1, 1))


@pytest.mark.parametrize("url", ["not-a-url", "ftp://example.com/catalog.json"])
def test_invalid_source_url_rejected(record, url):
    with pytest.raises(ValidationError):
        parse(record, source_url=url)
