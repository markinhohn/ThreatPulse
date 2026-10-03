"""Deterministic NVD parsing, pacing, pagination, and failure tests."""

import json
from copy import deepcopy
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from threatpulse.nvd import (
    NVD_URL,
    CvssMetric,
    NvdCollectionError,
    collect_nvd,
    parse_nvd_record,
)


@pytest.fixture
def nvd_raw():
    return json.loads((Path(__file__).parent / "fixtures" / "nvd_cve.json").read_text())


def parse(raw):
    return parse_nvd_record(
        raw, source_url=NVD_URL, ingested_at=datetime(2026, 1, 1, tzinfo=UTC)
    )


def page(rows, start=0, total=None):
    return {
        "startIndex": start,
        "totalResults": len(rows) if total is None else total,
        "vulnerabilities": [{"cve": raw} for raw in rows],
    }


class FakeTime:
    def __init__(self):
        self.now = 0.0
        self.waits = []

    def sleep(self, seconds):
        self.waits.append(seconds)
        self.now += seconds

    def clock(self):
        return self.now


def collect(handler, ids=None, api_key="test-key"):
    fake = FakeTime()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        batch = collect_nvd(
            ids or ["CVE-2021-44228"],
            api_key=api_key,
            client=client,
            sleep=fake.sleep,
            clock=fake.clock,
        )
        assert not client.is_closed
    return batch, fake


def test_parse_technical_context_and_provenance(nvd_raw):
    record = parse(nvd_raw)
    assert record.cve_id == "CVE-2021-44228"
    assert record.published_at.tzinfo == UTC
    assert record.modified_at == datetime(2026, 1, 1, 12, tzinfo=UTC)
    assert record.weaknesses == ["CWE-502"]
    assert str(record.references[0]) == "https://example.com/advisory"
    assert record.preferred_cvss.base_score == Decimal("9.8")
    assert record.preferred_cvss.attack_vector == "NETWORK"
    assert record.raw_record == nvd_raw
    nvd_raw["configurations"].clear()
    assert record.raw_record["configurations"]


@pytest.mark.parametrize(
    "version,vector,score,severity",
    [
        ("2.0", "AV:N/AC:L/Au:N/C:P/I:P/A:P", "7.5", "HIGH"),
        ("3.0", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "9.8", "CRITICAL"),
        ("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "9.8", "CRITICAL"),
        (
            "4.0",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "9.3",
            "CRITICAL",
        ),
    ],
)
def test_supported_cvss_versions(version, vector, score, severity):
    assert (
        CvssMetric(
            version=version,
            vector=vector,
            base_score=score,
            source="nvd@nist.gov",
            metric_type="Primary",
            severity=severity,
            attack_vector="NETWORK",
        ).version
        == version
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("base_score", "11"),
        ("base_score", "NaN"),
        ("base_score", "8.0"),
        ("severity", "HIGH"),
        ("attack_vector", "LOCAL"),
        ("vector", "CVSS:3.1/AV:X"),
        ("version", "3.0"),
        ("source", " "),
        ("metric_type", "Other"),
    ],
)
def test_invalid_cvss(nvd_raw, field, value):
    metric = parse(nvd_raw).preferred_cvss.model_dump()
    metric[field] = value
    with pytest.raises(ValidationError):
        CvssMetric.model_validate(metric)


def test_metric_preference_and_missing_scores(nvd_raw):
    primary = nvd_raw["metrics"]["cvssMetricV31"][0]
    secondary = deepcopy(primary)
    secondary["type"] = "Secondary"
    secondary["source"] = "a@example.com"
    nvd_raw["metrics"]["cvssMetricV31"] = [secondary, primary]
    assert parse(nvd_raw).preferred_cvss.source == "nvd@nist.gov"
    nvd_raw.pop("metrics")
    nvd_raw["vulnStatus"] = "Awaiting Analysis"
    record = parse(nvd_raw)
    assert record.preferred_cvss is None
    assert record.cvss_metrics == []


def test_v2_source_mapping(nvd_raw):
    nvd_raw["metrics"] = {
        "cvssMetricV2": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "baseSeverity": "HIGH",
                "cvssData": {
                    "version": "2.0",
                    "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                    "baseScore": 7.5,
                    "accessVector": "NETWORK",
                },
            }
        ]
    }
    assert parse(nvd_raw).preferred_cvss.version == "2.0"


def test_legacy_ftp_reference_preserved(nvd_raw):
    nvd_raw["references"] = [{"url": "ftp://ftp.example.com/advisory.txt"}]
    assert str(parse(nvd_raw).references[0]) == "ftp://ftp.example.com/advisory.txt"


def test_adjacent_attack_vector_normalized(nvd_raw):
    data = nvd_raw["metrics"]["cvssMetricV31"][0]["cvssData"]
    data["attackVector"] = "ADJACENT"
    data["vectorString"] = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    data["baseScore"] = 8.8
    data["baseSeverity"] = "HIGH"
    assert parse(nvd_raw).preferred_cvss.attack_vector == "ADJACENT_NETWORK"


def test_bulk_kev_fetch_and_key_header(nvd_raw):
    calls = []

    def handler(request):
        calls.append(request)
        assert "hasKev" in request.url.params
        assert request.headers["apiKey"] == "test-key"
        assert "test-key" not in str(request.url)
        return httpx.Response(200, json=page([nvd_raw]))

    batch, _ = collect(handler)
    assert len(calls) == 1
    assert len(batch.records) == 1
    assert batch.missing_cves == []
    assert "test-key" not in batch.model_dump_json()


@pytest.mark.parametrize("api_key,interval", [("test-key", 0.65), ("", 6.1)])
def test_pagination_and_pacing(nvd_raw, api_key, interval):
    calls = []
    other = dict(nvd_raw, id="CVE-2026-12345")

    def handler(request):
        calls.append(request)
        start = int(request.url.params["startIndex"])
        return httpx.Response(
            200, json=page([nvd_raw if start == 0 else other], start=start, total=2)
        )

    batch, fake = collect(handler, ids=[nvd_raw["id"], other["id"]], api_key=api_key)
    assert len(batch.records) == 2
    assert len(calls) == 2
    assert fake.waits == [interval]


def test_missing_cve_fallback(nvd_raw):
    calls = []

    def handler(request):
        calls.append(request)
        if "hasKev" in request.url.params:
            return httpx.Response(200, json=page([nvd_raw]))
        assert request.url.params["cveId"] == "CVE-2026-12345"
        return httpx.Response(200, json=page([]))

    batch, _ = collect(handler, ids=[nvd_raw["id"], "CVE-2026-12345"])
    assert batch.missing_cves == ["CVE-2026-12345"]
    assert len(batch.records) == 1


def test_non_kev_cve_fallback(nvd_raw):
    def handler(request):
        rows = [] if "hasKev" in request.url.params else [nvd_raw]
        return httpx.Response(200, json=page(rows))

    batch, _ = collect(handler)
    assert len(batch.records) == 1


def test_retry_after_and_bounded_retry(nvd_raw):
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": "3"})
        return httpx.Response(200, json=page([nvd_raw]))

    _, fake = collect(handler)
    assert fake.waits == [3.0]
    assert calls == 2


@pytest.mark.parametrize("status", [401, 403, 404, 429, 503])
def test_http_failure(status):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status)

    with pytest.raises(NvdCollectionError, match=f"HTTP {status}"):
        collect(handler)
    assert len(calls) == (4 if status in {429, 503} else 1)


def test_transport_failure():
    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.ConnectError("test failure", request=request)

    with pytest.raises(NvdCollectionError, match="ConnectError"):
        collect(handler)
    assert len(calls) == 4


@pytest.mark.parametrize(
    "payload", [{}, [], {"startIndex": 0, "totalResults": 1, "vulnerabilities": []}]
)
def test_invalid_envelope(payload):
    with pytest.raises(NvdCollectionError):
        collect(lambda request: httpx.Response(200, json=payload))


def test_malformed_json_and_invalid_record(nvd_raw):
    with pytest.raises(NvdCollectionError, match="JSON"):
        collect(lambda request: httpx.Response(200, text="bad"))
    nvd_raw["published"] = "not-a-date"
    with pytest.raises(NvdCollectionError, match="validation"):
        collect(lambda request: httpx.Response(200, json=page([nvd_raw])))


def test_duplicate_and_partial_batch_failure(nvd_raw):
    with pytest.raises(NvdCollectionError, match="validation"):
        collect(lambda request: httpx.Response(200, json=page([nvd_raw, nvd_raw])))

    def handler(request):
        if request.url.params["startIndex"] == "0":
            return httpx.Response(200, json=page([nvd_raw], total=2))
        return httpx.Response(403)

    with pytest.raises(NvdCollectionError):
        collect(handler)


def test_no_cves_no_request():
    assert collect_nvd([]).records == []


def test_long_retry_after_is_not_ignored():
    with pytest.raises(NvdCollectionError, match="cooldown"):
        collect(lambda request: httpx.Response(429, headers={"Retry-After": "120"}))


def test_authenticated_window_stays_under_50_requests(nvd_raw):
    fake = FakeTime()
    starts = []

    def handler(request):
        starts.append(fake.clock())
        return httpx.Response(200, json=page([]))

    ids = [f"CVE-2026-{i:04}" for i in range(60)]
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        batch = collect_nvd(
            ids, api_key="test-key", client=client, sleep=fake.sleep, clock=fake.clock
        )
    assert len(batch.missing_cves) == 60
    assert len(starts) == 61
    assert max(sum(start <= t < start + 30 for t in starts) for start in starts) <= 50


def test_key_is_read_from_environment(nvd_raw, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "injected-test-key")

    def handler(request):
        assert request.headers["apiKey"] == "injected-test-key"
        return httpx.Response(200, json=page([nvd_raw]))

    fake = FakeTime()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        batch = collect_nvd(
            [nvd_raw["id"]], client=client, sleep=fake.sleep, clock=fake.clock
        )
    assert len(batch.records) == 1


def test_preferred_metric_uses_newest_version(nvd_raw):
    raw = nvd_raw["metrics"]["cvssMetricV31"][0]
    raw4 = deepcopy(raw)
    raw4["type"] = "Secondary"
    raw4["cvssData"] = {
        "version": "4.0",
        "vectorString": (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        ),
        "baseScore": 9.3,
        "baseSeverity": "CRITICAL",
        "attackVector": "NETWORK",
    }
    nvd_raw["metrics"]["cvssMetricV40"] = [raw4]
    assert parse(nvd_raw).preferred_cvss.version == "4.0"


def test_changed_total_rejects_partial_catalog(nvd_raw):
    def handler(request):
        start = int(request.url.params["startIndex"])
        return httpx.Response(
            200,
            json=page(
                [nvd_raw] if start == 0 else [dict(nvd_raw, id="CVE-2026-9999")],
                start=start,
                total=2 if start == 0 else 3,
            ),
        )

    with pytest.raises(NvdCollectionError, match="changed"):
        collect(handler)
