"""Offline FIRST API contract tests."""

from datetime import date
from decimal import Decimal

import httpx
import pytest

from threatpulse.epss import EpssCollectionError, collect_epss

ROW = {
    "cve": "CVE-2021-44228",
    "epss": "0.943210000",
    "percentile": "0.999000000",
    "date": "2026-01-01",
}


def envelope(rows):
    return {"status": "OK", "total": len(rows), "offset": 0, "data": rows}


def collect(payload):
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=payload))
    ) as client:
        return collect_epss([ROW["cve"], "CVE-2026-12345"], client=client)


def test_decimal_scores_and_missing_cves():
    batch = collect(envelope([ROW]))
    score = batch.observations[0]
    assert score.epss == Decimal("0.943210000")
    assert score.percentile == Decimal("0.999000000")
    assert score.score_date == date(2026, 1, 1)
    assert score.raw_record == ROW
    assert "cve=" in str(score.source_url)
    assert batch.missing_cves == ["CVE-2026-12345"]


def test_chunking_and_date_pinning():
    ids = [f"CVE-2026-{i:04}" for i in range(300)]
    requests = []

    def respond(request):
        requests.append(request)
        cves = request.url.params["cve"].split(",")
        assert len(request.url.params["cve"]) <= 2000
        assert request.url.params["limit"] == str(len(cves))
        if len(requests) > 1:
            assert request.url.params["date"] == "2026-01-01"
        return httpx.Response(200, json=envelope([dict(ROW, cve=cve) for cve in cves]))

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        batch = collect_epss(ids, client=client)
        assert not client.is_closed
    assert len(requests) > 1
    assert len(batch.observations) == 300
    assert batch.missing_cves == []


def test_explicit_date_rejects_wrong_response_date():
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=envelope([ROW]))
        )
    ) as client:
        with pytest.raises(EpssCollectionError, match="dates"):
            collect_epss([ROW["cve"]], score_date=date(2025, 1, 1), client=client)


@pytest.mark.parametrize(
    "field,value",
    [
        ("epss", "1.01"),
        ("epss", "-0.1"),
        ("epss", "NaN"),
        ("percentile", "Infinity"),
        ("percentile", "2"),
        ("date", "2026-02-30"),
        ("epss", None),
    ],
)
def test_invalid_record(field, value):
    with pytest.raises(EpssCollectionError, match="validation"):
        collect(envelope([dict(ROW, **{field: value})]))


@pytest.mark.parametrize(
    "payload",
    [
        {},
        [],
        {"status": "ERROR", "data": []},
        {"status": "OK", "data": [], "total": 1, "offset": 0},
        {"status": "OK", "data": [], "total": 0, "offset": 1},
    ],
)
def test_invalid_or_incomplete_envelope(payload):
    with pytest.raises(EpssCollectionError):
        collect(payload)


def test_duplicate_and_unrequested_records():
    for rows in [[ROW, ROW], [dict(ROW, cve="CVE-2020-1234")]]:
        with pytest.raises(EpssCollectionError, match="unexpected or duplicate"):
            collect(envelope(rows))


def test_missing_is_not_zero():
    batch = collect(envelope([]))
    assert batch.observations == []
    assert len(batch.missing_cves) == 2


@pytest.mark.parametrize("status", [403, 429, 500])
def test_http_errors(status):
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(status))
    ) as client:
        with pytest.raises(EpssCollectionError, match=f"HTTP {status}"):
            collect_epss([ROW["cve"]], client=client)


def test_timeout_and_invalid_json():
    def fail(request):
        raise httpx.ReadTimeout("timeout", request=request)

    for handler in [fail, lambda request: httpx.Response(200, text="bad JSON")]:
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(EpssCollectionError):
                collect_epss([ROW["cve"]], client=client)


def test_no_ids_performs_no_request():
    assert collect_epss([]).observations == []


def test_later_chunk_failure_rejects_entire_collection():
    calls = 0

    def respond(request):
        nonlocal calls
        calls += 1
        if calls == 2:
            return httpx.Response(500)
        return httpx.Response(
            200,
            json=envelope(
                [dict(ROW, cve=cve) for cve in request.url.params["cve"].split(",")]
            ),
        )

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(EpssCollectionError):
            collect_epss([f"CVE-2026-{i:04}" for i in range(300)], client=client)
    assert calls == 2
