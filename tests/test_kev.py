"""Offline collector and command tests using mock HTTP responses."""

import json
from pathlib import Path

import httpx
import pytest

from threatpulse.kev import CISA_KEV_URL, KevCollectionError, collect_kev, main


@pytest.fixture
def record():
    return json.loads(
        (Path(__file__).parent / "fixtures" / "cisa_kev_record.json").read_text()
    )


def collect(payload, status=200):
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(status, json=payload)
        )
    ) as client:
        return collect_kev(client=client)


def test_collect_maps_entire_batch(record):
    second = dict(record, cveID="CVE-2026-12345")

    def respond(request):
        assert str(request.url) == CISA_KEV_URL
        assert request.extensions["timeout"]["read"] == 30.0
        return httpx.Response(
            200, json={"count": 2, "vulnerabilities": [record, second]}
        )

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        catalog = collect_kev(client=client)
        assert not client.is_closed
    assert len(catalog.records) == 2
    assert catalog.records[1].vulnerability.cve_id == second["cveID"]
    assert catalog.records[0].kev.raw_record == record
    assert catalog.records[0].kev.ingested_at == catalog.records[1].kev.ingested_at


@pytest.mark.parametrize("status", [403, 404, 429, 500])
def test_http_failure(status):
    with pytest.raises(KevCollectionError, match=f"HTTP {status}"):
        collect({}, status=status)


@pytest.mark.parametrize("exception", [httpx.ReadTimeout, httpx.ConnectError])
def test_transport_failure(exception):
    def fail(request):
        raise exception("test failure", request=request)

    with httpx.Client(transport=httpx.MockTransport(fail)) as client:
        with pytest.raises(KevCollectionError, match=exception.__name__):
            collect_kev(client=client)


def test_invalid_json():
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, text="<html>")
        )
    ) as client:
        with pytest.raises(KevCollectionError, match="not valid JSON"):
            collect_kev(client=client)


@pytest.mark.parametrize(
    "payload", [[], {}, {"vulnerabilities": {}}, {"vulnerabilities": []}]
)
def test_invalid_catalog(payload):
    with pytest.raises(KevCollectionError):
        collect(payload)


@pytest.mark.parametrize("count", [0, "1", True])
def test_count_mismatch(record, count):
    with pytest.raises(KevCollectionError, match="count"):
        collect({"count": count, "vulnerabilities": [record]})


def test_invalid_record_fails_whole_batch(record):
    with pytest.raises(KevCollectionError, match="record 1 failed validation"):
        collect({"vulnerabilities": [record, {"cveID": "bad"}]})


def test_non_object_record(record):
    with pytest.raises(KevCollectionError, match="must be an object"):
        collect({"vulnerabilities": [record, None]})


def test_duplicate_cve(record):
    with pytest.raises(KevCollectionError, match="Duplicate CVE"):
        collect({"vulnerabilities": [record, record]})


def test_invalid_timeout():
    with pytest.raises(ValueError, match="positive"):
        collect_kev(timeout=0)


def test_cli_export(record, monkeypatch, tmp_path, capsys):
    catalog = collect({"vulnerabilities": [record]})
    monkeypatch.setattr("threatpulse.kev.collect_kev", lambda **kwargs: catalog)
    output = tmp_path / "kev.json"
    assert main(["--output", str(output)]) == 0
    assert json.loads(output.read_text())["records"][0]["kev"]["raw_record"] == record
    assert json.loads(capsys.readouterr().out)["records"] == 1
    assert main(["--output", str(output)]) == 1
    assert "Collection failed" in capsys.readouterr().err
    assert json.loads(output.read_text())["records"][0]["kev"]["raw_record"] == record


def test_cli_collection_failure(monkeypatch, capsys):
    def fail(**kwargs):
        raise KevCollectionError("test failure")

    monkeypatch.setattr("threatpulse.kev.collect_kev", fail)
    assert main([]) == 1
    assert "test failure" in capsys.readouterr().err
