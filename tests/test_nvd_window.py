"""Complete publication-window collection, bounds, pacing, and pagination."""

from datetime import date

import httpx
import pytest
from tests.test_nvd import FakeTime
from tests.test_nvd import nvd_raw as raw_fixture

from threatpulse.nvd import NvdCollectionError, collect_nvd_window

nvd_raw = raw_fixture
START, END = date(2021, 12, 1), date(2022, 1, 1)


def page(rows, *, start=0, total=None, size=None):
    return {
        "startIndex": start,
        "totalResults": len(rows) if total is None else total,
        "resultsPerPage": len(rows) if size is None else size,
        "vulnerabilities": [{"cve": raw} for raw in rows],
    }


def collect(handler, **kwargs):
    fake = FakeTime()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = collect_nvd_window(
            START,
            END,
            client=client,
            api_key="test-key",
            sleep=fake.sleep,
            clock=fake.clock,
            **kwargs,
        )
        assert not client.is_closed
    return result, fake


def test_window_params_full_pagination_and_key(nvd_raw):
    requests = []

    def handler(request):
        requests.append(request)
        assert request.url.params["pubStartDate"] == "2021-12-01T00:00:00.000+00:00"
        assert request.url.params["pubEndDate"] == "2021-12-31T23:59:59.999+00:00"
        assert "hasKev" not in request.url.params
        assert "noRejected" not in request.url.params
        assert request.headers["apiKey"] == "test-key"
        start = int(request.url.params["startIndex"])
        row = nvd_raw if start == 0 else dict(nvd_raw, id="CVE-2021-9999")
        return httpx.Response(200, json=page([row], start=start, total=2, size=1))

    result, fake = collect(handler)
    assert len(result.records) == 2 and result.missing_cves == []
    assert fake.waits == [0.65]
    assert "test-key" not in result.model_dump_json()
    assert len(requests) == 2


def test_no_records():
    result, _ = collect(lambda request: httpx.Response(200, json=page([])))
    assert result.records == []


def test_window_cap_rejects_instead_of_truncates(nvd_raw):
    with pytest.raises(NvdCollectionError, match="max_records"):
        collect(
            lambda r: httpx.Response(200, json=page([nvd_raw], total=2)), max_records=1
        )


@pytest.mark.parametrize("change", ["total", "duplicate", "empty", "start"])
def test_changed_or_incomplete_page_rejected(nvd_raw, change):
    def handler(request):
        start = int(request.url.params["startIndex"])
        data = page([nvd_raw], start=start, total=2, size=1)
        if start:
            if change == "total":
                data["totalResults"] = 3
            elif change == "empty":
                data["vulnerabilities"] = []
            elif change == "start":
                data["startIndex"] = 0
        return httpx.Response(200, json=data)

    with pytest.raises(NvdCollectionError):
        collect(handler)


@pytest.mark.parametrize(
    "published", ["2021-11-30T23:59:59.999", "2022-01-01T00:00:00"]
)
def test_outside_half_open_window(nvd_raw, published):
    nvd_raw["published"] = published
    with pytest.raises(NvdCollectionError, match="validation"):
        collect(lambda r: httpx.Response(200, json=page([nvd_raw])))


def test_start_boundary_is_included(nvd_raw):
    nvd_raw["published"] = "2021-12-01T00:00:00.000"
    result, _ = collect(lambda r: httpx.Response(200, json=page([nvd_raw])))
    assert len(result.records) == 1


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {
            "startIndex": 0,
            "totalResults": True,
            "resultsPerPage": 0,
            "vulnerabilities": [],
        },
        {
            "startIndex": 0,
            "totalResults": 2,
            "resultsPerPage": 2,
            "vulnerabilities": [],
        },
    ],
)
def test_invalid_envelope(payload):
    with pytest.raises(NvdCollectionError):
        collect(lambda r: httpx.Response(200, json=payload))


def test_http_failure_on_later_page_rejects_batch(nvd_raw):
    def handler(request):
        if request.url.params["startIndex"] == "0":
            return httpx.Response(200, json=page([nvd_raw], total=2))
        return httpx.Response(403)

    with pytest.raises(NvdCollectionError, match="403"):
        collect(handler)


@pytest.mark.parametrize(
    "start,end", [(END, START), (START, START), (date(2021, 1, 1), date(2022, 1, 1))]
)
def test_invalid_window_before_requests(start, end):
    with pytest.raises(ValueError):
        collect_nvd_window(start, end)
