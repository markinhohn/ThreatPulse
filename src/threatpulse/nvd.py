"""Rate-limited enrichment from the official NVD CVE API 2.0."""

import os
import time
from copy import deepcopy
from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated, Any, Literal

import httpx
from cvss import CVSS2, CVSS3, CVSS4
from pydantic import (
    AnyUrl,
    AwareDatetime,
    BaseModel,
    Field,
    HttpUrl,
    TypeAdapter,
    ValidationError,
    model_validator,
)

from threatpulse.models import CveId, RequiredText

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
BaseScore = Annotated[Decimal, Field(ge=0, le=10, allow_inf_nan=False)]
Severity = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class NvdCollectionError(Exception):
    """The NVD batch could not be completely fetched and validated."""


class CvssMetric(BaseModel):
    version: Literal["2.0", "3.0", "3.1", "4.0"]
    source: RequiredText
    metric_type: Literal["Primary", "Secondary"]
    vector: RequiredText
    base_score: BaseScore
    severity: Severity
    attack_vector: Literal["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"]

    @model_validator(mode="after")
    def validate_vector(self):
        engine = {"2.0": CVSS2, "3.0": CVSS3, "3.1": CVSS3, "4.0": CVSS4}
        if self.version != "2.0" and not self.vector.startswith(
            f"CVSS:{self.version}/"
        ):
            raise ValueError("CVSS version and vector prefix disagree")
        try:
            parsed = engine[self.version](self.vector)
        except Exception as exc:
            raise ValueError("Invalid CVSS vector") from exc
        # For v4, the vector can include threat/environmental metrics. NVD's
        # baseScore refers to the base metric set, so calculate only that set.
        if self.version == "4.0":
            base_names = {
                "AV",
                "AC",
                "AT",
                "PR",
                "UI",
                "VC",
                "VI",
                "VA",
                "SC",
                "SI",
                "SA",
            }
            base_vector = "CVSS:4.0/" + "/".join(
                f"{name}:{value}"
                for name, value in parsed.metrics.items()
                if name in base_names
            )
            parsed = CVSS4(base_vector)
        score = Decimal(str(parsed.scores()[0]))
        if score != self.base_score:
            raise ValueError("CVSS vector and base score disagree")
        if parsed.severities()[0].upper() != self.severity:
            raise ValueError("CVSS severity and base score disagree")
        av = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}
        if av[parsed.metrics["AV"]] != self.attack_vector:
            raise ValueError("CVSS vector and attack vector disagree")
        return self


class NvdRecord(BaseModel):
    cve_id: CveId
    published_at: AwareDatetime
    modified_at: AwareDatetime
    status: RequiredText
    description: str | None
    references: list[AnyUrl]
    weaknesses: list[str]
    cvss_metrics: list[CvssMetric]
    source_url: HttpUrl
    ingested_at: AwareDatetime
    raw_record: dict[str, Any]

    @property
    def preferred_cvss(self) -> CvssMetric | None:
        """Prefer newer versions, then Primary, with a deterministic tie-break."""
        return min(
            self.cvss_metrics,
            key=lambda m: (
                -float(m.version),
                m.metric_type != "Primary",
                m.source,
                m.vector,
            ),
            default=None,
        )


class NvdBatch(BaseModel):
    records: list[NvdRecord]
    missing_cves: list[CveId]


def _utc_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("NVD timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    # NVD API timestamps omit an offset but are specified in UTC.
    return (
        parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    )


def parse_nvd_record(
    raw: dict[str, Any], *, source_url: str, ingested_at: datetime
) -> NvdRecord:
    """Normalize a source CVE while retaining all original technical context."""
    metrics = []
    groups = raw.get("metrics", {})
    for group, version in [
        ("cvssMetricV2", "2.0"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV40", "4.0"),
    ]:
        for metric in groups.get(group, []):
            data = metric["cvssData"]
            metrics.append(
                CvssMetric(
                    version=data["version"],
                    source=metric["source"],
                    metric_type=metric["type"],
                    vector=data["vectorString"],
                    base_score=data["baseScore"],
                    severity=(
                        metric["baseSeverity"]
                        if version == "2.0"
                        else data["baseSeverity"]
                    ),
                    attack_vector=(
                        "ADJACENT_NETWORK"
                        if data.get("attackVector") == "ADJACENT"
                        else data[
                            "accessVector" if version == "2.0" else "attackVector"
                        ]
                    ),
                )
            )
            if metrics[-1].version != version:
                raise ValueError("NVD metric group and CVSS version disagree")
    return NvdRecord(
        cve_id=raw["id"],
        published_at=_utc_timestamp(raw["published"]),
        modified_at=_utc_timestamp(raw["lastModified"]),
        status=raw["vulnStatus"],
        description=next(
            (d["value"] for d in raw.get("descriptions", []) if d["lang"] == "en"), None
        ),
        references=[r["url"] for r in raw.get("references", [])],
        weaknesses=sorted(
            {
                d["value"]
                for w in raw.get("weaknesses", [])
                for d in w["description"]
                if d["lang"] == "en"
            }
        ),
        cvss_metrics=metrics,
        source_url=source_url,
        ingested_at=ingested_at,
        raw_record=deepcopy(raw),
    )


class _NvdRequests:
    def __init__(self, client, api_key, timeout, sleep, clock):
        self.client, self.api_key, self.timeout = client, api_key, timeout
        self.sleep, self.clock = sleep, clock
        self.interval = 0.65 if api_key else 6.1
        self.last_request = None

    def fetch(self, params):
        for attempt in range(4):
            if self.last_request is not None:
                wait = self.interval - (self.clock() - self.last_request)
                if wait > 0:
                    self.sleep(wait)
            self.last_request = self.clock()
            try:
                response = self.client.get(
                    NVD_URL,
                    params=params,
                    timeout=self.timeout,
                    headers={"apiKey": self.api_key} if self.api_key else {},
                )
            except httpx.RequestError as exc:
                if attempt == 3:
                    raise NvdCollectionError(
                        f"NVD request failed ({type(exc).__name__})"
                    ) from exc
                self.sleep(2**attempt)
                continue
            if response.status_code in {429, 500, 502, 503, 504} and attempt < 3:
                retry = response.headers.get("Retry-After")
                if retry:
                    try:
                        wait = float(retry)
                    except ValueError:
                        from email.utils import parsedate_to_datetime

                        try:
                            wait = (
                                parsedate_to_datetime(retry) - datetime.now(UTC)
                            ).total_seconds()
                        except (ValueError, TypeError) as exc:
                            raise NvdCollectionError(
                                "Invalid NVD Retry-After header"
                            ) from exc
                    if wait > 60:
                        raise NvdCollectionError(
                            "NVD requests a cooldown over 60 seconds; retry later"
                        )
                else:
                    wait = 2**attempt
                self.sleep(max(self.interval, wait))
                continue
            if response.status_code >= 400:
                raise NvdCollectionError(
                    f"NVD request failed with HTTP {response.status_code}"
                )
            try:
                payload = response.json()
            except ValueError as exc:
                raise NvdCollectionError("NVD response is not valid JSON") from exc
            return payload, str(response.request.url)
        raise NvdCollectionError("NVD retries exhausted")


def collect_nvd(
    cve_ids: list[str],
    *,
    api_key: str | None = None,
    client: httpx.Client | None = None,
    timeout: float = 30.0,
    sleep=time.sleep,
    clock=time.monotonic,
) -> NvdBatch:
    """Fetch NVD's KEV-filtered pages, then look up any remaining CVEs.

    This reduces the initial KEV enrichment to a few API calls instead of one
    per CVE. Other stored CVEs still work through individual fallback lookups.
    Rate limits are per collector process; do not run concurrent collectors.
    """
    ids = set(TypeAdapter(list[CveId]).validate_python(cve_ids))
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if not ids:
        return NvdBatch(records=[], missing_cves=[])
    if api_key is None:
        api_key = os.environ.get("NVD_API_KEY") or None
    if client is None:
        with httpx.Client() as owned_client:
            return collect_nvd(
                sorted(ids),
                api_key=api_key,
                client=owned_client,
                timeout=timeout,
                sleep=sleep,
                clock=clock,
            )
    requests = _NvdRequests(client, api_key, timeout, sleep, clock)
    records = {}
    ingested_at = datetime.now(UTC)

    def read_page(params, expected_start):
        payload, source_url = requests.fetch(params)
        if (
            not isinstance(payload, dict)
            or type(payload.get("totalResults")) is not int
            or payload["totalResults"] < 0
            or type(payload.get("startIndex")) is not int
            or payload.get("startIndex") != expected_start
            or not isinstance(payload.get("vulnerabilities"), list)
        ):
            raise NvdCollectionError("Invalid NVD response envelope")
        rows = payload["vulnerabilities"]
        if expected_start + len(rows) > payload["totalResults"] or (
            not rows and payload["totalResults"] > expected_start
        ):
            raise NvdCollectionError("Incomplete NVD page")
        for wrapper in rows:
            try:
                raw = wrapper["cve"]
                cve_id = TypeAdapter(CveId).validate_python(raw["id"])
                if "cveId" in params and cve_id != params["cveId"]:
                    raise ValueError("NVD returned an unrequested CVE")
                if cve_id in ids:
                    if cve_id in records:
                        raise ValueError("NVD returned a duplicate CVE")
                    records[cve_id] = parse_nvd_record(
                        raw, source_url=source_url, ingested_at=ingested_at
                    )
            except (
                ValidationError,
                ValueError,
                KeyError,
                TypeError,
                AttributeError,
            ) as exc:
                raise NvdCollectionError("NVD record failed validation") from exc
        return len(rows), payload["totalResults"]

    start, total = 0, None
    while True:
        length, observed_total = read_page(
            {"hasKev": "", "resultsPerPage": "2000", "startIndex": str(start)}, start
        )
        if total is not None and observed_total != total:
            raise NvdCollectionError("NVD catalog changed during pagination; retry")
        total = observed_total
        start += length
        if start >= total:
            break
    for cve_id in sorted(ids - records.keys()):
        length, total = read_page({"cveId": cve_id}, 0)
        if total != length or total > 1:
            raise NvdCollectionError("Unexpected NVD CVE lookup count")
    return NvdBatch(
        records=[records[cve_id] for cve_id in sorted(records)],
        missing_cves=sorted(ids - records.keys()),
    )
