"""Collect dated EPSS probabilities from FIRST's public API."""

from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Annotated, Any

import httpx
from pydantic import (
    AwareDatetime,
    BaseModel,
    Field,
    HttpUrl,
    TypeAdapter,
    ValidationError,
)

from threatpulse.models import CveId

EPSS_URL = "https://api.first.org/data/v1/epss"
Probability = Annotated[Decimal, Field(ge=0, le=1, allow_inf_nan=False)]


class EpssCollectionError(Exception):
    """EPSS could not be retrieved and validated as a complete batch."""


class EpssObservation(BaseModel):
    cve_id: CveId
    score_date: date
    epss: Probability
    percentile: Probability
    source_url: HttpUrl
    ingested_at: AwareDatetime
    raw_record: dict[str, Any]


class EpssBatch(BaseModel):
    observations: list[EpssObservation]
    missing_cves: list[CveId]


def collect_epss(
    cve_ids: list[str],
    *,
    score_date: date | None = None,
    client: httpx.Client | None = None,
    timeout: float = 30.0,
) -> EpssBatch:
    """Fetch stored CVEs in chunks, pinning all chunks to one score date.

    The first returned score date selects the latest available date when the
    caller omits it. Missing CVEs remain explicit and never receive zero scores.
    Each chunk is small enough to fit FIRST's 2,000-character CVE filter limit.
    A partial or malformed response rejects the entire collection.
    """
    ids = sorted(set(TypeAdapter(list[CveId]).validate_python(cve_ids)))
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if not ids:
        return EpssBatch(observations=[], missing_cves=[])
    if client is None:
        with httpx.Client() as owned_client:
            return collect_epss(
                ids, score_date=score_date, client=owned_client, timeout=timeout
            )
    chunks: list[list[str]] = []
    chunk: list[str] = []
    for cve in ids:
        # Leave space for URL-encoded commas and provenance URL validation.
        if len(cve) > 1200:
            raise ValueError("CVE identifier exceeds the API filter limit")
        if chunk and len(",".join([*chunk, cve])) > 1200:
            chunks.append(chunk)
            chunk = []
        chunk.append(cve)
    chunks.append(chunk)
    observations = []
    seen: set[str] = set()
    ingested_at = datetime.now(UTC)
    for chunk in chunks:
        params = {"cve": ",".join(chunk), "limit": str(len(chunk))}
        if score_date is not None:
            params["date"] = score_date.isoformat()
        try:
            response = client.get(EPSS_URL, params=params, timeout=timeout)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise EpssCollectionError(
                f"EPSS request failed with HTTP {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise EpssCollectionError(
                f"EPSS request failed ({type(exc).__name__})"
            ) from exc
        try:
            payload = response.json()
        except ValueError as exc:
            raise EpssCollectionError("EPSS response is not valid JSON") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("status") != "OK"
            or not isinstance(payload.get("data"), list)
        ):
            raise EpssCollectionError("EPSS response has an invalid envelope")
        data = payload["data"]
        # FIRST may omit unknown CVEs, but must not silently paginate our chunk.
        if (
            type(payload.get("total")) is not int
            or payload["total"] != len(data)
            or payload.get("offset") != 0
        ):
            raise EpssCollectionError("EPSS response is incomplete or paginated")
        for raw in data:
            if not isinstance(raw, dict):
                raise EpssCollectionError("EPSS record must be an object")
            try:
                observation = EpssObservation.model_validate(
                    {
                        "cve_id": raw.get("cve"),
                        "score_date": raw.get("date"),
                        "epss": raw.get("epss"),
                        "percentile": raw.get("percentile"),
                        "source_url": str(response.request.url),
                        "ingested_at": ingested_at,
                        "raw_record": raw.copy(),
                    }
                )
            except ValidationError as exc:
                raise EpssCollectionError("EPSS record failed validation") from exc
            if observation.cve_id not in chunk or observation.cve_id in seen:
                raise EpssCollectionError(
                    "EPSS returned an unexpected or duplicate CVE"
                )
            if score_date is None:
                score_date = observation.score_date
            if observation.score_date != score_date:
                raise EpssCollectionError("EPSS returned inconsistent score dates")
            seen.add(observation.cve_id)
            observations.append(observation)
    return EpssBatch(observations=observations, missing_cves=sorted(set(ids) - seen))
