"""Strict response-header codec and one-shot candidate body adapter."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import asdict, dataclass, fields
from datetime import datetime
from typing import Any, Iterable, Mapping

from tools.evidence import release_candidate_contract as contract
from tools.evidence.release_candidate_provider import (
    MAX_RAW_ZIP_BYTES,
    ProviderArtifactObservation,
)
from tools.evidence.release_candidate_stream import (
    CACHE_CONTROL,
    CONTENT_TYPE,
    MAX_OBSERVATION_BYTES,
    MAX_OBSERVATION_HEADER_CHARS,
    RESPONSE_SCHEMA,
    CandidateReaderAuthority,
    CandidateStreamResponse,
)
from tools.evidence.release_canonical import canonical_json_bytes

_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]+\Z", re.ASCII)
_POSITIVE_INTEGER_RE = re.compile(r"[1-9][0-9]*\Z", re.ASCII)
_REQUIRED_HEADERS = frozenset(
    {
        "content-length",
        "content-type",
        "cache-control",
        "x-content-type-options",
        "x-dpone-response-schema",
        "x-dpone-request-id",
        "x-dpone-provider-observation",
        "x-dpone-provider-observation-sha256",
        "x-dpone-candidate-reader-service-identity",
        "x-dpone-candidate-reader-service-version-id",
    }
)
_APPLICATION_HEADERS = frozenset(
    key for key in _REQUIRED_HEADERS if key.startswith("x-dpone-")
)
_FORBIDDEN_HEADERS = frozenset(
    {"content-encoding", "location", "set-cookie", "transfer-encoding"}
)
_OBSERVATION_FIELDS = frozenset(
    item.name for item in fields(ProviderArtifactObservation)
)


@dataclass(slots=True)
class VerifiedCandidateStream:
    """Validated response metadata and a body that may be consumed once."""

    observation: ProviderArtifactObservation
    content_length: int
    _response: CandidateStreamResponse
    _consumed: bool = False

    def chunks(self, *, maximum_bytes: int) -> Iterable[bytes]:
        """Yield exactly the declared bytes once and reject partial/replayed use."""

        if self._consumed:
            raise contract.CandidateHandoffError(
                "candidate broker stream was already consumed"
            )
        if (
            type(maximum_bytes) is not int
            or not 1 <= maximum_bytes <= MAX_RAW_ZIP_BYTES
        ):
            raise contract.CandidateHandoffError("candidate stream limit is invalid")
        if self.content_length > maximum_bytes:
            raise contract.CandidateHandoffError(
                "candidate stream exceeds caller limit"
            )
        self._consumed = True
        observed = 0
        for chunk in self._response.chunks(maximum_bytes=maximum_bytes):
            if not isinstance(chunk, bytes) or not chunk:
                raise contract.CandidateHandoffError(
                    "candidate broker stream yielded an invalid chunk"
                )
            observed += len(chunk)
            if observed > self.content_length:
                raise contract.CandidateHandoffError(
                    "candidate broker stream exceeded Content-Length"
                )
            yield chunk
        if observed != self.content_length:
            raise contract.CandidateHandoffError(
                "candidate broker stream ended before Content-Length"
            )


def open_candidate_stream(
    response: CandidateStreamResponse,
    binding: contract.ArtifactBinding,
    *,
    expected_request_id: str,
    authority: CandidateReaderAuthority,
    now: datetime,
) -> VerifiedCandidateStream:
    """Validate status and headers before making any body byte available."""

    if type(response.status_code) is not int or response.status_code != 200:
        raise contract.CandidateHandoffError("candidate broker did not return 200")
    headers = _normalize_headers(response.headers)
    _require_header_contract(headers)
    if _REQUEST_ID_RE.fullmatch(expected_request_id) is None:
        raise contract.CandidateHandoffError("candidate request identity is invalid")
    if headers["x-dpone-request-id"] != expected_request_id:
        raise contract.CandidateHandoffError("candidate response request mismatch")
    observation = decode_observation_header(
        headers["x-dpone-provider-observation"],
        headers["x-dpone-provider-observation-sha256"],
    )
    observation.require_matches(binding, now=now)
    if observation.broker_request_id != expected_request_id:
        raise contract.CandidateHandoffError("observation request identity mismatch")
    expected_service = {
        "x-dpone-candidate-reader-service-identity": authority.service_identity,
        "x-dpone-candidate-reader-service-version-id": authority.service_version_id,
    }
    for key, expected in expected_service.items():
        if headers[key] != expected:
            raise contract.CandidateHandoffError("candidate reader authority mismatch")
    if (
        observation.candidate_reader_service_identity != authority.service_identity
        or observation.candidate_reader_service_version_id
        != authority.service_version_id
    ):
        raise contract.CandidateHandoffError("observation service authority mismatch")
    content_length = _content_length(headers["content-length"])
    if content_length != observation.artifact_size_bytes:
        raise contract.CandidateHandoffError("candidate Content-Length mismatch")
    return VerifiedCandidateStream(observation, content_length, response)


def encode_observation_header(observation: ProviderArtifactObservation) -> str:
    """Return unpadded base64url of exact canonical observation bytes."""

    raw = canonical_json_bytes(asdict(observation))
    if len(raw) > MAX_OBSERVATION_BYTES:
        raise contract.CandidateHandoffError("provider observation exceeds byte limit")
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    if len(encoded) > MAX_OBSERVATION_HEADER_CHARS:
        raise contract.CandidateHandoffError("provider observation header is too long")
    return encoded


def observation_sha256(observation: ProviderArtifactObservation) -> str:
    """Hash the exact canonical bytes carried in the observation header."""

    raw = canonical_json_bytes(asdict(observation))
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def response_headers(observation: ProviderArtifactObservation) -> dict[str, str]:
    """Generate the broker's normalized closed application header envelope."""

    return {
        "content-length": str(observation.artifact_size_bytes),
        "content-type": CONTENT_TYPE,
        "cache-control": CACHE_CONTROL,
        "x-content-type-options": "nosniff",
        "x-dpone-response-schema": RESPONSE_SCHEMA,
        "x-dpone-request-id": observation.broker_request_id,
        "x-dpone-provider-observation": encode_observation_header(observation),
        "x-dpone-provider-observation-sha256": observation_sha256(observation),
        "x-dpone-candidate-reader-service-identity": (
            observation.candidate_reader_service_identity
        ),
        "x-dpone-candidate-reader-service-version-id": (
            observation.candidate_reader_service_version_id
        ),
    }


def decode_observation_header(
    encoded: str, expected_digest: str
) -> ProviderArtifactObservation:
    """Decode only canonical, duplicate-free JSON with an exact tagged digest."""

    contract.require_digest(expected_digest, "provider observation digest")
    if (
        not isinstance(encoded, str)
        or not 1 <= len(encoded) <= MAX_OBSERVATION_HEADER_CHARS
        or _B64URL_RE.fullmatch(encoded) is None
    ):
        raise contract.CandidateHandoffError("provider observation header is invalid")
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, UnicodeError) as exc:
        raise contract.CandidateHandoffError(
            "provider observation header is invalid"
        ) from exc
    if len(raw) > MAX_OBSERVATION_BYTES:
        raise contract.CandidateHandoffError("provider observation exceeds byte limit")
    actual_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if actual_digest != expected_digest:
        raise contract.CandidateHandoffError("provider observation digest mismatch")
    document = _canonical_document(raw)
    if set(document) != _OBSERVATION_FIELDS:
        raise contract.CandidateHandoffError("provider observation keys mismatch")
    try:
        return ProviderArtifactObservation(**document)
    except TypeError as exc:
        raise contract.CandidateHandoffError(
            "provider observation fields are invalid"
        ) from exc


def _normalize_headers(raw: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(raw, Mapping):
        raise contract.CandidateHandoffError("candidate response headers are invalid")
    normalized: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise contract.CandidateHandoffError("candidate response header is invalid")
        lowered = key.lower()
        if lowered in normalized or "\r" in value or "\n" in value:
            raise contract.CandidateHandoffError(
                "candidate response header is duplicated or unsafe"
            )
        normalized[lowered] = value
    return normalized


def _require_header_contract(headers: Mapping[str, str]) -> None:
    if not _REQUIRED_HEADERS.issubset(headers):
        raise contract.CandidateHandoffError("candidate response header is missing")
    if _FORBIDDEN_HEADERS.intersection(headers):
        raise contract.CandidateHandoffError(
            "candidate response redirects are forbidden"
        )
    observed_application = {key for key in headers if key.startswith("x-dpone-")}
    if observed_application != _APPLICATION_HEADERS:
        raise contract.CandidateHandoffError(
            "candidate application headers are not exact"
        )
    constants = {
        "content-type": CONTENT_TYPE,
        "cache-control": CACHE_CONTROL,
        "x-content-type-options": "nosniff",
        "x-dpone-response-schema": RESPONSE_SCHEMA,
    }
    if any(headers[key] != value for key, value in constants.items()):
        raise contract.CandidateHandoffError("candidate response header mismatch")


def _content_length(value: str) -> int:
    if _POSITIVE_INTEGER_RE.fullmatch(value) is None:
        raise contract.CandidateHandoffError("candidate Content-Length is invalid")
    parsed = int(value)
    if parsed > MAX_RAW_ZIP_BYTES:
        raise contract.CandidateHandoffError("candidate Content-Length exceeds limit")
    return parsed


def _canonical_document(raw: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise contract.CandidateHandoffError(
            "provider observation JSON is invalid"
        ) from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise contract.CandidateHandoffError("provider observation is not canonical")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_number(value: str) -> Any:
    raise ValueError(f"unsupported JSON number: {value}")
