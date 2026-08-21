"""Executable verification adapters for contextual and binary wire fixtures.

The operation registry contains a small set of contracts whose authority is
owned by a deeper provider or receipt-chain verifier.  This module gives those
contracts one uniform verification boundary without weakening their original
context requirements.  In particular, response expectations are loaded from
independent request fixtures or fixed workflow invocation values; they are
never inferred from the response being verified.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping

from tools.evidence import release_candidate_contract as candidate_contract
from tools.evidence import release_candidate_provider as candidate_provider
from tools.evidence import release_candidate_stream as candidate_stream
from tools.evidence import release_candidate_stream_response as candidate_response
from tools.evidence import release_controller_activation_proof as activation
from tools.evidence import release_controller_exchange as exchange
from tools.evidence.release_canonical import canonical_json_bytes

_CANDIDATE_NOW = datetime(2026, 8, 15, 0, 0, 30, tzinfo=timezone.utc)
_ACTIVATION_NOW = datetime(2026, 8, 15, 0, 0, 30, tzinfo=timezone.utc)
_ACTIVATION_REQUEST_ID = "request-01HXDPONE"
_CANDIDATE_SERVICE_IDENTITY = (
    "cloudflare-worker:account-01/dpone-release-candidate-reader@"
    "candidate-reader-version-01"
)
_CANDIDATE_SERVICE_VERSION_ID = "candidate-reader-version-01"


class DelegatedWireVerificationError(ValueError):
    """A contextual fixture cannot pass its production verifier boundary."""


@dataclass(frozen=True, slots=True)
class _FrozenClock:
    instant: datetime

    def now(self) -> datetime:
        return self.instant


@dataclass(slots=True)
class _MemoryCandidateResponse:
    """One-shot provider response used only at the verification boundary."""

    body: bytes
    headers: Mapping[str, str]
    status_code: int = 200
    consumed: bool = False

    def chunks(self, *, maximum_bytes: int) -> Iterable[bytes]:
        if self.consumed:
            raise DelegatedWireVerificationError("candidate body was consumed twice")
        self.consumed = True
        if len(self.body) > maximum_bytes:
            raise DelegatedWireVerificationError("candidate body exceeds limit")
        for offset in range(0, len(self.body), 64 * 1024):
            yield self.body[offset : offset + 64 * 1024]


def verify_delegated_fixture(
    schema_id: str,
    body: bytes,
    headers: Mapping[str, str] | None,
    *,
    fixture_root: Path,
) -> None:
    """Run one delegated fixture through its real builder/parser/verifier pair."""

    verifiers = {
        activation.REQUEST_SCHEMA: _verify_activation_request,
        activation.RESPONSE_SCHEMA: _verify_activation_response,
        candidate_stream.REQUEST_SCHEMA: _verify_candidate_request,
        candidate_stream.RESPONSE_SCHEMA: _verify_candidate_response,
        exchange.CANDIDATE_ADMIT_REQUEST_SCHEMA: _verify_candidate_admit_request,
        exchange.CANDIDATE_ADMIT_RESPONSE_SCHEMA: _verify_candidate_admit_response,
    }
    try:
        verifier = verifiers[schema_id]
    except KeyError as exc:
        raise DelegatedWireVerificationError(
            f"unknown delegated schema: {schema_id}"
        ) from exc
    verifier(body, headers, fixture_root)


def _verify_activation_request(
    body: bytes, headers: Mapping[str, str] | None, fixture_root: Path
) -> None:
    _no_headers(headers)
    parsed = activation.parse_request(body)
    if parsed != {"schema": activation.REQUEST_SCHEMA, "schema_version": 1}:
        raise DelegatedWireVerificationError("activation request projection drift")
    if activation.request_bytes() != body:
        raise DelegatedWireVerificationError("activation request builder drift")


def _verify_activation_response(
    body: bytes, headers: Mapping[str, str] | None, fixture_root: Path
) -> None:
    _no_headers(headers)
    expected = activation.ExpectedControllerRun(
        repository_id=1_305_993_853,
        ref="refs/tags/v2.0.0",
        workflow_ref=(
            "PaulKov/dpone-release-controller/.github/workflows/"
            "release-controller.yml@refs/tags/v2.0.0"
        ),
        workflow_sha="a" * 40,
        run_id=123_456_789,
        run_attempt=2,
    )
    activation.verify_exchange(
        activation.BrokerActivationExchange(_ACTIVATION_REQUEST_ID, body),
        expected=expected,
        clock=_FrozenClock(_ACTIVATION_NOW),
    )
    document = _json_object(body, "activation response")
    if activation.reference_response_bytes(document) != body:
        raise DelegatedWireVerificationError("activation response builder drift")


def _verify_candidate_request(
    body: bytes, headers: Mapping[str, str] | None, fixture_root: Path
) -> None:
    _no_headers(headers)
    parsed = candidate_stream.CandidateStreamRequest.parse(body)
    if parsed.encoded() != body:
        raise DelegatedWireVerificationError("candidate request builder drift")


def _verify_candidate_response(
    body: bytes, headers: Mapping[str, str] | None, fixture_root: Path
) -> None:
    normalized = _required_headers(headers)
    admit_request = _candidate_admit_request(fixture_root)
    selector = admit_request.candidate
    binding = candidate_contract.ArtifactBinding(
        run_id=selector["candidate_run_id"],
        run_attempt=selector["candidate_run_attempt"],
        artifact_id=selector["candidate_artifact_id"],
        artifact_digest=selector["candidate_artifact_digest"],
        expected_release=selector["tag"],
        expected_peeled_commit_sha=selector["expected_peeled_commit_sha"],
    )
    authority = candidate_stream.CandidateReaderAuthority(
        service_identity=_CANDIDATE_SERVICE_IDENTITY,
        service_version_id=_CANDIDATE_SERVICE_VERSION_ID,
    )
    response = _MemoryCandidateResponse(body, normalized)
    verified = candidate_response.open_candidate_stream(
        response,
        binding,
        expected_request_id=_ACTIVATION_REQUEST_ID,
        authority=authority,
        now=_CANDIDATE_NOW,
    )
    received = b"".join(
        verified.chunks(maximum_bytes=candidate_provider.MAX_RAW_ZIP_BYTES)
    )
    if received != body:
        raise DelegatedWireVerificationError("candidate stream byte drift")
    if "sha256:" + hashlib.sha256(body).hexdigest() != binding.artifact_digest:
        raise DelegatedWireVerificationError("candidate body digest mismatch")
    rebuilt = candidate_response.response_headers(verified.observation)
    if rebuilt != dict(normalized):
        raise DelegatedWireVerificationError("candidate response header builder drift")


def _verify_candidate_admit_request(
    body: bytes, headers: Mapping[str, str] | None, fixture_root: Path
) -> None:
    _no_headers(headers)
    parsed = exchange.parse_candidate_admit_request(body, now=_CANDIDATE_NOW)
    document = _json_object(body, "candidate admit request")
    if parsed.release_identity_id != document["release_identity_id"]:
        raise DelegatedWireVerificationError("candidate admit request projection drift")


def _verify_candidate_admit_response(
    body: bytes, headers: Mapping[str, str] | None, fixture_root: Path
) -> None:
    _no_headers(headers)
    expected = _candidate_admit_request(fixture_root)
    parsed = exchange.parse_candidate_admit_response(body, expected=expected)
    rebuilt = exchange.candidate_admit_response_bytes(
        parsed.receipt,
        expected=expected,
    )
    if rebuilt != body:
        raise DelegatedWireVerificationError("candidate response builder drift")


def _candidate_admit_request(fixture_root: Path) -> exchange.CandidateAdmitRequest:
    path = fixture_root / f"{exchange.CANDIDATE_ADMIT_REQUEST_SCHEMA}.json"
    try:
        body = path.read_bytes()
    except OSError as exc:
        raise DelegatedWireVerificationError(
            "candidate admit request context is unavailable"
        ) from exc
    return exchange.parse_candidate_admit_request(body, now=_CANDIDATE_NOW)


def _json_object(body: bytes, label: str) -> Mapping[str, object]:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DelegatedWireVerificationError(f"{label} is invalid") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != body:
        raise DelegatedWireVerificationError(f"{label} is not canonical")
    return value


def _no_headers(headers: Mapping[str, str] | None) -> None:
    if headers not in (None, {}):
        raise DelegatedWireVerificationError("unexpected response headers")


def _required_headers(headers: Mapping[str, str] | None) -> Mapping[str, str]:
    if not isinstance(headers, Mapping) or not headers:
        raise DelegatedWireVerificationError("required response headers are absent")
    return headers
