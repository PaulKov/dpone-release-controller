"""Typed controller-to-ledger exchanges with broker-authored authority.

Workflow inputs can select immutable provider objects, but they can never
submit a receipt, ledger head, lease, fence, producer, committer, timestamp or
opaque JSON payload.  The pinned Commit-A adapter builds this candidate-admit
request only after the candidate stream and its exact archive have passed the
local semantic verifier.  The broker re-derives current state and authors the
canonical receipt envelope returned by the response codec.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, fields
from datetime import datetime
from typing import Any, Mapping

from tools.evidence import release_candidate_contract as candidate_contract
from tools.evidence import release_controller_candidate_admission as admission
from tools.evidence import release_candidate_handoff as candidate_handoff
from tools.evidence import release_candidate_provider as candidate_provider
from tools.evidence import release_candidate_stream as candidate_stream
from tools.evidence import release_identity
from tools.evidence import release_receipt_contract as receipt_contract
from tools.evidence import release_receipt_payloads as receipt_payloads
from tools.evidence.release_canonical import CanonicalJsonError, canonical_json_bytes
from tools.evidence.release_controller_exchange_errors import ControllerExchangeError
from tools.evidence.release_receipt_envelope_v2 import encode as encode_receipt
from tools.evidence.release_receipt_envelope_v2 import verify as verify_receipt

CANDIDATE_ADMIT_REQUEST_SCHEMA = "dpone.release-controller-candidate-admit-request.v1"
CANDIDATE_ADMIT_RESPONSE_SCHEMA = "dpone.release-controller-candidate-admit-response.v1"
ERROR_SCHEMA = "dpone.release-controller-error-response.v1"
CANDIDATE_RECEIPT_KIND = "CANDIDATE_HANDOFF"
_ERROR_CODE_RE = re.compile(r"[A-Z][A-Z0-9_]{1,127}\Z", re.ASCII)
_OBSERVATION_FIELDS = frozenset(
    item.name for item in fields(candidate_provider.ProviderArtifactObservation)
)
_CANDIDATE_SELECTOR_FIELDS = frozenset(
    {
        "candidate_artifact_digest",
        "candidate_artifact_id",
        "candidate_run_attempt",
        "candidate_run_id",
    }
)
_FIXED_RECEIPT_FIELDS = frozenset({"kind", "state"})
_CANDIDATE_EVIDENCE_FIELDS = frozenset(
    {
        "candidate_artifact_broker_request_id",
        "candidate_artifact_created_at",
        "candidate_artifact_expanded_bytes",
        "candidate_artifact_expires_at",
        "candidate_artifact_file_count",
        "candidate_artifact_policy_blob_sha",
        "candidate_artifact_policy_sha256",
        "candidate_artifact_provider_api_version",
        "candidate_artifact_provider_metadata_schema",
        "candidate_artifact_provider_observation_sha256",
        "candidate_artifact_provider_response_sha256",
        "candidate_artifact_raw_zip_sha256",
        "candidate_artifact_raw_zip_size_bytes",
        "candidate_artifact_source_url_expires_at",
        "candidate_artifact_source_url_sha256",
        "candidate_artifact_tag_object_sha",
        "candidate_id",
        "candidate_inventory_sha256",
        "candidate_manifest_sha256",
        "candidate_reader_service_identity",
        "candidate_reader_service_version_id",
        "candidate_reader_deployment_observation_record_id",
        "candidate_reader_deployment_observation_record_sha256",
        "distribution_inventory",
        "distribution_inventory_sha256",
        "file_count",
        "total_bytes",
    }
)


@dataclass(frozen=True, slots=True)
class LedgerHead:
    """The broker-authored stream head returned only as a checked UX hint."""

    phase: str
    receipt_id: str
    receipt_sha256: str
    sequence: int


@dataclass(frozen=True, slots=True)
class CandidateAdmitRequest:
    """Parsed immutable selectors and bounded evidence for one candidate."""

    release_identity_id: str
    candidate: Mapping[str, Any]
    provider_observation: Mapping[str, Any]
    evidence: Mapping[str, Any]
    receipt_payload: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class CandidateAdmitResponse:
    """One verified broker-authored CANDIDATE receipt and checked head hint."""

    receipt: Mapping[str, Any]
    head: LedgerHead


@dataclass(frozen=True, slots=True)
class ErrorResponse:
    """Sanitized broker failure safe to expose in an Actions annotation."""

    code: str
    request_id: str
    retryable: bool


def candidate_admit_request_bytes(
    imported: candidate_handoff.ProviderBoundCandidate,
) -> bytes:
    """Encode proof from a locally verified provider-bound candidate only."""

    if not isinstance(imported, candidate_handoff.ProviderBoundCandidate):
        raise ControllerExchangeError(
            "candidate admit requires a verified provider-bound candidate"
        )
    payload = imported.receipt_payload()
    try:
        receipt_payloads.validate(payload)
    except receipt_contract.ReceiptValidationError as exc:
        raise ControllerExchangeError(f"invalid candidate evidence: {exc}") from exc
    binding = imported.candidate.binding
    selector = candidate_stream.CandidateStreamRequest.from_binding(binding).document()
    evidence = {
        key: value
        for key, value in payload.items()
        if key not in _FIXED_RECEIPT_FIELDS | _CANDIDATE_SELECTOR_FIELDS
    }
    release_identity_id = imported.candidate.manifest.release_identity_id
    request = {
        "candidate": selector,
        "evidence": evidence,
        "provider_observation": asdict(imported.provider_archive.observation),
        "release_identity_id": release_identity_id,
        "schema": CANDIDATE_ADMIT_REQUEST_SCHEMA,
        "schema_version": 1,
    }
    parsed = _parse_candidate_admit_document(request, now=None)
    if parsed.receipt_payload != payload:
        raise ControllerExchangeError("candidate admit projection drift")
    return canonical_json_bytes(request)


def parse_candidate_admit_request(
    data: bytes, *, now: datetime
) -> CandidateAdmitRequest:
    """Parse and independently cross-bind the typed candidate-admit evidence."""

    raw = _canonical_object(data, "candidate admit request")
    return _parse_candidate_admit_document(raw, now=now)


def parse_candidate_admit_response(
    data: bytes, *, expected: CandidateAdmitRequest
) -> CandidateAdmitResponse:
    """Verify the broker-authored envelope exactly reflects admitted evidence."""

    if not isinstance(expected, CandidateAdmitRequest):
        raise ControllerExchangeError("candidate response expectation is invalid")
    raw = _canonical_object(data, "candidate admit response")
    _exact_keys(
        raw,
        {"head", "receipt", "schema", "schema_version"},
        "candidate admit response",
    )
    if raw["schema"] != CANDIDATE_ADMIT_RESPONSE_SCHEMA or raw["schema_version"] != 1:
        raise ControllerExchangeError("candidate response schema/version mismatch")
    receipt = _mapping(raw["receipt"], "receipt")
    try:
        verify_receipt(receipt)
        receipt_bytes = encode_receipt(receipt)
    except receipt_contract.ReceiptValidationError as exc:
        raise ControllerExchangeError(
            f"invalid broker-authored receipt: {exc}"
        ) from exc
    if receipt["payload"] != expected.receipt_payload:
        raise ControllerExchangeError("candidate response evidence substitution")
    if receipt["stream"]["release_identity_id"] != expected.release_identity_id:
        raise ControllerExchangeError("candidate response release identity mismatch")
    head = _mapping(raw["head"], "head")
    _exact_keys(
        head,
        {"phase", "receipt_id", "receipt_sha256", "sequence"},
        "head",
    )
    receipt_sha256 = "sha256:" + hashlib.sha256(receipt_bytes).hexdigest()
    expected_head = {
        "phase": CANDIDATE_RECEIPT_KIND,
        "receipt_id": receipt["receipt_id"],
        "receipt_sha256": receipt_sha256,
        "sequence": receipt["stream"]["sequence"],
    }
    if head != expected_head:
        raise ControllerExchangeError("candidate response head/receipt mismatch")
    return CandidateAdmitResponse(dict(receipt), LedgerHead(**head))


def candidate_admit_response_bytes(
    receipt: Mapping[str, Any], *, expected: CandidateAdmitRequest
) -> bytes:
    """Build reference broker bytes and verify their receipt/head cross-binding."""

    try:
        receipt_bytes = encode_receipt(receipt)
    except receipt_contract.ReceiptValidationError as exc:
        raise ControllerExchangeError("candidate response receipt is invalid") from exc
    document = {
        "head": {
            "phase": CANDIDATE_RECEIPT_KIND,
            "receipt_id": receipt["receipt_id"],
            "receipt_sha256": "sha256:" + hashlib.sha256(receipt_bytes).hexdigest(),
            "sequence": receipt["stream"]["sequence"],
        },
        "receipt": dict(receipt),
        "schema": CANDIDATE_ADMIT_RESPONSE_SCHEMA,
        "schema_version": 1,
    }
    encoded = canonical_json_bytes(document)
    parse_candidate_admit_response(encoded, expected=expected)
    return encoded


def parse_error_response(data: bytes, *, expected_request_id: str) -> ErrorResponse:
    """Parse the broker's exact sanitized error shape without trusting text."""

    receipt_contract.request_id(expected_request_id, "expected_request_id")
    raw = _canonical_object(data, "error response")
    _exact_keys(raw, {"error", "schema", "schema_version"}, "error response")
    if raw["schema"] != ERROR_SCHEMA or raw["schema_version"] != 1:
        raise ControllerExchangeError("error response schema/version mismatch")
    error = _mapping(raw["error"], "error")
    _exact_keys(error, {"code", "request_id", "retryable"}, "error")
    code = _string(error["code"], "error.code")
    if _ERROR_CODE_RE.fullmatch(code) is None:
        raise ControllerExchangeError("error code is not canonical")
    if error["request_id"] != expected_request_id:
        raise ControllerExchangeError("error request ID mismatch")
    if type(error["retryable"]) is not bool:
        raise ControllerExchangeError("error retryable must be boolean")
    return ErrorResponse(code, expected_request_id, error["retryable"])


def _parse_candidate_admit_document(
    raw: Mapping[str, Any], *, now: datetime | None
) -> CandidateAdmitRequest:
    _exact_keys(
        raw,
        {
            "candidate",
            "evidence",
            "provider_observation",
            "release_identity_id",
            "schema",
            "schema_version",
        },
        "candidate admit request",
    )
    if raw["schema"] != CANDIDATE_ADMIT_REQUEST_SCHEMA or raw["schema_version"] != 1:
        raise ControllerExchangeError("candidate request schema/version mismatch")
    release_identity_id = _digest(raw["release_identity_id"], "release_identity_id")
    selector = admission.candidate_selector(raw["candidate"])
    if release_identity_id != release_identity.release_identity_id(selector["tag"]):
        raise ControllerExchangeError("candidate request release identity mismatch")
    binding = candidate_contract.ArtifactBinding(
        run_id=selector["candidate_run_id"],
        run_attempt=selector["candidate_run_attempt"],
        artifact_id=selector["candidate_artifact_id"],
        artifact_digest=selector["candidate_artifact_digest"],
        expected_release=selector["tag"],
        expected_peeled_commit_sha=selector["expected_peeled_commit_sha"],
    )
    observation_raw = _mapping(raw["provider_observation"], "provider_observation")
    if set(observation_raw) != _OBSERVATION_FIELDS:
        raise ControllerExchangeError("provider observation keys are not exact")
    try:
        observation = candidate_provider.ProviderArtifactObservation(**observation_raw)
        if now is not None:
            observation.require_matches(binding, now=now)
        else:
            admission.require_observation_binding_without_clock(observation, binding)
    except (TypeError, candidate_contract.CandidateHandoffError) as exc:
        raise ControllerExchangeError(f"invalid provider observation: {exc}") from exc
    evidence = _mapping(raw["evidence"], "candidate evidence")
    if set(evidence) != _CANDIDATE_EVIDENCE_FIELDS:
        raise ControllerExchangeError("candidate evidence keys are not exact")
    payload = {
        "kind": CANDIDATE_RECEIPT_KIND,
        "state": CANDIDATE_RECEIPT_KIND,
        **dict(evidence),
        "candidate_run_id": selector["candidate_run_id"],
        "candidate_run_attempt": selector["candidate_run_attempt"],
        "candidate_artifact_id": selector["candidate_artifact_id"],
        "candidate_artifact_digest": selector["candidate_artifact_digest"],
    }
    try:
        receipt_payloads.validate(payload)
    except receipt_contract.ReceiptValidationError as exc:
        raise ControllerExchangeError(f"invalid candidate evidence: {exc}") from exc
    admission.verify_projection(payload, observation, binding, release_identity_id)
    return CandidateAdmitRequest(
        release_identity_id,
        dict(selector),
        dict(observation_raw),
        dict(evidence),
        payload,
    )


def _canonical_object(data: bytes, name: str) -> Mapping[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ControllerExchangeError(f"duplicate {name} key: {key!r}")
            result[key] = value
        return result

    try:
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ControllerExchangeError(f"invalid {name} JSON: {exc}") from exc
    raw = _mapping(raw, name)
    try:
        if data != canonical_json_bytes(raw):
            raise ControllerExchangeError(f"{name} bytes are not canonical JSON")
    except CanonicalJsonError as exc:
        raise ControllerExchangeError(f"invalid {name} canonical JSON: {exc}") from exc
    return raw


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ControllerExchangeError(f"{name} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise ControllerExchangeError(f"{name} keys are not exact")


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ControllerExchangeError(f"{name} must be a bounded string")
    return value


def _digest(value: Any, name: str) -> str:
    try:
        return receipt_contract.digest(value, name)
    except receipt_contract.ReceiptValidationError as exc:
        raise ControllerExchangeError(str(exc)) from exc
