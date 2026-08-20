"""Canonical builder and semantic verifier for release receipt envelope v2."""

from __future__ import annotations

import json
from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_payloads as payloads
from tools.evidence import release_receipt_producers as producers
from tools.evidence import release_broker_record_envelope as broker_envelope
from tools.evidence.release_canonical import (
    CanonicalJsonError,
    canonical_json_bytes,
    sha256_id,
)

_SCOPE_KEYS = {
    "release": "release_identity_id",
    "candidate": "candidate_id",
    "authorization": "authorization_id",
    "recovery": "recovery_id",
}


def _canonical_id(domain: str, value: Mapping[str, Any]) -> str:
    try:
        return sha256_id(domain, value)
    except CanonicalJsonError as exc:
        raise contract.ReceiptValidationError(
            f"value is outside the canonical receipt domain: {exc}"
        ) from exc


def payload_sha256(payload: Mapping[str, Any]) -> str:
    """Return the frozen domain-separated payload identity."""

    return _canonical_id(contract.PAYLOAD_DOMAIN, payload)


def receipt_id(envelope_without_id: Mapping[str, Any]) -> str:
    """Return the frozen domain-separated identity of the complete body."""

    if "receipt_id" in envelope_without_id:
        raise contract.ReceiptValidationError(
            "receipt identity input must omit receipt_id"
        )
    return _canonical_id(contract.RECEIPT_DOMAIN, envelope_without_id)


def build(
    *,
    stream: Mapping[str, Any],
    scope: Mapping[str, Any],
    attempt: Mapping[str, Any],
    producer: Mapping[str, Any],
    committer: Mapping[str, Any],
    timestamps: Mapping[str, Any],
    payload: Mapping[str, Any],
    lease: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build and self-verify one canonical broker-committed envelope."""

    body: dict[str, Any] = {
        "schema": contract.SCHEMA,
        "schema_version": contract.SCHEMA_VERSION,
        "receipt_type": payload.get("kind"),
        "stream": dict(stream),
        "scope": dict(scope),
        "attempt": dict(attempt),
        "producer": dict(producer),
        "committer": dict(committer),
        "timestamps": dict(timestamps),
        "payload": dict(payload),
        "payload_sha256": payload_sha256(payload),
    }
    if lease is not None:
        body["lease"] = dict(lease)
    body["receipt_id"] = receipt_id(body)
    verify(body)
    return body


def encode(envelope: Mapping[str, Any]) -> bytes:
    """Verify then return the only accepted durable JSON bytes."""

    verify(envelope)
    return canonical_json_bytes(envelope)


def decode(data: bytes) -> Mapping[str, Any]:
    """Reject duplicate keys, non-canonical bytes, and semantic drift."""

    try:
        bounded = broker_envelope.require_bounded_envelope_bytes(
            data, name="receipt envelope"
        )
    except broker_envelope.BrokerRecordEnvelopeError as exc:
        raise contract.ReceiptValidationError(str(exc)) from exc

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise contract.ReceiptValidationError(f"duplicate receipt key: {key!r}")
            result[key] = value
        return result

    try:
        raw = json.loads(bounded.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise contract.ReceiptValidationError(f"invalid receipt JSON: {exc}") from exc
    raw = contract.mapping(raw, "receipt")
    if bounded != canonical_json_bytes(raw):
        raise contract.ReceiptValidationError("receipt bytes are not canonical JSON")
    verify(raw)
    return raw


def verify(envelope: Mapping[str, Any]) -> None:
    """Validate closed shape, identities, producer authority, and state semantics."""

    stream = _stream(envelope.get("stream"))
    if stream["sequence"] == 0:
        try:
            broker_envelope.require_bounded_envelope_bytes(
                canonical_json_bytes(envelope), name="genesis receipt envelope"
            )
        except (CanonicalJsonError, broker_envelope.BrokerRecordEnvelopeError) as exc:
            raise contract.ReceiptValidationError(
                f"genesis receipt envelope exceeds the byte contract: {exc}"
            ) from exc
    payload = contract.mapping(envelope.get("payload"), "payload")
    semantics = payloads.validate(payload)
    expected_keys = {
        "schema",
        "schema_version",
        "receipt_id",
        "receipt_type",
        "stream",
        "scope",
        "attempt",
        "producer",
        "committer",
        "timestamps",
        "payload",
        "payload_sha256",
    }
    if semantics.lease_required:
        expected_keys.add("lease")
    contract.exact_keys(envelope, expected_keys, "receipt")
    if (
        envelope["schema"] != contract.SCHEMA
        or type(envelope["schema_version"]) is not int
        or envelope["schema_version"] != contract.SCHEMA_VERSION
        or envelope["receipt_type"] != payload["kind"]
    ):
        raise contract.ReceiptValidationError("receipt schema/type mismatch")

    scope = _scope(envelope["scope"], semantics, stream, payload)
    attempt = _attempt(envelope["attempt"])
    lease = _lease(envelope.get("lease"), semantics)
    producer_kind = producers.validate_producer(envelope["producer"], payload)
    if producer_kind not in semantics.allowed_producers:
        raise contract.ReceiptValidationError("producer is forbidden for payload kind")
    producers.validate_committer(envelope["committer"])
    _timestamps(envelope["timestamps"])
    contract.require_historical_event_timestamps(payload, envelope["timestamps"])
    _cross_bind(payload, scope, attempt, lease, envelope["producer"])

    expected_payload_digest = payload_sha256(payload)
    if envelope["payload_sha256"] != expected_payload_digest:
        raise contract.ReceiptValidationError("payload_sha256 mismatch")
    body = dict(envelope)
    supplied_receipt_id = body.pop("receipt_id")
    contract.digest(supplied_receipt_id, "receipt_id")
    if supplied_receipt_id != receipt_id(body):
        raise contract.ReceiptValidationError("receipt_id mismatch")


def _stream(value: Any) -> Mapping[str, Any]:
    stream = contract.mapping(value, "stream")
    contract.exact_keys(
        stream,
        {"release_identity_id", "release_authority_id", "sequence", "previous"},
        "stream",
    )
    contract.digest_fields(stream, "release_identity_id", "release_authority_id")
    sequence = contract.nonnegative_int(stream["sequence"], "stream.sequence")
    previous = stream["previous"]
    if sequence == 0:
        if previous != contract.GENESIS:
            raise contract.ReceiptValidationError("sequence zero must use GENESIS")
    elif previous == contract.GENESIS:
        raise contract.ReceiptValidationError(
            "GENESIS is forbidden after sequence zero"
        )
    else:
        contract.digest(previous, "stream.previous")
    return stream


def _scope(
    value: Any,
    semantics: contract.PayloadSemantics,
    stream: Mapping[str, Any],
    payload: Mapping[str, Any],
) -> Mapping[str, Any]:
    scope = contract.mapping(value, "scope")
    key = _SCOPE_KEYS[semantics.scope_kind]
    contract.exact_keys(scope, {"kind", key}, "scope")
    if scope["kind"] != semantics.scope_kind:
        raise contract.ReceiptValidationError("scope kind does not match payload")
    contract.digest(scope[key], f"scope.{key}")
    expected = (
        stream["release_identity_id"] if key == "release_identity_id" else payload[key]
    )
    if scope[key] != expected:
        raise contract.ReceiptValidationError(
            "scope identity does not match payload/stream"
        )
    return scope


def _attempt(value: Any) -> Mapping[str, Any]:
    attempt = contract.mapping(value, "attempt")
    contract.exact_keys(attempt, {"attempt_id", "queue_entry_id"}, "attempt")
    contract.digest_fields(attempt, "attempt_id", "queue_entry_id")
    return attempt


def _lease(
    value: Any, semantics: contract.PayloadSemantics
) -> Mapping[str, Any] | None:
    if not semantics.lease_required:
        if value is not None:
            raise contract.ReceiptValidationError(
                "lease is forbidden before acquisition"
            )
        return None
    lease = contract.mapping(value, "lease")
    contract.exact_keys(lease, {"lease_id", "fencing_token"}, "lease")
    contract.digest(lease["lease_id"], "lease.lease_id")
    contract.positive_int(lease["fencing_token"], "lease.fencing_token")
    return lease


def _timestamps(value: Any) -> None:
    timestamps = contract.mapping(value, "timestamps")
    contract.exact_keys(timestamps, {"observed_at", "committed_at"}, "timestamps")
    contract.ordered_timestamps(
        timestamps["observed_at"],
        timestamps["committed_at"],
        "timestamps.observed_at",
        "timestamps.committed_at",
    )


def _cross_bind(
    payload: Mapping[str, Any],
    scope: Mapping[str, Any],
    attempt: Mapping[str, Any],
    lease: Mapping[str, Any] | None,
    producer: Mapping[str, Any],
) -> None:
    if "attempt_id" in payload and payload["attempt_id"] != attempt["attempt_id"]:
        raise contract.ReceiptValidationError("payload/root attempt mismatch")
    if lease is not None:
        if "lease_id" in payload and payload["lease_id"] != lease["lease_id"]:
            raise contract.ReceiptValidationError("payload/root lease mismatch")
        if (
            "fencing_token" in payload
            and payload["fencing_token"] != lease["fencing_token"]
        ):
            raise contract.ReceiptValidationError("payload/root fencing mismatch")
    scope_key = _SCOPE_KEYS[scope["kind"]]
    if scope_key in payload and payload[scope_key] != scope[scope_key]:
        raise contract.ReceiptValidationError("payload/root scope mismatch")
