"""Bounded canonical broker-record integrity primitives.

This module deliberately validates only the transport and hash envelope shared
by broker A0/A1 records.  A record returned here is *not* release authority:
callers must additionally pass its document through the exact schema-specific
A0 or A1 semantic parser.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from tools.evidence.release_canonical import CanonicalJsonError, canonical_json_bytes
from tools.evidence.release_controller_limits import MAX_CONTROL_DOCUMENT_BYTES

MAX_BROKER_RECORD_BYTES = MAX_CONTROL_DOCUMENT_BYTES

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


class BrokerRecordEnvelopeError(ValueError):
    """A broker record is oversized, non-canonical, or hash-inconsistent."""


@dataclass(frozen=True, slots=True)
class VerifiedBrokerRecordEnvelope:
    """Integrity-verified bytes pending schema-specific authority validation."""

    canonical_bytes: bytes
    document: Mapping[str, Any]
    record_id: str
    record_sha256: str


def require_bounded_envelope_bytes(data: bytes, *, name: str) -> bytes:
    """Reject empty or oversized bytes before any JSON decoding/allocation."""

    if type(data) is not bytes:
        raise BrokerRecordEnvelopeError(f"{name} must be exact bytes")
    if not 1 <= len(data) <= MAX_BROKER_RECORD_BYTES:
        raise BrokerRecordEnvelopeError(
            f"{name} must be 1..{MAX_BROKER_RECORD_BYTES} bytes"
        )
    return data


def derive_record_id(body_without_record_id: Mapping[str, Any]) -> str:
    """Derive the broker record ID from canonical bytes without ``record_id``."""

    if not isinstance(body_without_record_id, Mapping):
        raise BrokerRecordEnvelopeError("broker record body must be an object")
    if "record_id" in body_without_record_id:
        raise BrokerRecordEnvelopeError("broker record ID input must omit record_id")
    try:
        body = canonical_json_bytes(body_without_record_id)
    except CanonicalJsonError as exc:
        raise BrokerRecordEnvelopeError(f"invalid broker record body: {exc}") from exc
    return _tagged_sha256(body)


def encode_record(body_without_record_id: Mapping[str, Any]) -> bytes:
    """Build one bounded canonical broker record using the actual ID algorithm."""

    record = dict(body_without_record_id)
    record["record_id"] = derive_record_id(body_without_record_id)
    try:
        encoded = canonical_json_bytes(record)
    except CanonicalJsonError as exc:
        raise BrokerRecordEnvelopeError(f"invalid broker record: {exc}") from exc
    return require_bounded_envelope_bytes(encoded, name="broker record")


def verify_record_bytes(data: bytes) -> VerifiedBrokerRecordEnvelope:
    """Verify bounded canonical bytes and both actual broker record digests.

    The size check intentionally runs before UTF-8 decoding or ``json.loads``.
    Unknown fields remain untouched for the later closed A0/A1 parser.
    """

    bounded = require_bounded_envelope_bytes(data, name="broker record")
    document = _canonical_object(bounded)
    supplied_record_id = document.get("record_id")
    if (
        not isinstance(supplied_record_id, str)
        or _DIGEST_RE.fullmatch(supplied_record_id) is None
    ):
        raise BrokerRecordEnvelopeError("broker record_id must be tagged SHA-256")
    body = dict(document)
    del body["record_id"]
    expected_record_id = derive_record_id(body)
    if supplied_record_id != expected_record_id:
        raise BrokerRecordEnvelopeError("broker record_id mismatch")
    return VerifiedBrokerRecordEnvelope(
        canonical_bytes=bounded,
        document=document,
        record_id=supplied_record_id,
        record_sha256=_tagged_sha256(bounded),
    )


def _canonical_object(data: bytes) -> Mapping[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BrokerRecordEnvelopeError(f"duplicate broker record key: {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BrokerRecordEnvelopeError(f"invalid broker record JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise BrokerRecordEnvelopeError("broker record root must be an object")
    try:
        canonical = canonical_json_bytes(value)
    except CanonicalJsonError as exc:
        raise BrokerRecordEnvelopeError(f"invalid broker record domain: {exc}") from exc
    if data != canonical:
        raise BrokerRecordEnvelopeError("broker record is not canonical JSON")
    return value


def _tagged_sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()
