"""Shared JSON-schema fragments and golden constants for state codecs."""

from __future__ import annotations

from typing import Any

from tools.evidence.release_canonical import MAX_SAFE_INTEGER
from tools.evidence.release_controller_wire_codecs import (
    SAMPLE_RELEASE_IDENTITY_ID,
    SAMPLE_TAG,
    JsonWireCodec,
)
from tools.evidence.release_controller_wire_state_validation import TIMESTAMP_PATTERN

DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
TAG = {
    "type": "string",
    "pattern": "^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$",
}
NONNEGATIVE = {"type": "integer", "minimum": 0, "maximum": MAX_SAFE_INTEGER}
POSITIVE = {"type": "integer", "minimum": 1, "maximum": MAX_SAFE_INTEGER}
TIMESTAMP = {"type": "string", "pattern": TIMESTAMP_PATTERN}
D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
D3 = "sha256:" + "3" * 64
D4 = "sha256:" + "4" * 64
LEASE_ID = "sha256:" + "5" * 64
ATTEMPT_ID = "sha256:" + "6" * 64


def selector_properties() -> dict[str, dict[str, Any]]:
    return {"release_identity_id": dict(DIGEST), "tag": dict(TAG)}


def selector_golden() -> dict[str, Any]:
    return {"release_identity_id": SAMPLE_RELEASE_IDENTITY_ID, "tag": SAMPLE_TAG}


def codec(
    schema_id: str,
    fields: tuple[str, ...],
    properties: dict[str, dict[str, Any]],
    golden: dict[str, Any],
    validator,
) -> JsonWireCodec:
    return JsonWireCodec(schema_id, fields, properties, golden, validator)


HEAD_FIELDS = (
    "head_receipt_id",
    "head_receipt_sha256",
    "head_sequence",
    "release_identity_id",
    "tag",
)
HEAD_PROPERTIES = {
    "head_receipt_id": dict(DIGEST),
    "head_receipt_sha256": dict(DIGEST),
    "head_sequence": dict(NONNEGATIVE),
    **selector_properties(),
}
HEAD_GOLDEN = {
    "head_receipt_id": D1,
    "head_receipt_sha256": D2,
    "head_sequence": 18,
    **selector_golden(),
}
