"""Closed catalog for every canonical Commit-A JSON document."""

from __future__ import annotations

from tools.evidence import release_controller_schema_ids as ids
from tools.evidence.release_controller_wire_codecs import (
    SAMPLE_RELEASE_IDENTITY_ID,
    SAMPLE_TAG,
    JsonWireCodec,
    _draft_advance_response,
    _error,
    _provider_result,
    _pypi_proof,
    _receipt,
    _receipt_batch,
    _selector,
)
from tools.evidence.release_controller_wire_state import STATE_CODECS

_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_TAG = {
    "type": "string",
    "pattern": "^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$",
}
_POSITIVE = {"type": "integer", "minimum": 1, "maximum": 9_007_199_254_740_991}
_NONNEGATIVE = {"type": "integer", "minimum": 0, "maximum": 9_007_199_254_740_991}
_RID = "sha256:" + "3d52af3a2bc6eb185a48465c8680d988a57f7fecf668313673ded1aaed3a59ab"
_D1 = "sha256:" + "1" * 64
_D2 = "sha256:" + "2" * 64
_D3 = "sha256:" + "3" * 64
_D4 = "sha256:" + "4" * 64

if SAMPLE_RELEASE_IDENTITY_ID != _RID:
    raise RuntimeError("wire golden release identity drift")


def _selector_properties() -> dict[str, dict]:
    return {"release_identity_id": dict(_DIGEST), "tag": dict(_TAG)}


def _selector_golden() -> dict:
    return {"release_identity_id": _RID, "tag": SAMPLE_TAG}


def _codec(
    schema_id: str,
    fields: tuple[str, ...],
    properties: dict[str, dict],
    golden: dict,
    validator,
) -> JsonWireCodec:
    return JsonWireCodec(schema_id, fields, properties, golden, validator)


JSON_CODECS = (
    _codec(
        ids.SELECTOR_REQUEST,
        ("release_identity_id", "tag"),
        _selector_properties(),
        _selector_golden(),
        _selector,
    ),
    _codec(
        ids.RECEIPT_PROJECTION,
        (
            "authority_selectors",
            "head_receipt_id",
            "head_receipt_sha256",
            "head_sequence",
            "operation_id",
            "release_identity_id",
            "tag",
        ),
        {
            "authority_selectors": {
                "type": "array",
                "minItems": 1,
                "maxItems": 64,
                "uniqueItems": True,
                "items": {
                    "type": "string",
                    "pattern": "^[A-Z][A-Z0-9_]*(?::[A-Z][A-Z0-9_]*)?$",
                },
            },
            "head_receipt_id": dict(_DIGEST),
            "head_receipt_sha256": dict(_DIGEST),
            "head_sequence": dict(_NONNEGATIVE),
            "operation_id": {
                "type": "string",
                "pattern": "^[a-z][a-z0-9-]{1,63}$",
            },
            **_selector_properties(),
        },
        {
            "authority_selectors": ["REQUEST_ENQUEUED"],
            "head_receipt_id": _D1,
            "head_receipt_sha256": _D2,
            "head_sequence": 0,
            "operation_id": "admit",
            **_selector_golden(),
        },
        _receipt,
    ),
    _codec(
        ids.RECEIPT_BATCH_PROJECTION,
        (
            "authority_selectors",
            "batch_sha256",
            "first_receipt_id",
            "head_receipt_id",
            "head_receipt_sha256",
            "head_sequence",
            "operation_id",
            "receipt_count",
            "release_identity_id",
            "tag",
        ),
        {
            "authority_selectors": {
                "type": "array",
                "minItems": 1,
                "maxItems": 64,
                "uniqueItems": True,
                "items": {
                    "type": "string",
                    "pattern": "^[A-Z][A-Z0-9_]*(?::[A-Z][A-Z0-9_]*)?$",
                },
            },
            "batch_sha256": dict(_DIGEST),
            "first_receipt_id": dict(_DIGEST),
            "head_receipt_id": dict(_DIGEST),
            "head_receipt_sha256": dict(_DIGEST),
            "head_sequence": dict(_POSITIVE),
            "operation_id": {
                "type": "string",
                "pattern": "^[a-z][a-z0-9-]{1,63}$",
            },
            "receipt_count": {"type": "integer", "minimum": 1, "maximum": 64},
            **_selector_properties(),
        },
        {
            "authority_selectors": [
                "MUTATION_INTENT:PYPI_FILE_UPLOAD_SET",
                "PYPI_FILE_TRANSITION:PENDING_UPLOAD",
                "PYPI_FILE_TRANSITION:SEALED_FOR_UPLOAD",
            ],
            "batch_sha256": _D3,
            "first_receipt_id": _D4,
            "head_receipt_id": _D1,
            "head_receipt_sha256": _D2,
            "head_sequence": 17,
            "operation_id": "pypi-prepare",
            "receipt_count": 8,
            **_selector_golden(),
        },
        _receipt_batch,
    ),
    _codec(
        ids.PROVIDER_MUTATION_RESULT,
        (
            "operation",
            "provider_request_sha256",
            "release_identity_id",
            "status",
            "tag",
        ),
        {
            "operation": {
                "enum": [
                    "ATTESTATION_CREATE",
                    "GITHUB_RELEASE_PUBLISH",
                ]
            },
            "provider_request_sha256": dict(_DIGEST),
            "status": {"const": "MUTATION_SUBMITTED_UNVERIFIED"},
            **_selector_properties(),
        },
        {
            "operation": "ATTESTATION_CREATE",
            "provider_request_sha256": _D1,
            "status": "MUTATION_SUBMITTED_UNVERIFIED",
            **_selector_golden(),
        },
        _provider_result,
    ),
    _codec(
        ids.DRAFT_ADVANCE_RESPONSE,
        (
            "advance_ordinal",
            "durable_state_sha256",
            "release_identity_id",
            "retry_after_seconds",
            "status",
            "tag",
        ),
        {
            "advance_ordinal": {"type": "integer", "minimum": 1, "maximum": 256},
            "durable_state_sha256": dict(_DIGEST),
            "retry_after_seconds": {"type": "integer", "minimum": 0, "maximum": 5},
            "status": {"enum": ["COMPLETE", "HOLD", "IN_PROGRESS", "WAITING"]},
            **_selector_properties(),
        },
        {
            "advance_ordinal": 1,
            "durable_state_sha256": _D1,
            "retry_after_seconds": 5,
            "status": "IN_PROGRESS",
            **_selector_golden(),
        },
        _draft_advance_response,
    ),
    _codec(
        ids.PYPI_MATERIALIZATION_PROOF,
        (
            "candidate_id",
            "candidate_inventory_sha256",
            "distribution_file_count",
            "distribution_inventory_sha256",
            "distribution_total_bytes",
            "file_count",
            "raw_zip_sha256",
            "raw_zip_size_bytes",
            "release_identity_id",
            "tag",
        ),
        {
            "candidate_id": dict(_DIGEST),
            "candidate_inventory_sha256": dict(_DIGEST),
            "distribution_file_count": {"const": 8},
            "distribution_inventory_sha256": dict(_DIGEST),
            "distribution_total_bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": 536_870_912,
            },
            "file_count": {"const": 25},
            "raw_zip_sha256": dict(_DIGEST),
            "raw_zip_size_bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": 805_306_368,
            },
            **_selector_properties(),
        },
        {
            "candidate_id": _D1,
            "candidate_inventory_sha256": _D2,
            "distribution_file_count": 8,
            "distribution_inventory_sha256": _D3,
            "distribution_total_bytes": 8_388_608,
            "file_count": 25,
            "raw_zip_sha256": _D4,
            "raw_zip_size_bytes": 9_437_184,
            **_selector_golden(),
        },
        _pypi_proof,
    ),
    _codec(
        ids.ERROR_RESPONSE,
        ("code", "request_id", "retryable"),
        {
            "code": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]{1,63}$"},
            "request_id": {
                "type": "string",
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$",
            },
            "retryable": {"type": "boolean"},
        },
        {
            "code": "LEDGER_CONFLICT",
            "request_id": "request-01HXDPONE",
            "retryable": False,
        },
        _error,
    ),
    *STATE_CODECS,
)

BY_SCHEMA = {codec.schema_id: codec for codec in JSON_CODECS}
if len(BY_SCHEMA) != len(JSON_CODECS):
    raise RuntimeError("duplicate canonical JSON wire schema")


def by_schema(schema_id: str) -> JsonWireCodec:
    """Return one explicit codec; unknown identifiers are never synthesized."""

    try:
        return BY_SCHEMA[schema_id]
    except KeyError as exc:
        raise ValueError("unknown canonical JSON wire schema") from exc
