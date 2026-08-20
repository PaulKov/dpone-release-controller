"""Lease, recovery, and PyPI state response codec specifications."""

from tools.evidence import release_controller_schema_ids as ids
from tools.evidence import release_controller_wire_state_schema as s
from tools.evidence.release_controller_wire_codecs import _selector
from tools.evidence.release_controller_wire_state_validation import (
    validate_lease_response,
    validate_pypi_response,
    validate_recovery_response,
)

PRIMARY_STATE_CODECS = (
    s.codec(
        ids.LEASE_RENEW_REQUEST,
        ("release_identity_id", "tag"),
        s.selector_properties(),
        s.selector_golden(),
        _selector,
    ),
    s.codec(
        ids.LEASE_RENEW_RESPONSE,
        (
            *s.HEAD_FIELDS,
            "durable_state",
            "fencing_token",
            "lease_id",
            "renewal",
            "status",
        ),
        {
            **s.HEAD_PROPERTIES,
            "durable_state": {
                "enum": [
                    "ABORTED",
                    "INCIDENT_HOLD",
                    "LEASED_ACTIVE",
                    "RECOVERY_REQUIRED",
                    "TERMINAL",
                ]
            },
            "fencing_token": dict(s.POSITIVE),
            "lease_id": dict(s.DIGEST),
            "renewal": {
                "oneOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "expires_at",
                            "receipt_id",
                            "receipt_sha256",
                            "sequence",
                        ],
                        "properties": {
                            "expires_at": dict(s.TIMESTAMP),
                            "receipt_id": dict(s.DIGEST),
                            "receipt_sha256": dict(s.DIGEST),
                            "sequence": dict(s.NONNEGATIVE),
                        },
                    },
                ]
            },
            "status": {"enum": ["ABORTED", "ACTIVE", "EXPIRED", "HOLD", "RELEASED"]},
        },
        {
            **s.HEAD_GOLDEN,
            "durable_state": "LEASED_ACTIVE",
            "fencing_token": 3,
            "lease_id": s.LEASE_ID,
            "renewal": {
                "expires_at": "2026-08-15T00:05:45Z",
                "receipt_id": s.D1,
                "receipt_sha256": s.D2,
                "sequence": 18,
            },
            "status": "ACTIVE",
        },
        validate_lease_response,
    ),
    s.codec(
        ids.RECOVERY_DECISION_RESPONSE,
        (
            *s.HEAD_FIELDS,
            "append_count",
            "appended_selectors",
            "attempt_id",
            "batch_sha256",
            "classification",
            "fencing_token",
            "first_receipt_id",
            "first_receipt_sha256",
            "first_sequence",
            "lease_id",
            "resulting_state",
            "resume_phase",
            "workflow_outcome",
        ),
        {
            **s.HEAD_PROPERTIES,
            "append_count": {"const": 2},
            "appended_selectors": {
                "type": "array",
                "minItems": 2,
                "maxItems": 2,
                "items": {"type": "string"},
            },
            "attempt_id": dict(s.DIGEST),
            "batch_sha256": dict(s.DIGEST),
            "classification": {
                "enum": ["CLOSE_EXACT", "INCIDENT_HOLD", "RESUME_ORIGINAL_CANDIDATE"]
            },
            "fencing_token": dict(s.POSITIVE),
            "first_receipt_id": dict(s.DIGEST),
            "first_receipt_sha256": dict(s.DIGEST),
            "first_sequence": dict(s.NONNEGATIVE),
            "lease_id": dict(s.DIGEST),
            "resulting_state": {
                "enum": [
                    "GITHUB_IMMUTABLE",
                    "INCIDENT_HOLD",
                    "LEASED",
                    "PYPI_RECOVERY",
                    "PYPI_VERIFIED",
                ]
            },
            "resume_phase": {
                "enum": [
                    None,
                    "GITHUB_IMMUTABLE",
                    "LEASED_RESTART",
                    "PYPI_RECOVERY",
                    "PYPI_VERIFIED",
                ]
            },
            "workflow_outcome": {"enum": ["CONTINUE", "HOLD"]},
        },
        {
            **s.HEAD_GOLDEN,
            "append_count": 2,
            "appended_selectors": ["RECOVERY_OBSERVATION", "RECOVERY_RESUMED"],
            "attempt_id": s.ATTEMPT_ID,
            "batch_sha256": s.D3,
            "classification": "RESUME_ORIGINAL_CANDIDATE",
            "fencing_token": 4,
            "first_receipt_id": s.D4,
            "first_receipt_sha256": s.D3,
            "first_sequence": 17,
            "lease_id": s.LEASE_ID,
            "resulting_state": "LEASED",
            "resume_phase": "LEASED_RESTART",
            "workflow_outcome": "CONTINUE",
        },
        validate_recovery_response,
    ),
    s.codec(
        ids.PYPI_OUTCOME_RESPONSE,
        (
            *s.HEAD_FIELDS,
            "append_count",
            "appended_selectors",
            "batch_sha256",
            "classification",
            "first_receipt_id",
            "first_receipt_sha256",
            "first_sequence",
            "resulting_state",
            "verified_file_count",
        ),
        {
            **s.HEAD_PROPERTIES,
            "append_count": {"type": "integer", "minimum": 1, "maximum": 9},
            "appended_selectors": {
                "type": "array",
                "minItems": 1,
                "maxItems": 9,
                "items": {"type": "string"},
            },
            "batch_sha256": dict(s.DIGEST),
            "classification": {
                "enum": [
                    "ALREADY_PUBLISHED_EXACT",
                    "AMBIGUOUS",
                    "COMPLETE",
                    "CONFLICT",
                    "PARTIAL_EXACT",
                ]
            },
            "first_receipt_id": dict(s.DIGEST),
            "first_receipt_sha256": dict(s.DIGEST),
            "first_sequence": dict(s.NONNEGATIVE),
            "resulting_state": {
                "enum": ["PYPI_RECOVERY", "PYPI_VERIFIED", "RECOVERY_REQUIRED"]
            },
            "verified_file_count": {"type": "integer", "minimum": 0, "maximum": 8},
        },
        {
            **s.HEAD_GOLDEN,
            "append_count": 1,
            "appended_selectors": ["PYPI_UPLOAD_SET_OBSERVED"],
            "batch_sha256": s.D3,
            "classification": "PARTIAL_EXACT",
            "first_receipt_id": s.D4,
            "first_receipt_sha256": s.D3,
            "first_sequence": 18,
            "resulting_state": "RECOVERY_REQUIRED",
            "verified_file_count": 0,
        },
        validate_pypi_response,
    ),
)
