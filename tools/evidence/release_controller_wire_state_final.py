"""Cancellation and terminal codec specifications."""

from tools.evidence import release_controller_schema_ids as ids
from tools.evidence import release_controller_wire_state_schema as s
from tools.evidence.release_controller_wire_state_validation import (
    validate_cancellation_response,
    validate_terminal_response,
)

FINAL_STATE_CODECS = (
    s.codec(
        ids.CANCELLATION_OUTCOME_RESPONSE,
        (
            *s.HEAD_FIELDS,
            "append_count",
            "appended_selectors",
            "batch_sha256",
            "external_commit_observed",
            "first_receipt_id",
            "first_receipt_sha256",
            "first_sequence",
            "recovery_id",
            "resulting_state",
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
            "batch_sha256": dict(s.DIGEST),
            "external_commit_observed": {"type": "boolean"},
            "first_receipt_id": dict(s.DIGEST),
            "first_receipt_sha256": dict(s.DIGEST),
            "first_sequence": dict(s.NONNEGATIVE),
            "recovery_id": {"oneOf": [{"type": "null"}, dict(s.DIGEST)]},
            "resulting_state": {"enum": ["ABORTED", "RECOVERY_REQUIRED"]},
        },
        {
            **s.HEAD_GOLDEN,
            "append_count": 2,
            "appended_selectors": ["CANCELLATION", "LEASE_RELEASED:CANCELLED"],
            "batch_sha256": s.D3,
            "external_commit_observed": False,
            "first_receipt_id": s.D4,
            "first_receipt_sha256": s.D3,
            "first_sequence": 17,
            "recovery_id": None,
            "resulting_state": "ABORTED",
        },
        validate_cancellation_response,
    ),
    s.codec(
        ids.TERMINAL_ASSERT_RESPONSE,
        (*s.HEAD_FIELDS, "action_outcome", "durable_state", "sentinel_status"),
        {
            **s.HEAD_PROPERTIES,
            "action_outcome": {"enum": ["FAIL", "SUCCESS"]},
            "durable_state": {
                "enum": [
                    "ABORTED",
                    "ACTIVE",
                    "INCIDENT_HOLD",
                    "RECOVERY_REQUIRED",
                    "TERMINAL",
                ]
            },
            "sentinel_status": {
                "enum": ["ABORTED", "ACTIVE", "EXPIRED", "HOLD", "RELEASED"]
            },
        },
        {
            **s.HEAD_GOLDEN,
            "action_outcome": "SUCCESS",
            "durable_state": "TERMINAL",
            "sentinel_status": "RELEASED",
        },
        validate_terminal_response,
    ),
)
