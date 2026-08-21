"""Generate language-neutral golden bytes for release receipt envelope v2."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Sequence

from scripts.release_generator_support import (
    ManagedRoot,
    parse_check_mode,
    reconcile_generated_files,
)

from tools.evidence.release_canonical import canonical_json_bytes
from tools.evidence.release_receipt_envelope_v2 import payload_sha256, receipt_id
from tools.evidence.release_receipt_reference_vectors import positive_envelope

OUTPUT = (
    Path(__file__).resolve().parents[2]
    / "tests/fixtures/release-receipt-v2-golden.json"
)
MANAGED_PATTERNS = ("release-receipt-*.json",)


def golden_document() -> dict[str, Any]:
    """Return positive canonical bytes and legacy/alias negative vectors."""

    envelope = _golden_envelope()
    payload = envelope["payload"]
    lower_type = dict(envelope)
    lower_type.pop("receipt_id")
    lower_type["receipt_type"] = "request_enqueued"
    plain_payload_digest = (
        "sha256:" + hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    )
    return {
        "schema": "dpone.release-receipt-v2-golden.v1",
        "schema_version": 1,
        "domains": {
            "payload": "dpone.release.payload.v2",
            "receipt": "dpone.release.receipt.v2",
        },
        "positive": {
            "payload": payload,
            "payload_sha256": envelope["payload_sha256"],
            "envelope": envelope,
            "canonical_json_sha256": "sha256:"
            + hashlib.sha256(canonical_json_bytes(envelope)).hexdigest(),
            "receipt_id": envelope["receipt_id"],
        },
        "negative_vectors": [
            {
                "name": "plain_payload_hash_without_domain",
                "candidate_digest": plain_payload_digest,
                "must_not_equal": envelope["payload_sha256"],
            },
            {
                "name": "lowercase_receipt_type_alias",
                "candidate_receipt_id": receipt_id(lower_type),
                "must_not_equal": envelope["receipt_id"],
            },
            {
                "name": "boolean_queue_sequence_alias",
                "candidate_payload_sha256": payload_sha256(
                    {**payload, "queue_sequence": False}
                ),
                "must_not_equal": envelope["payload_sha256"],
            },
            {
                "name": "integer_above_ecmascript_safe_range",
                "json_pointer": "/producer/run_id",
                "candidate_value": 9_007_199_254_740_992,
                "maximum": 9_007_199_254_740_991,
                "expected": "REJECT",
            },
            {
                "name": "floating_point_integer_alias",
                "json_pointer": "/producer/run_id",
                "candidate_value": 1.0,
                "expected": "REJECT",
            },
        ],
    }


def _golden_envelope() -> dict[str, Any]:
    """Return the production-owned, semantically verified positive vector."""

    return positive_envelope()


def golden_bytes() -> bytes:
    """Return the exact checked language-neutral receipt vector bytes."""

    return (json.dumps(golden_document(), indent=2, sort_keys=True) + "\n").encode()


def generated_files() -> dict[Path, bytes]:
    """Return the complete receipt-vector output inventory."""

    return {OUTPUT: golden_bytes()}


def managed_roots() -> tuple[ManagedRoot, ...]:
    """Return the receipt-vector namespace inside the shared fixture root."""

    return (ManagedRoot(OUTPUT.parent, MANAGED_PATTERNS),)


def generate(*, check: bool) -> int:
    """Verify or atomically update the exact receipt-vector inventory."""

    return reconcile_generated_files(
        generated_files(),
        managed_roots(),
        check=check,
        label="release receipt vector",
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run one explicit receipt-vector generation mode."""

    parser = argparse.ArgumentParser(description=__doc__)
    return generate(check=parse_check_mode(parser, argv))


if __name__ == "__main__":
    raise SystemExit(main())
