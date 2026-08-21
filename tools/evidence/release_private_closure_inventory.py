"""INTERNAL/CONFIDENTIAL private-ledger inventory; NOT PUBLICATION data."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

from tools.evidence import release_receipt_contract as contract
from tools.evidence.release_canonical import canonical_json_bytes

SCHEMA = "dpone.release-controller-private-closure-member-inventory.v1"
CLOSED_RECEIPT_PATH = "closed-receipt-v2.json"
RECEIPT_CHAIN_PATH = "receipt-chain-v2.json"
RELEASE_EVIDENCE_PATH = "release-evidence-v2.json"
MANIFEST_PATH = "closure-manifest-v1.json"
MEMBER_PATHS = tuple(
    sorted(
        (
            CLOSED_RECEIPT_PATH,
            RECEIPT_CHAIN_PATH,
            RELEASE_EVIDENCE_PATH,
            MANIFEST_PATH,
        ),
        key=lambda value: value.encode("ascii"),
    )
)
MANIFEST_INPUT_PATHS = tuple(path for path in MEMBER_PATHS if path != MANIFEST_PATH)
MAX_TOTAL_BYTES = 20 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024


def validate(value: Any) -> tuple[dict[str, Any], ...]:
    """Validate the historical private-ledger member inventory only."""

    if not isinstance(value, list) or len(value) != len(MEMBER_PATHS):
        raise contract.ReceiptValidationError(
            "private closure inventory must contain exactly four members"
        )
    result: list[dict[str, Any]] = []
    total = 0
    for expected_path, raw in zip(MEMBER_PATHS, value, strict=True):
        member = contract.mapping(raw, "private closure inventory member")
        contract.exact_keys(
            member,
            {"path", "size_bytes", "sha256"},
            "private closure inventory member",
        )
        if member["path"] != expected_path:
            raise contract.ReceiptValidationError(
                "private closure inventory path/order mismatch"
            )
        size = contract.positive_int(member["size_bytes"], "private member size")
        if size > MAX_MEMBER_BYTES:
            raise contract.ReceiptValidationError("private member exceeds byte limit")
        contract.digest(member["sha256"], "private member sha256")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise contract.ReceiptValidationError(
                "private closure inventory exceeds byte limit"
            )
        result.append(dict(member))
    return tuple(result)


def digest(records: Sequence[Mapping[str, Any]]) -> str:
    """Hash the canonical private-ledger inventory document."""

    normalized = validate(list(records))
    document = {"schema": SCHEMA, "schema_version": 1, "members": normalized}
    return "sha256:" + hashlib.sha256(canonical_json_bytes(document)).hexdigest()
