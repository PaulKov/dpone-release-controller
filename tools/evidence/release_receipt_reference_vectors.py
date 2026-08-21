"""Normative language-neutral reference vectors for receipt-envelope v2."""

from __future__ import annotations

import copy
from typing import Any

from tools.evidence import release_receipt_contract as receipt_contract
from tools.evidence import release_receipt_envelope_v2 as receipt_envelope
from tools.evidence.release_contract_source import CONTRACT_ROOT, load_object

POSITIVE_SOURCE = (
    CONTRACT_ROOT / "vectors/release/release-receipt-envelope-v2-positive.json"
)


def positive_envelope() -> dict[str, Any]:
    """Return the independently checked positive envelope after semantic validation."""

    value = load_object(POSITIVE_SOURCE, label="receipt-envelope v2 positive vector")
    receipt_envelope.verify(value)
    if (
        value.get("schema") != receipt_contract.SCHEMA
        or value.get("schema_version") != receipt_contract.SCHEMA_VERSION
        or value.get("receipt_type") != "REQUEST_ENQUEUED"
        or value.get("stream", {}).get("sequence") != 0
    ):
        raise ValueError("receipt positive vector identity drift")
    return copy.deepcopy(value)
