"""Normative production registry for receipt-envelope v2 structural schema.

The checked JSON source is the language-neutral contract authority.  Runtime
semantic validators remain authoritative for cross-field and state-machine
rules that JSON Schema cannot express.
"""

from __future__ import annotations

import copy
import hashlib
from typing import Any, Mapping

from tools.evidence import release_receipt_contract as receipt_contract
from tools.evidence.release_contract_source import (
    CONTRACT_ROOT,
    ContractSourceError,
    REPOSITORY_ROOT,
    load_object,
    pretty_json_bytes,
)

REGISTRY_SOURCE = CONTRACT_ROOT / "registries/release-receipt-envelope-v2.json"
SOURCE = (
    REPOSITORY_ROOT / "docs/schemas/release/release-receipt-envelope-v2.schema.json"
)
EXPECTED_ID = (
    "https://github.com/PaulKov/dpone-release-controller/blob/master/"
    "docs/schemas/release/release-receipt-envelope-v2.schema.json"
)


def document() -> dict[str, Any]:
    """Return a validated copy of the normative structural schema registry."""

    metadata = load_object(REGISTRY_SOURCE, label="receipt-envelope v2 registry")
    value = load_object(SOURCE, label="receipt-envelope v2 schema registry")
    _validate_metadata(metadata, value)
    _validate_schema(value)
    return copy.deepcopy(value)


def schema_bytes() -> bytes:
    """Return the stable public JSON Schema projection bytes."""

    return pretty_json_bytes(document())


def registered_receipt_types(value: Mapping[str, Any] | None = None) -> frozenset[str]:
    """Return every receipt type represented by at least one closed union branch."""

    schema = value if value is not None else document()
    try:
        variants = schema["allOf"][0]["oneOf"]
        return frozenset(
            branch["properties"]["receipt_type"]["const"] for branch in variants
        )
    except (KeyError, IndexError, TypeError) as exc:
        raise ContractSourceError("receipt schema union registry is malformed") from exc


def _validate_metadata(metadata: Mapping[str, Any], schema: Mapping[str, Any]) -> None:
    if set(metadata) != {
        "contract_id",
        "document_path",
        "document_sha256",
        "projection_mode",
        "receipt_types",
        "schema",
        "schema_version",
        "semantic_table",
        "semantic_validator",
    }:
        raise ContractSourceError("receipt contract registry keys are not exact")
    expected = {
        "contract_id": receipt_contract.SCHEMA,
        "document_path": SOURCE.relative_to(REPOSITORY_ROOT).as_posix(),
        "projection_mode": "checked-public-source",
        "schema": "dpone.release-contract-registry.v1",
        "schema_version": 1,
        "semantic_table": "docs/release-receipt-v2-semantics.md",
        "semantic_validator": "tools/evidence/release_receipt_envelope_v2.py",
    }
    if any(metadata.get(key) != value for key, value in expected.items()):
        raise ContractSourceError("receipt contract registry metadata drift")
    kinds = metadata.get("receipt_types")
    if kinds != sorted(receipt_contract.PAYLOAD_KINDS):
        raise ContractSourceError("receipt contract registry kind inventory drift")
    digest = "sha256:" + hashlib.sha256(pretty_json_bytes(schema)).hexdigest()
    if metadata.get("document_sha256") != digest:
        raise ContractSourceError("receipt schema registry digest mismatch")


def _validate_schema(value: Mapping[str, Any]) -> None:
    expected_top_level = {
        "$defs",
        "$id",
        "$schema",
        "additionalProperties",
        "allOf",
        "description",
        "properties",
        "required",
        "title",
        "type",
        "x-dpone-semantic-table",
        "x-dpone-semantic-validator",
    }
    if set(value) != expected_top_level:
        raise ContractSourceError("receipt schema registry keys are not exact")
    if (
        value["$schema"] != "https://json-schema.org/draft/2020-12/schema"
        or value["$id"] != EXPECTED_ID
        or value["type"] != "object"
        or value["additionalProperties"] is not False
        or value["x-dpone-semantic-validator"]
        != "tools/evidence/release_receipt_envelope_v2.py"
    ):
        raise ContractSourceError("receipt schema registry authority metadata drift")
    try:
        variants = value["allOf"][0]["oneOf"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ContractSourceError("receipt schema union registry is malformed") from exc
    if not isinstance(variants, list) or not variants:
        raise ContractSourceError("receipt schema union registry must not be empty")
    for index, branch in enumerate(variants):
        _validate_branch(branch, index)
    registered = registered_receipt_types(value)
    if registered != receipt_contract.PAYLOAD_KINDS:
        raise ContractSourceError(
            "receipt schema/runtime kind mismatch: "
            f"missing={sorted(receipt_contract.PAYLOAD_KINDS - registered)}, "
            f"extra={sorted(registered - receipt_contract.PAYLOAD_KINDS)}"
        )
    property_types = value.get("properties", {}).get("receipt_type", {}).get("enum")
    if property_types != sorted(registered):
        raise ContractSourceError("receipt schema receipt_type enum drift")


def _validate_branch(value: Any, index: int) -> None:
    if not isinstance(value, dict) or set(value) not in (
        {"not", "properties", "required"},
        {"properties", "required"},
    ):
        raise ContractSourceError(f"receipt schema branch {index} keys are not exact")
    required = value.get("required")
    if required not in (
        ["payload", "receipt_type"],
        ["payload", "receipt_type", "lease"],
    ):
        raise ContractSourceError(f"receipt schema branch {index} required set drift")
    properties = value.get("properties")
    if not isinstance(properties, dict) or set(properties) != {
        "payload",
        "receipt_type",
    }:
        raise ContractSourceError(f"receipt schema branch {index} properties drift")
    receipt_type = properties["receipt_type"]
    payload = properties["payload"]
    if (
        not isinstance(receipt_type, dict)
        or set(receipt_type) != {"const"}
        or receipt_type["const"] not in receipt_contract.PAYLOAD_KINDS
        or not isinstance(payload, dict)
        or payload.get("type") != "object"
        or payload.get("additionalProperties") is not False
    ):
        raise ContractSourceError(f"receipt schema branch {index} is not closed")
    if "lease" in required:
        if "not" in value:
            raise ContractSourceError(
                f"leased receipt schema branch {index} forbids lease"
            )
    elif value.get("not") != {"required": ["lease"]}:
        raise ContractSourceError(f"pre-lease schema branch {index} must forbid lease")
