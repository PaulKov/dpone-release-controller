"""Generate the closed structural JSON Schema for receipt-envelope v2.

Semantic and cross-receipt constraints remain normative in the Python
validator and the checked semantic transition table named by the schema.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.release_generator_support import (  # noqa: E402
    ManagedRoot,
    parse_check_mode,
    reconcile_generated_files,
)

OUTPUT = ROOT / "docs/schemas/release/release-receipt-envelope-v2.schema.json"
MANAGED_PATTERNS = ("release-receipt-envelope-*.schema.json",)
DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
GIT_SHA_PATTERN = r"^[0-9a-f]{40}$"
TIMESTAMP_PATTERN = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
MAX_SAFE_INTEGER = 9_007_199_254_740_991
NONNEGATIVE_INTEGER_FIELDS = {
    "finding_count",
    "percentage",
    "pypi_exact_file_count",
    "queue_sequence",
    "rekor_log_index",
    "sequence",
}
EXACT_VALUE_FIELDS = {
    "kind",
    "label",
    "provider_api_version",
    "schema",
    "schema_version",
    "transition",
}


def document() -> dict[str, Any]:
    """Return deterministic draft-2020-12 schema bytes."""
    from tests.release_receipt_fixtures import all_payloads, envelope_for

    envelopes = [envelope_for(payload) for payload in all_payloads()]
    first = envelopes[0]
    variants = _unique_schema(_variant_schema(value) for value in envelopes)
    common_required = [
        "attempt",
        "committer",
        "payload",
        "payload_sha256",
        "producer",
        "receipt_id",
        "receipt_type",
        "schema",
        "schema_version",
        "scope",
        "stream",
        "timestamps",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/PaulKov/dpone-release-controller/blob/master/docs/schemas/release/release-receipt-envelope-v2.schema.json",
        "title": "dpone release receipt envelope v2",
        "description": (
            "Closed structural union. Cross-field, state-order, provider, lease, "
            "and fencing rules in docs/release-receipt-v2-semantics.md are normative."
        ),
        "type": "object",
        "required": common_required,
        "properties": {
            "schema": {"const": "dpone.release-receipt-envelope.v2"},
            "schema_version": {"const": 2},
            "receipt_id": {"$ref": "#/$defs/digest"},
            "receipt_type": {
                "enum": sorted({value["receipt_type"] for value in envelopes})
            },
            "stream": {"$ref": "#/$defs/stream"},
            "scope": {"$ref": "#/$defs/scope"},
            "attempt": {"$ref": "#/$defs/attempt"},
            "lease": {"$ref": "#/$defs/lease"},
            "producer": {"$ref": "#/$defs/producer"},
            "committer": {"$ref": "#/$defs/committer"},
            "timestamps": {"$ref": "#/$defs/timestamps"},
            "payload": {"type": "object"},
            "payload_sha256": {"$ref": "#/$defs/digest"},
        },
        "additionalProperties": False,
        "allOf": [{"oneOf": variants}],
        "$defs": {
            "digest": {"type": "string", "pattern": DIGEST_PATTERN},
            "stream": _schema_for(first["stream"]),
            "scope": {
                "oneOf": _unique_schema(
                    _schema_for(value["scope"]) for value in envelopes
                )
            },
            "attempt": _schema_for(first["attempt"]),
            "lease": _schema_for(next(v["lease"] for v in envelopes if "lease" in v)),
            "producer": {
                "oneOf": _unique_schema(
                    _schema_for(value["producer"]) for value in envelopes
                )
            },
            "committer": _schema_for(first["committer"]),
            "timestamps": _schema_for(first["timestamps"]),
        },
        "x-dpone-semantic-validator": ("tools/evidence/release_receipt_envelope_v2.py"),
        "x-dpone-semantic-table": "docs/release-receipt-v2-semantics.md",
    }


def _variant_schema(envelope: Mapping[str, Any]) -> dict[str, Any]:
    required = ["payload", "receipt_type"]
    branch: dict[str, Any] = {
        "required": required,
        "properties": {
            "receipt_type": {"const": envelope["receipt_type"]},
            "payload": _schema_for(envelope["payload"]),
        },
    }
    if "lease" in envelope:
        required.append("lease")
    else:
        branch["not"] = {"required": ["lease"]}
    return branch


def _unique_schema(values: Any) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for value in values:
        marker = json.dumps(value, sort_keys=True, separators=(",", ":"))
        unique.setdefault(marker, value)
    return list(unique.values())


def _schema_for(value: Any, *, name: str = "") -> dict[str, Any]:
    if isinstance(value, dict):
        properties = {key: _schema_for(child, name=key) for key, child in value.items()}
        return {
            "type": "object",
            "required": sorted(value),
            "properties": properties,
            "additionalProperties": False,
        }
    if isinstance(value, list):
        if not value:
            return {"type": "array", "maxItems": 0}
        item_schemas = [_schema_for(item) for item in value]
        unique = []
        for schema in item_schemas:
            if schema not in unique:
                unique.append(schema)
        items = unique[0] if len(unique) == 1 else {"oneOf": unique}
        return {"type": "array", "items": items}
    if type(value) is bool:
        return {"type": "boolean"}
    if type(value) is int:
        minimum = 0 if name in NONNEGATIVE_INTEGER_FIELDS else 1
        return {
            "type": "integer",
            "minimum": minimum,
            "maximum": MAX_SAFE_INTEGER,
        }
    if isinstance(value, str):
        if name in EXACT_VALUE_FIELDS:
            return {"const": value}
        if re.fullmatch(DIGEST_PATTERN, value):
            return {"type": "string", "pattern": DIGEST_PATTERN}
        if re.fullmatch(GIT_SHA_PATTERN, value):
            return {"type": "string", "pattern": GIT_SHA_PATTERN}
        if re.fullmatch(TIMESTAMP_PATTERN, value):
            return {"type": "string", "pattern": TIMESTAMP_PATTERN}
        return {"type": "string", "minLength": 1, "maxLength": 512}
    raise TypeError(f"unsupported schema example {type(value).__name__}")


def schema_bytes() -> bytes:
    return (json.dumps(document(), indent=2, sort_keys=True) + "\n").encode()


def managed_roots() -> tuple[ManagedRoot, ...]:
    """Return the receipt-envelope namespace inside the shared schema root."""

    return (ManagedRoot(OUTPUT.parent, MANAGED_PATTERNS),)


def generate(*, check: bool) -> int:
    """Verify or atomically update the exact receipt-envelope schema."""

    return reconcile_generated_files(
        {OUTPUT: schema_bytes()},
        managed_roots(),
        check=check,
        label="receipt envelope schema",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    return generate(check=parse_check_mode(parser, argv))


if __name__ == "__main__":
    raise SystemExit(main())
