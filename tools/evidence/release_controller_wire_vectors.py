"""Production-owned reference corpus for contextual controller wire contracts.

Generic JSON codec vectors are constructed directly by their production codec.
Only contextual JSON and binary/provider boundaries need checked source bytes;
every source is replayed through its real parser before a generator may copy it
to the conformance-fixture projection.
"""

from __future__ import annotations

import json

from tools.evidence.release_canonical import canonical_json_bytes
from tools.evidence.release_contract_source import CONTRACT_ROOT, ContractSourceError
from tools.evidence.release_controller_schema_registry import DELEGATED

REFERENCE_ROOT = CONTRACT_ROOT / "vectors/release-controller-wire-v1"


def reference_files() -> dict[str, bytes]:
    """Return and deeply verify the complete delegated reference inventory."""

    expected_names = {
        name
        for codec in DELEGATED
        for name in (codec.golden_body_name, codec.golden_headers_name)
        if name is not None
    }
    try:
        actual_names = {
            path.name for path in REFERENCE_ROOT.iterdir() if path.is_file()
        }
    except OSError as exc:
        raise ContractSourceError(
            "controller wire reference root is unavailable"
        ) from exc
    if actual_names != expected_names:
        raise ContractSourceError(
            "controller wire reference inventory drift: "
            f"missing={sorted(expected_names - actual_names)}, "
            f"extra={sorted(actual_names - expected_names)}"
        )

    result = {
        name: (REFERENCE_ROOT / name).read_bytes() for name in sorted(expected_names)
    }
    for codec in DELEGATED:
        body = result[codec.golden_body_name]
        headers = None
        if codec.golden_headers_name is not None:
            raw_headers = result[codec.golden_headers_name]
            try:
                headers = json.loads(raw_headers)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ContractSourceError(
                    f"{codec.schema_id} reference headers are invalid"
                ) from exc
            if (
                not isinstance(headers, dict)
                or canonical_json_bytes(headers) != raw_headers
            ):
                raise ContractSourceError(
                    f"{codec.schema_id} reference headers are not canonical"
                )
        codec.verify(body, headers, fixture_root=REFERENCE_ROOT)
    return result
