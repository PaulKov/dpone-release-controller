"""Canonical distribution and GitHub asset inventories for receipt v2."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_distribution_contract
from tools.evidence import release_pypi_limits
from tools.evidence.release_canonical import canonical_json_bytes

DISTRIBUTION_SCHEMA = "dpone.release-distribution-inventory.v2"
GITHUB_ASSET_SCHEMA = "dpone.release-github-asset-inventory.v2"


def distribution_inventory(value: Any) -> tuple[dict[str, Any], ...]:
    """Validate the ordered exact four-project wheel/sdist matrix."""

    records = _records(value, "distribution inventory", 8)
    normalized: list[dict[str, Any]] = []
    version = contract.stable_version(records[0].get("version"))
    expected_rows = release_distribution_contract.matrix(version)
    for index, (raw, (project, _artifact_type, expected_name)) in enumerate(
        zip(records, expected_rows)
    ):
        contract.exact_keys(
            raw,
            {"project", "version", "filename", "size_bytes", "sha256"},
            f"distribution[{index}]",
        )
        contract.enum(raw["project"], set(contract.PROJECTS), "project")
        observed_version = contract.stable_version(raw["version"])
        filename = contract.filename(raw["filename"])
        if (
            raw["project"] != project
            or observed_version != version
            or filename != expected_name
        ):
            raise contract.ReceiptValidationError("distribution matrix/order mismatch")
        require_distribution_file_size(
            raw["size_bytes"], f"distribution[{index}].size_bytes"
        )
        contract.digest(raw["sha256"], "distribution.sha256")
        normalized.append(dict(raw))
    require_distribution_inventory_sizes(normalized, "distribution inventory")
    return tuple(normalized)


def distribution_subset_inventory(value: Any) -> tuple[dict[str, Any], ...]:
    """Validate an ordered, duplicate-free subset of the exact matrix."""

    if not isinstance(value, list) or len(value) > 8:
        raise contract.ReceiptValidationError(
            "distribution subset must contain at most 8 records"
        )
    expected = distribution_inventory(_matrix_fixture(value))
    allowed = {
        (item["project"], item["version"], item["filename"]): item for item in expected
    }
    normalized: list[dict[str, Any]] = []
    positions: list[int] = []
    matrix_keys = list(allowed)
    for index, raw in enumerate(value):
        item = contract.mapping(raw, f"distribution subset[{index}]")
        contract.exact_keys(
            item,
            {"project", "version", "filename", "size_bytes", "sha256"},
            f"distribution subset[{index}]",
        )
        key = (item["project"], item["version"], item["filename"])
        if key not in allowed:
            raise contract.ReceiptValidationError(
                "distribution subset contains an unexpected file"
            )
        require_distribution_file_size(
            item["size_bytes"], f"distribution subset[{index}].size_bytes"
        )
        contract.digest(item["sha256"], "distribution.sha256")
        positions.append(matrix_keys.index(key))
        normalized.append(dict(item))
    if positions != sorted(set(positions)):
        raise contract.ReceiptValidationError(
            "distribution subset matrix/order mismatch"
        )
    require_distribution_inventory_sizes(normalized, "distribution subset")
    return tuple(normalized)


def require_distribution_file_size(value: Any, name: str) -> int:
    """Validate a receipt distribution against the frozen PyPI file limit."""

    size = contract.positive_int(value, name)
    try:
        return release_pypi_limits.require_file_size(size, name)
    except release_pypi_limits.PyPISizeLimitError as exc:
        raise contract.ReceiptValidationError(str(exc)) from exc


def require_distribution_inventory_sizes(
    records: Sequence[Mapping[str, Any]], name: str
) -> int:
    """Validate a receipt distribution set against the frozen A1 budget."""

    try:
        return release_pypi_limits.require_inventory_sizes(
            (record["size_bytes"] for record in records), name
        )
    except release_pypi_limits.PyPISizeLimitError as exc:
        raise contract.ReceiptValidationError(str(exc)) from exc


def _matrix_fixture(value: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Build shape-only matrix records used to derive canonical filenames."""

    version = "0.0.0"
    if value:
        version = contract.stable_version(value[0].get("version"))
        for item in value:
            if item.get("version") != version:
                raise contract.ReceiptValidationError(
                    "distribution subset version mismatch"
                )
    records: list[dict[str, Any]] = []
    for index, (project, _artifact_type, filename) in enumerate(
        release_distribution_contract.matrix(version)
    ):
        records.append(
            {
                "project": project,
                "version": version,
                "filename": filename,
                "size_bytes": index + 1,
                "sha256": "sha256:" + f"{index + 1:064x}",
            }
        )
    return records


def github_asset_inventory(
    value: Any, *, expected_count: int
) -> tuple[dict[str, Any], ...]:
    """Validate a sorted, duplicate-free exact release asset inventory."""

    records = _records(value, "GitHub asset inventory", expected_count)
    normalized: list[dict[str, Any]] = []
    previous = ""
    for index, raw in enumerate(records):
        contract.exact_keys(
            raw,
            {"name", "size_bytes", "sha256"},
            f"release_asset_inventory[{index}]",
        )
        name = contract.filename(raw["name"], "asset.name")
        if name <= previous:
            raise contract.ReceiptValidationError(
                "GitHub asset inventory must be strictly filename-sorted"
            )
        previous = name
        contract.positive_int(raw["size_bytes"], "asset.size_bytes")
        contract.digest(raw["sha256"], "asset.sha256")
        normalized.append(dict(raw))
    return tuple(normalized)


def inventory_sha256(schema: str, records: Sequence[Mapping[str, Any]]) -> str:
    """Hash the exact canonical inventory document bytes."""

    document = {"schema": schema, "schema_version": 2, "files": list(records)}
    return "sha256:" + hashlib.sha256(canonical_json_bytes(document)).hexdigest()


def require_digest(
    supplied: Any, schema: str, records: Sequence[Mapping[str, Any]], name: str
) -> str:
    """Require a supplied digest to match a canonical inventory."""

    contract.digest(supplied, name)
    expected = inventory_sha256(schema, records)
    if supplied != expected:
        raise contract.ReceiptValidationError(f"{name} mismatch")
    return expected


def _records(value: Any, name: str, expected_count: int) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or len(value) != expected_count:
        raise contract.ReceiptValidationError(
            f"{name} must contain exactly {expected_count} records"
        )
    return [contract.mapping(item, f"{name} member") for item in value]
