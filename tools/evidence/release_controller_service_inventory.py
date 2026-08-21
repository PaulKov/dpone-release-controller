"""Post-promotion authority inventory for trusted controller services.

The sanitized inventory is materialized in WORM storage only after Cloudflare
provider requery proves the final ingress version at 100 percent.  Logical
receipt roles bind to these executable authority rows; credentials, key IDs,
webhook secrets and fingerprints are never exposed in closure evidence.
"""

from __future__ import annotations

import hashlib
import re
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from tools.evidence import release_controller_service_bindings as bindings
from tools.evidence import release_receipt_contract as contract
from tools.evidence.release_canonical import canonical_json_bytes
from tools.evidence.release_controller_service_inventory_types import (
    AUTHORITY_BINDINGS,
    INGRESS_ROLE,
    SCHEMA,
    SCHEMA_VERSION,
    CompiledServiceInventory,
    ServiceInventoryError,
)
from tools.evidence.release_controller_service_roles import (
    AUTHORITY_ROLE_BY_SERVICE_ROLE,
)

_ACCOUNT_RE = re.compile(r"[0-9a-f]{32}\Z")
_CLOUDFLARE_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)


def document(
    *,
    account_id: str,
    authorities: Sequence[Mapping[str, Any]],
    ingress_promotion: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the exact sanitized, post-promotion WORM projection."""

    result = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "account_id": account_id,
        "authorities": [dict(authority) for authority in authorities],
        "receipt_role_bindings": role_bindings(),
        "ingress_promotion": dict(ingress_promotion),
    }
    validate(result)
    return result


def validate(value: Any) -> dict[str, Mapping[str, Any]]:
    """Return the authority-role index after closed semantic validation."""

    inventory = _mapping(value, "service authority inventory")
    _exact_keys(
        inventory,
        {
            "schema",
            "schema_version",
            "account_id",
            "authorities",
            "receipt_role_bindings",
            "ingress_promotion",
        },
        "service authority inventory",
    )
    if inventory["schema"] != SCHEMA or inventory["schema_version"] != 1:
        raise ServiceInventoryError("service inventory schema/version mismatch")
    account_id = inventory["account_id"]
    if not isinstance(account_id, str) or _ACCOUNT_RE.fullmatch(account_id) is None:
        raise ServiceInventoryError("service inventory account ID is invalid")
    indexed = validate_authorities(account_id, inventory["authorities"])
    if inventory["receipt_role_bindings"] != role_bindings():
        raise ServiceInventoryError("receipt role/authority bindings mismatch")
    _promotion(inventory["ingress_promotion"], indexed[INGRESS_ROLE])
    return indexed


def role_bindings() -> list[dict[str, str]]:
    """Return the complete byte-sorted logical-to-executable role mapping."""

    return [
        {
            "service_role": service_role,
            "service_authority_role": AUTHORITY_ROLE_BY_SERVICE_ROLE[service_role],
        }
        for service_role in sorted(AUTHORITY_ROLE_BY_SERVICE_ROLE)
    ]


def validate_authorities(
    account_id: str, authorities: Any
) -> dict[str, Mapping[str, Any]]:
    """Validate one complete executable-authority array."""

    if not isinstance(authorities, list):
        raise ServiceInventoryError("service inventory authorities must be an array")
    indexed: dict[str, Mapping[str, Any]] = {}
    previous = ""
    source_commit: str | None = None
    observation_record_ids: set[str] = set()
    observation_record_digests: set[str] = set()
    for raw in authorities:
        authority = _authority(raw, account_id)
        role = authority["authority_role"]
        if role <= previous or role in indexed:
            raise ServiceInventoryError(
                "authority roles must be unique and byte-sorted"
            )
        previous = role
        indexed[role] = authority
        source_commit = source_commit or authority["source_commit_sha"]
        if authority["source_commit_sha"] != source_commit:
            raise ServiceInventoryError("service authority source commit drift")
        record_id = authority["deployment_observation_record_id"]
        record_digest = authority["deployment_observation_record_sha256"]
        if (
            record_id in observation_record_ids
            or record_digest in observation_record_digests
        ):
            raise ServiceInventoryError(
                "deployment observation WORM anchors must be unique"
            )
        observation_record_ids.add(record_id)
        observation_record_digests.add(record_digest)
    if set(indexed) != set(AUTHORITY_BINDINGS):
        raise ServiceInventoryError(
            "service authority coverage mismatch: "
            f"missing={sorted(set(AUTHORITY_BINDINGS) - set(indexed))}, "
            f"unexpected={sorted(set(indexed) - set(AUTHORITY_BINDINGS))}"
        )
    return indexed


def digest(value: Any) -> str:
    """Return tagged SHA-256 of the validated canonical inventory bytes."""

    validate(value)
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def compile_inventory(value: Any) -> CompiledServiceInventory:
    """Validate once and freeze the lookup/digest context for stream replay."""

    document_value = _mapping(value, "service authority inventory")
    indexed = validate(document_value)
    sha256 = (
        "sha256:" + hashlib.sha256(canonical_json_bytes(document_value)).hexdigest()
    )
    return CompiledServiceInventory(
        document=MappingProxyType(dict(document_value)),
        indexed=MappingProxyType(dict(indexed)),
        sha256=sha256,
    )


def bind_committer(
    committer: Mapping[str, Any], context: CompiledServiceInventory
) -> None:
    """Cross-bind the broker committer and post-promotion inventory."""

    bindings.bind_committer(committer, context)


def bind_producer(
    producer: Mapping[str, Any], context: CompiledServiceInventory
) -> None:
    """Bind one trusted producer to its activated executable authority row."""

    bindings.bind_producer(producer, context)


def bind_candidate_reader(
    payload: Mapping[str, Any], context: CompiledServiceInventory
) -> None:
    """Bind candidate provider bytes to the activated route-less reader."""

    bindings.bind_candidate_reader(payload, context)


def bind_authority_guard(
    guard: Mapping[str, Any],
    context: CompiledServiceInventory,
    *,
    head_record_id: str,
    head_record_sha256: str,
) -> None:
    """Bind a fresh effect guard's authorizer to the activated inventory row."""

    bindings.bind_authority_guard(
        guard,
        context,
        head_record_id=head_record_id,
        head_record_sha256=head_record_sha256,
    )


def _authority(value: Any, account_id: str) -> Mapping[str, Any]:
    authority = _mapping(value, "service authority")
    _exact_keys(
        authority,
        {
            "authority_role",
            "binding",
            "service",
            "service_identity",
            "worker_version_id",
            "deployment_id",
            "deployment_observation_sha256",
            "deployment_observation_record_id",
            "deployment_observation_record_sha256",
            "deployment_versions",
            "source_commit_sha",
            "source_sha256",
            "configuration_sha256",
            "version_resource_projection_sha256",
        },
        "service authority",
    )
    role = authority["authority_role"]
    if not isinstance(role, str) or role not in AUTHORITY_BINDINGS:
        raise ServiceInventoryError("service authority role is not closed")
    if authority["binding"] != AUTHORITY_BINDINGS[role]:
        raise ServiceInventoryError("service authority binding mismatch")
    _opaque(authority["service"], "service authority service")
    for key in ("worker_version_id", "deployment_id"):
        _cloudflare_uuid(authority[key], f"service authority {key}")
    expected_identity = (
        f"cloudflare-worker:{account_id}/{authority['service']}"
        f"@{authority['worker_version_id']}"
    )
    if authority["service_identity"] != expected_identity:
        raise ServiceInventoryError("service authority identity derivation mismatch")
    _digest(
        authority["deployment_observation_sha256"],
        "deployment_observation_sha256",
    )
    _digest(
        authority["deployment_observation_record_id"],
        "deployment_observation_record_id",
    )
    _digest(
        authority["deployment_observation_record_sha256"],
        "deployment_observation_record_sha256",
    )
    _git_sha(authority["source_commit_sha"], "source_commit_sha")
    for key in (
        "source_sha256",
        "configuration_sha256",
        "version_resource_projection_sha256",
    ):
        _digest(authority[key], key)
    versions = _versions(authority["deployment_versions"])
    if role != INGRESS_ROLE and versions != (
        {"percentage": 100, "worker_version_id": authority["worker_version_id"]},
    ):
        raise ServiceInventoryError("private authority must be exact one-version@100")
    return authority


def _promotion(value: Any, ingress: Mapping[str, Any]) -> None:
    promotion = _mapping(value, "ingress promotion")
    _exact_keys(
        promotion,
        {
            "pre_promotion_deployment_id",
            "pre_promotion_deployment_observation_sha256",
            "pre_promotion_deployment_observation_record_id",
            "pre_promotion_deployment_observation_record_sha256",
            "pre_promotion_deployment_versions",
            "post_promotion_deployment_id",
            "post_promotion_deployment_observation_sha256",
            "post_promotion_deployment_observation_record_id",
            "post_promotion_deployment_observation_record_sha256",
            "post_promotion_deployment_versions",
        },
        "ingress promotion",
    )
    for key in ("pre_promotion_deployment_id", "post_promotion_deployment_id"):
        _cloudflare_uuid(promotion[key], key)
    for key in (
        "pre_promotion_deployment_observation_sha256",
        "pre_promotion_deployment_observation_record_id",
        "pre_promotion_deployment_observation_record_sha256",
        "post_promotion_deployment_observation_sha256",
        "post_promotion_deployment_observation_record_id",
        "post_promotion_deployment_observation_record_sha256",
    ):
        _digest(promotion[key], key)
    pre = _versions(promotion["pre_promotion_deployment_versions"])
    post = _versions(promotion["post_promotion_deployment_versions"])
    ingress_versions = _versions(ingress["deployment_versions"])
    if (
        len(pre) != 2
        or len(post) != 1
        or not {row["worker_version_id"] for row in post}.issubset(
            {row["worker_version_id"] for row in pre}
        )
        or post != ingress_versions
        or promotion["post_promotion_deployment_id"] != ingress["deployment_id"]
        or promotion["post_promotion_deployment_observation_sha256"]
        != ingress["deployment_observation_sha256"]
        or promotion["post_promotion_deployment_observation_record_id"]
        != ingress["deployment_observation_record_id"]
        or promotion["post_promotion_deployment_observation_record_sha256"]
        != ingress["deployment_observation_record_sha256"]
    ):
        raise ServiceInventoryError("ingress promotion membership mismatch")
    final = ingress["worker_version_id"]
    pre_by_version = {row["worker_version_id"]: row["percentage"] for row in pre}
    post_by_version = {row["worker_version_id"]: row["percentage"] for row in post}
    bootstrap = next(version for version in pre_by_version if version != final)
    if pre_by_version != {bootstrap: 100, final: 0} or post_by_version != {final: 100}:
        raise ServiceInventoryError("ingress promotion is not bootstrap-to-final")


def _versions(value: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list) or not value:
        raise ServiceInventoryError("deployment_versions must be non-empty")
    result: list[dict[str, Any]] = []
    previous = ""
    total = 0
    for raw in value:
        row = _mapping(raw, "deployment version")
        _exact_keys(row, {"percentage", "worker_version_id"}, "deployment version")
        version = row["worker_version_id"]
        _cloudflare_uuid(version, "deployment version worker_version_id")
        if version <= previous:
            raise ServiceInventoryError("deployment versions must be byte-sorted")
        previous = version
        percentage = row["percentage"]
        if type(percentage) is not int or not 0 <= percentage <= 100:
            raise ServiceInventoryError("deployment percentage is outside [0,100]")
        total += percentage
        result.append(dict(row))
    if total != 100:
        raise ServiceInventoryError("deployment percentages must sum to 100")
    return tuple(result)


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ServiceInventoryError(f"{name} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise ServiceInventoryError(f"{name} keys are not exact")


def _digest(value: Any, name: str) -> None:
    try:
        contract.digest(value, name)
    except contract.ReceiptValidationError as exc:
        raise ServiceInventoryError(str(exc)) from exc


def _git_sha(value: Any, name: str) -> None:
    try:
        contract.git_sha(value, name)
    except contract.ReceiptValidationError as exc:
        raise ServiceInventoryError(str(exc)) from exc


def _opaque(value: Any, name: str) -> None:
    try:
        contract.opaque(value, name)
    except contract.ReceiptValidationError as exc:
        raise ServiceInventoryError(str(exc)) from exc


def _cloudflare_uuid(value: Any, name: str) -> None:
    if not isinstance(value, str) or _CLOUDFLARE_UUID_RE.fullmatch(value) is None:
        raise ServiceInventoryError(f"{name} must be a lowercase Cloudflare UUID")
