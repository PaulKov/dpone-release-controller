"""A0 expected service-authority projection and provider observation."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

from tools.evidence import release_controller_service_inventory as inventory
from tools.evidence import release_receipt_contract as contract
from tools.evidence.release_canonical import canonical_json_bytes
from tools.evidence.release_controller_service_errors import ServiceActivationError

EXPECTED_SCHEMA = "dpone.expected-service-authorities.v1"
SCHEMA_VERSION = 1
DEPLOYMENT_OBSERVER_ROLE = "cloudflare_deployment_observer"
PROVIDER_API_VERSION = "cloudflare-v4"


def expected_document(
    *,
    account_id: str,
    broker_source_commit_sha: str,
    authorities: Sequence[Mapping[str, Any]],
    provider_observed_at: str,
) -> dict[str, Any]:
    """Build the self-excluding document embedded by the outer A0 record."""

    result = {
        "schema": EXPECTED_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "account_id": account_id,
        "broker_source_commit_sha": broker_source_commit_sha,
        "authorities": [dict(authority) for authority in authorities],
        "receipt_role_bindings": inventory.role_bindings(),
        "provider_observation": _provider_observation(
            authorities, provider_observed_at
        ),
    }
    validate_expected(result)
    return result


def validate_expected(value: Any) -> dict[str, Mapping[str, Any]]:
    """Validate exact A0 rows and return an authority-role index."""

    document = _mapping(value, "expected service authorities")
    _keys(
        document,
        {
            "schema",
            "schema_version",
            "account_id",
            "broker_source_commit_sha",
            "authorities",
            "receipt_role_bindings",
            "provider_observation",
        },
        "expected service authorities",
    )
    if document["schema"] != EXPECTED_SCHEMA or document["schema_version"] != 1:
        raise ServiceActivationError("expected authority schema/version mismatch")
    _git_sha(document["broker_source_commit_sha"], "broker_source_commit_sha")
    if document["receipt_role_bindings"] != inventory.role_bindings():
        raise ServiceActivationError("expected receipt role bindings mismatch")
    authorities = document["authorities"]
    if not isinstance(authorities, list):
        raise ServiceActivationError("expected authorities must be an array")
    rows: list[dict[str, Any]] = []
    previous = ""
    for raw in authorities:
        row = _mapping(raw, "expected service authority")
        _keys(row, _AUTHORITY_KEYS, "expected service authority")
        role = row["authority_role"]
        if not isinstance(role, str) or role <= previous:
            raise ServiceActivationError("expected authority roles are not byte-sorted")
        previous = role
        for key in ("configuration_sha256", "version_resource_projection_sha256"):
            _digest(row[key], key)
        rows.append(dict(row))
    try:
        indexed = inventory.validate_authorities(document["account_id"], rows)
    except inventory.ServiceInventoryError as exc:
        raise ServiceActivationError(str(exc)) from exc
    if any(
        row["source_commit_sha"] != document["broker_source_commit_sha"]
        for row in indexed.values()
    ):
        raise ServiceActivationError("expected authority source commit mismatch")
    _validate_provider_observation(
        document["provider_observation"], indexed, document["authorities"]
    )
    return {row["authority_role"]: row for row in authorities if isinstance(row, dict)}


def expected_digest(value: Any) -> str:
    """Return tagged canonical digest of the validated A0 document."""

    validate_expected(value)
    return _sha256(canonical_json_bytes(value))


_AUTHORITY_KEYS = {
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
}


def _provider_observation(
    authorities: Sequence[Mapping[str, Any]], observed_at: str
) -> dict[str, Any]:
    indexed = {row["authority_role"]: row for row in authorities}
    observer = indexed[DEPLOYMENT_OBSERVER_ROLE]
    return {
        "schema": "dpone.service-authority-provider-observation.v1",
        "schema_version": 1,
        "observer_authority_role": DEPLOYMENT_OBSERVER_ROLE,
        "observer_service_identity": observer["service_identity"],
        "observer_worker_version_id": observer["worker_version_id"],
        "provider_api_version": PROVIDER_API_VERSION,
        "provider_observation_count": len(authorities),
        "provider_observation_aggregate_sha256": _observation_rows_digest(authorities),
        "observed_at": observed_at,
    }


def _validate_provider_observation(
    value: Any,
    authorities: Mapping[str, Mapping[str, Any]],
    ordered_rows: Any,
) -> None:
    observation = _mapping(value, "expected provider observation")
    _keys(
        observation,
        {
            "schema",
            "schema_version",
            "observer_authority_role",
            "observer_service_identity",
            "observer_worker_version_id",
            "provider_api_version",
            "provider_observation_count",
            "provider_observation_aggregate_sha256",
            "observed_at",
        },
        "expected provider observation",
    )
    observer = authorities[DEPLOYMENT_OBSERVER_ROLE]
    if (
        observation["schema"] != "dpone.service-authority-provider-observation.v1"
        or observation["schema_version"] != 1
        or observation["observer_authority_role"] != DEPLOYMENT_OBSERVER_ROLE
        or observation["observer_service_identity"] != observer["service_identity"]
        or observation["observer_worker_version_id"] != observer["worker_version_id"]
        or observation["provider_api_version"] != PROVIDER_API_VERSION
        or observation["provider_observation_count"] != len(authorities)
        or observation["provider_observation_aggregate_sha256"]
        != _observation_rows_digest(ordered_rows)
    ):
        raise ServiceActivationError("expected provider observation mismatch")
    contract.timestamp(observation["observed_at"], "expected provider observed_at")


def _observation_rows_digest(authorities: Any) -> str:
    rows = [
        {
            "authority_role": row["authority_role"],
            "deployment_observation_sha256": row["deployment_observation_sha256"],
            "deployment_observation_record_id": row["deployment_observation_record_id"],
            "deployment_observation_record_sha256": row[
                "deployment_observation_record_sha256"
            ],
        }
        for row in authorities
    ]
    return _sha256(
        canonical_json_bytes(
            {
                "schema": "dpone.service-authority-provider-observation-set.v1",
                "schema_version": 1,
                "authorities": rows,
            }
        )
    )


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ServiceActivationError(f"{name} must be an object")
    return value


def _keys(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise ServiceActivationError(f"{name} keys are not exact")


def _digest(value: Any, name: str) -> None:
    try:
        contract.digest(value, name)
    except contract.ReceiptValidationError as exc:
        raise ServiceActivationError(str(exc)) from exc


def _git_sha(value: Any, name: str) -> None:
    try:
        contract.git_sha(value, name)
    except contract.ReceiptValidationError as exc:
        raise ServiceActivationError(str(exc)) from exc


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()
