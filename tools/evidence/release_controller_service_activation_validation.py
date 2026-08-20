"""Validation for the post-A1 service-authority activation record.

This module owns semantic validation only.  Builders and WORM-head projection
remain in the public ``release_controller_service_activation`` facade so the
dependency graph is one-way and boundary validation stays independently
testable.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from tools.evidence import release_controller_service_expectation as expectation
from tools.evidence import release_controller_service_inventory as activated
from tools.evidence import release_receipt_contract as contract
from tools.evidence.release_canonical import canonical_json_bytes
from tools.evidence.release_controller_service_errors import ServiceActivationError

ACTIVATION_SCHEMA = "dpone.service-authority-activation-record.v1"
SCHEMA_VERSION = 1
MAX_PROMOTION_EPOCH_SECONDS = 300
MAX_PROVIDER_OBSERVATION_SECONDS = 30
MAX_ACCEPTANCE_DELAY_SECONDS = 30
DEPLOYMENT_OBSERVER_ROLE = expectation.DEPLOYMENT_OBSERVER_ROLE
PROVIDER_API_VERSION = expectation.PROVIDER_API_VERSION


def validate_activation(value: Any) -> None:
    """Verify A0→A1→post-promotion bytes and every static/deployment bind."""

    record = _mapping(value, "service authority activation")
    _keys(
        record,
        {
            "schema",
            "schema_version",
            "provisioned",
            "previous",
            "expected_service_authorities",
            "expected_service_authorities_sha256",
            "activated_service_authorities",
            "activated_service_authorities_sha256",
            "promotion_epoch",
            "provider_observation_window",
            "provider_observation_aggregate_sha256",
            "observed_at",
            "broker_accepted_at",
        },
        "service authority activation",
    )
    if record["schema"] != ACTIVATION_SCHEMA or record["schema_version"] != 1:
        raise ServiceActivationError("service activation schema/version mismatch")
    provisioned = _record_pointer(record["provisioned"], "service activation A0")
    previous = _record_pointer(record["previous"], "service activation previous")
    expected = _mapping(
        record["expected_service_authorities"], "expected service authorities"
    )
    final = _mapping(
        record["activated_service_authorities"], "activated service authorities"
    )
    expected_index = expectation.validate_expected(expected)
    try:
        final_index = activated.validate(final)
    except activated.ServiceInventoryError as exc:
        raise ServiceActivationError(str(exc)) from exc
    if (
        record["expected_service_authorities_sha256"]
        != expectation.expected_digest(expected)
        or record["activated_service_authorities_sha256"] != activated.digest(final)
        or final["account_id"] != expected["account_id"]
        or final["receipt_role_bindings"] != expected["receipt_role_bindings"]
    ):
        raise ServiceActivationError("service activation record/digest mismatch")
    _cross_bind_authorities(expected_index, final_index, final["ingress_promotion"])
    _epoch(record["promotion_epoch"])
    observation_started, observation_completed = _observation_window(
        record["provider_observation_window"], len(final_index), final_index
    )
    if record["provider_observation_aggregate_sha256"] != provider_observation_digest(
        final
    ):
        raise ServiceActivationError("provider observation aggregate mismatch")
    promotion_completed = contract.timestamp(
        record["promotion_epoch"]["completed_at"], "promotion completed_at"
    )
    promotion_started = contract.timestamp(
        record["promotion_epoch"]["started_at"], "promotion started_at"
    )
    expected_observed = contract.timestamp(
        expected["provider_observation"]["observed_at"],
        "expected provider observed_at",
    )
    observed = contract.timestamp(record["observed_at"], "activation observed_at")
    accepted = contract.timestamp(record["broker_accepted_at"], "broker_accepted_at")
    if (
        observed != observation_completed
        or not promotion_completed <= observation_started <= observation_completed
        or not observation_completed <= accepted
        or (accepted - observation_completed).total_seconds()
        > MAX_ACCEPTANCE_DELAY_SECONDS
        or expected_observed > promotion_started
    ):
        raise ServiceActivationError("activation observation chronology is invalid")
    if provisioned["record_id"] == previous["record_id"]:
        raise ServiceActivationError("A0 and A1 records must be distinct")


def provider_observation_digest(value: Mapping[str, Any]) -> str:
    """Aggregate every fresh deployment response without exposing raw bytes."""

    try:
        indexed = activated.validate(value)
    except activated.ServiceInventoryError as exc:
        raise ServiceActivationError(str(exc)) from exc
    projection = {
        "schema": "dpone.service-authority-provider-observation-set.v1",
        "schema_version": 1,
        "authorities": [
            {
                "authority_role": role,
                "deployment_observation_sha256": indexed[role][
                    "deployment_observation_sha256"
                ],
                "deployment_observation_record_id": indexed[role][
                    "deployment_observation_record_id"
                ],
                "deployment_observation_record_sha256": indexed[role][
                    "deployment_observation_record_sha256"
                ],
            }
            for role in sorted(indexed)
        ],
    }
    return _sha256(canonical_json_bytes(projection))


def authority_by_role(value: Mapping[str, Any], role: str) -> Mapping[str, Any]:
    """Return one closed authority row by its canonical role."""

    for authority in value["authorities"]:
        if authority.get("authority_role") == role:
            return authority
    raise ServiceActivationError(f"missing authority role: {role}")


def _cross_bind_authorities(
    expected: Mapping[str, Mapping[str, Any]],
    final: Mapping[str, Mapping[str, Any]],
    promotion: Any,
) -> None:
    static_keys = (
        "authority_role",
        "binding",
        "service",
        "service_identity",
        "worker_version_id",
        "source_commit_sha",
        "source_sha256",
        "configuration_sha256",
        "version_resource_projection_sha256",
    )
    if set(expected) != set(final):
        raise ServiceActivationError("expected/final authority coverage mismatch")
    for role in expected:
        if any(expected[role][key] != final[role][key] for key in static_keys):
            raise ServiceActivationError("expected/final static authority drift")
        if role != activated.INGRESS_ROLE and any(
            expected[role][key] != final[role][key]
            for key in (
                "deployment_id",
                "deployment_observation_sha256",
                "deployment_versions",
            )
        ):
            raise ServiceActivationError("private authority deployment drift")
    ingress = expected[activated.INGRESS_ROLE]
    promotion = _mapping(promotion, "ingress promotion")
    if any(
        ingress[key] != promotion[f"pre_promotion_{key}"]
        for key in (
            "deployment_id",
            "deployment_observation_sha256",
            "deployment_observation_record_id",
            "deployment_observation_record_sha256",
            "deployment_versions",
        )
    ):
        raise ServiceActivationError("A0 ingress staging observation mismatch")


def _epoch(value: Any) -> None:
    epoch = _mapping(value, "promotion epoch")
    _keys(epoch, {"started_at", "completed_at", "maximum_seconds"}, "promotion epoch")
    started = contract.timestamp(epoch["started_at"], "promotion started_at")
    completed = contract.timestamp(epoch["completed_at"], "promotion completed_at")
    if (
        epoch["maximum_seconds"] != MAX_PROMOTION_EPOCH_SECONDS
        or completed < started
        or (completed - started).total_seconds() > MAX_PROMOTION_EPOCH_SECONDS
    ):
        raise ServiceActivationError("promotion epoch is incomplete or unbounded")


def _observation_window(
    value: Any,
    expected_observations: int,
    authorities: Mapping[str, Mapping[str, Any]],
) -> tuple[Any, Any]:
    window = _mapping(value, "provider observation window")
    _keys(
        window,
        {
            "started_at",
            "completed_at",
            "maximum_seconds",
            "provider_observation_count",
            "observer_authority_role",
            "observer_service_identity",
            "observer_worker_version_id",
            "provider_api_version",
        },
        "provider observation window",
    )
    started = contract.timestamp(
        window["started_at"], "provider observation started_at"
    )
    completed = contract.timestamp(
        window["completed_at"], "provider observation completed_at"
    )
    observer = authorities[DEPLOYMENT_OBSERVER_ROLE]
    if (
        window["maximum_seconds"] != MAX_PROVIDER_OBSERVATION_SECONDS
        or window["provider_observation_count"] != expected_observations
        or completed < started
        or (completed - started).total_seconds() > MAX_PROVIDER_OBSERVATION_SECONDS
        or window["observer_authority_role"] != DEPLOYMENT_OBSERVER_ROLE
        or window["observer_service_identity"] != observer["service_identity"]
        or window["observer_worker_version_id"] != observer["worker_version_id"]
        or window["provider_api_version"] != PROVIDER_API_VERSION
    ):
        raise ServiceActivationError("provider observation window is incomplete")
    return started, completed


def _record_pointer(value: Any, name: str) -> Mapping[str, Any]:
    pointer = _mapping(value, name)
    _keys(pointer, {"record_id", "record_sha256"}, name)
    _digest(pointer["record_id"], f"{name}.record_id")
    _digest(pointer["record_sha256"], f"{name}.record_sha256")
    return pointer


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


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()
