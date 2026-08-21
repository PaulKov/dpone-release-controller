"""Shared closed-field validation for trusted receipt-service producers."""

from __future__ import annotations

from typing import Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence.release_controller_service_roles import (
    AUTHORITY_ROLE_BY_SERVICE_ROLE,
)


def provider_evidence(payload: Mapping[str, object]) -> str:
    """Return the sole provider-derived digest exposed by a payload."""

    for key in (
        "provider_observation_sha256",
        "observation_sha256",
        "provider_receipt_inventory_sha256",
        "provider_response_sha256",
    ):
        if key in payload:
            value = payload[key]
            if isinstance(value, str):
                return value
    raise contract.ReceiptValidationError("provider evidence digest is absent")


def ledger_evidence(payload: Mapping[str, object]) -> str:
    """Return the sole durable-ledger evidence digest exposed by a payload."""

    for key in ("observation_sha256", "incident_record_sha256", "lease_id"):
        if key in payload:
            value = payload[key]
            if isinstance(value, str):
                return value
    raise contract.ReceiptValidationError("ledger authority evidence is absent")


def exact_service_keys(
    producer: Mapping[str, object], extra: set[str], label: str
) -> None:
    """Require the exact common service envelope plus variant-specific keys."""

    contract.exact_keys(
        producer,
        {
            "kind",
            "service_role",
            "service_authority_role",
            "service_identity",
            "service_version_id",
            "deployment_observation_sha256",
            "deployment_observation_record_id",
            "deployment_observation_record_sha256",
            "service_authority_inventory_sha256",
            "activated_authority_head_record_id",
            "activated_authority_head_record_sha256",
            "activated_authority_head_generation",
            "request_id",
            *extra,
        },
        label,
    )


def validate_service_common(producer: Mapping[str, object]) -> None:
    """Validate the static activated-authority projection on one producer."""

    if producer["kind"] != "trusted_controller_service":
        raise contract.ReceiptValidationError("trusted service kind mismatch")
    service_role = producer["service_role"]
    expected_authority = AUTHORITY_ROLE_BY_SERVICE_ROLE.get(service_role)
    if producer["service_authority_role"] != expected_authority:
        raise contract.ReceiptValidationError("service authority role mismatch")
    for key in ("service_authority_role", "service_identity", "service_version_id"):
        contract.opaque(producer[key], f"producer.{key}")
    contract.digest(
        producer["deployment_observation_sha256"],
        "producer.deployment_observation_sha256",
    )
    contract.digest_fields(
        producer,
        "deployment_observation_record_id",
        "deployment_observation_record_sha256",
        "service_authority_inventory_sha256",
        "activated_authority_head_record_id",
        "activated_authority_head_record_sha256",
    )
    if producer["activated_authority_head_generation"] != 1:
        raise contract.ReceiptValidationError(
            "trusted service head generation must be one"
        )
    contract.request_id(producer["request_id"], "producer.request_id")


def validate_authority_guard_projection(
    producer: Mapping[str, object], payload: Mapping[str, object]
) -> None:
    """Require the service producer to repeat the consumed fresh guard."""

    fields = (
        "authority_guard_sha256",
        "authority_guard_accepted_at",
        "authority_guard_expires_at",
        "capability_binding_sha256",
    )
    if any(producer[key] != payload[key] for key in fields):
        raise contract.ReceiptValidationError("producer authority guard mismatch")
    contract.digest_fields(
        producer,
        "authority_guard_sha256",
        "capability_binding_sha256",
    )
    contract.ordered_timestamps(
        producer["authority_guard_accepted_at"],
        producer["authority_guard_expires_at"],
        "producer.authority_guard_accepted_at",
        "producer.authority_guard_expires_at",
    )
