"""Discriminated trusted-service producer variants for receipt v2."""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_service_common as common
from tools.evidence import release_receipt_service_observers as observers
from tools.evidence import release_receipt_payload_state_contract as state_contract
from tools.evidence.release_controller_service_roles import role_for_selector


def validate(producer: Mapping[str, Any], payload: Mapping[str, Any]) -> None:
    """Validate the exact service role and selector-specific evidence binding."""

    role = trusted_service_role(payload)
    if producer.get("service_role") != role:
        raise contract.ReceiptValidationError("service role/payload mismatch")
    validators = {
        "attestation_mutator": _provider_mutator,
        "attestation_reader": observers.validate_github_reader,
        "cancellation_observer": observers.validate_composite_observer,
        "draft_ledger_orchestrator": _draft_orchestrator,
        "github_draft_mutator": _draft_mutator,
        "github_governance_reader": observers.validate_github_reader,
        "github_release_mutator": _provider_mutator,
        "lease_orchestrator": _lease_orchestrator,
        "ledger_orchestrator": _ledger_orchestrator,
        "pypi_deployment_gate": _deployment_gate,
        "pypi_reader": observers.validate_pypi_reader,
        "recovery_observer": observers.validate_composite_observer,
        "tenant_scanner": observers.validate_tenant_scanner,
    }
    validators[role](producer, payload)


_MUTATOR_OPERATION = {
    "attestation_mutator": "ATTESTATION_CREATE",
    "github_release_mutator": "GITHUB_RELEASE_PUBLISH",
}


def _provider_mutator(producer: Mapping[str, Any], payload: Mapping[str, Any]) -> None:
    """Bind private consume/effect outcomes to one permission-scoped adapter."""

    expected_operation = _MUTATOR_OPERATION[producer.get("service_role")]
    common_fields = {
        "github_app_id",
        "installation_id",
        "operation",
        "intent_id",
        "intent_subject_sha256",
        "authority_guard_sha256",
        "authority_guard_accepted_at",
        "authority_guard_expires_at",
        "capability_binding_sha256",
    }
    if payload["kind"] == "MUTATION_INTENT_CONSUMED":
        common.exact_service_keys(
            producer,
            {*common_fields, "capability_sha256"},
            "provider mutator consumption producer",
        )
        if producer["capability_sha256"] != payload["capability_sha256"]:
            raise contract.ReceiptValidationError(
                "provider mutator capability mismatch"
            )
        contract.digest(producer["capability_sha256"], "producer.capability_sha256")
    else:
        common.exact_service_keys(
            producer,
            {
                *common_fields,
                "provider_response_sha256",
                "provider_api_version",
                "intent_consumption_receipt_id",
                "intent_consumption_receipt_sha256",
            },
            "provider mutator outcome producer",
        )
        if (
            payload["kind"] != "GITHUB_RELEASE_TRANSITION"
            or producer["provider_response_sha256"]
            != payload["provider_response_sha256"]
            or producer["provider_api_version"] != contract.GITHUB_API_VERSION
            or producer["intent_consumption_receipt_id"]
            != payload["intent_consumption_receipt_id"]
            or producer["intent_consumption_receipt_sha256"]
            != payload["intent_consumption_receipt_sha256"]
        ):
            raise contract.ReceiptValidationError(
                "provider mutator intent receipt/outcome binding mismatch"
            )
        contract.digest(
            producer["provider_response_sha256"],
            "producer.provider_response_sha256",
        )
        contract.digest_fields(
            producer,
            "intent_consumption_receipt_id",
            "intent_consumption_receipt_sha256",
        )
    if (
        producer["operation"] != expected_operation
        or producer["intent_id"] != payload["intent_id"]
        or producer["intent_subject_sha256"] != payload["intent_subject_sha256"]
    ):
        raise contract.ReceiptValidationError("provider mutator intent mismatch")
    common.validate_service_common(producer)
    common.validate_authority_guard_projection(producer, payload)
    contract.positive_fields(producer, "github_app_id", "installation_id")
    contract.digest_fields(producer, "intent_id", "intent_subject_sha256")


def trusted_service_role(payload: Mapping[str, Any]) -> str:
    """Return the sole internal role for one service-produced payload."""

    try:
        return role_for_selector(state_contract.selector_for(payload))
    except KeyError as exc:
        raise contract.ReceiptValidationError(
            "payload has no trusted service role"
        ) from exc


def _draft_orchestrator(
    producer: Mapping[str, Any], payload: Mapping[str, Any]
) -> None:
    common.exact_service_keys(
        producer,
        {
            "operation",
            "subject_identity_sha256",
        },
        "draft ledger orchestrator producer",
    )
    if (
        payload["kind"] != "MUTATION_INTENT"
        or producer["operation"] != payload["operation"]
        or producer["subject_identity_sha256"] != payload["subject_identity_sha256"]
    ):
        raise contract.ReceiptValidationError("draft orchestrator binding mismatch")
    common.validate_service_common(producer)
    contract.digest(producer["subject_identity_sha256"], "subject_identity_sha256")


def _draft_mutator(producer: Mapping[str, Any], payload: Mapping[str, Any]) -> None:
    common.exact_service_keys(
        producer,
        {
            "github_app_id",
            "installation_id",
            "operation",
            "intent_id",
            "intent_subject_sha256",
            "capability_sha256",
            "authority_guard_sha256",
            "authority_guard_accepted_at",
            "authority_guard_expires_at",
            "capability_binding_sha256",
        },
        "GitHub draft mutator producer",
    )
    if (
        payload["kind"] != "MUTATION_INTENT_CONSUMED"
        or producer["operation"] != payload["operation"]
        or producer["intent_id"] != payload["intent_id"]
        or producer["intent_subject_sha256"] != payload["intent_subject_sha256"]
        or producer["capability_sha256"] != payload["capability_sha256"]
    ):
        raise contract.ReceiptValidationError(
            "draft mutator/capability binding mismatch"
        )
    common.validate_service_common(producer)
    common.validate_authority_guard_projection(producer, payload)
    contract.positive_fields(producer, "github_app_id", "installation_id")
    contract.digest_fields(
        producer, "intent_id", "intent_subject_sha256", "capability_sha256"
    )


def _ledger_orchestrator(
    producer: Mapping[str, Any], payload: Mapping[str, Any]
) -> None:
    common.exact_service_keys(
        producer,
        {
            "selector",
            "authority_evidence_sha256",
        },
        "ledger orchestrator producer",
    )
    selector = state_contract.selector_for(payload)
    if producer["selector"] != selector or producer[
        "authority_evidence_sha256"
    ] != common.ledger_evidence(payload):
        raise contract.ReceiptValidationError("ledger orchestrator binding mismatch")
    common.validate_service_common(producer)
    contract.digest(producer["authority_evidence_sha256"], "authority_evidence_sha256")


def _deployment_gate(producer: Mapping[str, Any], payload: Mapping[str, Any]) -> None:
    guard_fields = (
        {
            "authority_guard_sha256",
            "authority_guard_accepted_at",
            "authority_guard_expires_at",
            "capability_binding_sha256",
        }
        if payload["kind"] == "MUTATION_INTENT_CONSUMED"
        else set()
    )
    common.exact_service_keys(
        producer,
        {
            "github_app_id",
            "installation_id",
            "workload_identity",
            "provider_observation_sha256",
            "provider_api_version",
            *guard_fields,
        },
        "PyPI deployment gate producer",
    )
    payload_kind = payload["kind"]
    if payload_kind in {"MUTATION_INTENT", "MUTATION_INTENT_CONSUMED"} and not payload[
        "operation"
    ].startswith("PYPI_DEPLOYMENT_"):
        raise contract.ReceiptValidationError("gate service intent operation mismatch")
    if payload_kind.startswith("PYPI_GATE_") and (
        producer["github_app_id"] != payload["gate_app_id"]
        or producer["installation_id"] != payload["gate_installation_id"]
    ):
        raise contract.ReceiptValidationError("gate producer/App identity mismatch")
    common.validate_service_common(producer)
    if guard_fields:
        common.validate_authority_guard_projection(producer, payload)
    contract.opaque(producer["workload_identity"], "producer.workload_identity")
    contract.digest(producer["provider_observation_sha256"], "provider observation")
    if producer["provider_api_version"] != contract.GITHUB_API_VERSION:
        raise contract.ReceiptValidationError("gate provider API version mismatch")
    contract.positive_fields(producer, "github_app_id", "installation_id")


def _lease_orchestrator(
    producer: Mapping[str, Any], payload: Mapping[str, Any]
) -> None:
    common.exact_service_keys(
        producer,
        {
            "lease_id",
            "fencing_token",
            "reason",
        },
        "lease orchestrator producer",
    )
    if (
        payload["kind"] != "LEASE_RELEASED"
        or payload["reason"] != "ABANDONED"
        or producer["lease_id"] != payload["lease_id"]
        or producer["fencing_token"] != payload["fencing_token"]
        or producer["reason"] != payload["reason"]
    ):
        raise contract.ReceiptValidationError("lease orchestrator binding mismatch")
    common.validate_service_common(producer)
    contract.digest(producer["lease_id"], "producer.lease_id")
    contract.positive_int(producer["fencing_token"], "producer.fencing_token")
