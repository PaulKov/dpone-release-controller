"""Closed deployment-protection gate receipts for the PyPI environment."""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_consumption as consumption

KINDS = frozenset(
    {
        "PYPI_GATE_REQUESTED",
        "PYPI_GATE_APPROVED",
        "PYPI_GATE_REJECTED",
        "PYPI_GATE_CALLBACK_AMBIGUOUS",
        "PYPI_GATE_RECONCILED",
    }
)
_GATE_SERVICE = frozenset({"trusted_controller_service"})
_COMMON_KEYS = {
    "kind",
    "state",
    "authorization_id",
    "candidate_id",
    "gate_request_id",
    "lease_id",
    "fencing_token",
    "tag",
    "environment_name",
    "environment_id",
    "protection_rule_id",
    "deployment_id",
    "gate_app_id",
    "gate_installation_id",
    "app_slug",
    "controller_repository_id",
    "controller_workflow_id",
    "controller_workflow_sha",
    "controller_run_id",
    "controller_run_attempt",
    "ref",
    "provider_observation_sha256",
    "expected_file_count",
    "expected_file_inventory_sha256",
}


def validate(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Validate one gate event and return its fixed envelope authority."""

    kind = contract.enum(payload.get("kind"), KINDS, "kind")
    validators = {
        "PYPI_GATE_REQUESTED": _requested,
        "PYPI_GATE_APPROVED": _approved,
        "PYPI_GATE_REJECTED": _rejected,
        "PYPI_GATE_CALLBACK_AMBIGUOUS": _ambiguous,
        "PYPI_GATE_RECONCILED": _reconciled,
    }
    validators[kind](payload)
    return contract.PayloadSemantics("authorization", True, _GATE_SERVICE)


def _common(payload: Mapping[str, Any]) -> None:
    contract.digest_fields(
        payload,
        "authorization_id",
        "candidate_id",
        "gate_request_id",
        "lease_id",
        "provider_observation_sha256",
        "expected_file_inventory_sha256",
    )
    if "gate_request_provider_observation_sha256" in payload:
        contract.digest(
            payload["gate_request_provider_observation_sha256"],
            "gate_request_provider_observation_sha256",
        )
    contract.positive_fields(
        payload,
        "fencing_token",
        "environment_id",
        "protection_rule_id",
        "deployment_id",
        "gate_app_id",
        "gate_installation_id",
        "controller_repository_id",
        "controller_workflow_id",
        "controller_run_id",
        "controller_run_attempt",
    )
    if payload["controller_repository_id"] != contract.CONTROLLER_REPOSITORY_ID:
        raise contract.ReceiptValidationError("gate repository ID mismatch")
    if (
        payload["expected_file_count"] != 8
        or type(payload["expected_file_count"]) is not int
    ):
        raise contract.ReceiptValidationError("gate expected_file_count must be 8")
    if payload["environment_name"] != "pypi":
        raise contract.ReceiptValidationError("gate environment mismatch")
    if payload["app_slug"] != "dpone-release-controller-pypi-gate":
        raise contract.ReceiptValidationError("gate app slug mismatch")
    if not payload["ref"].startswith("refs/tags/"):
        raise contract.ReceiptValidationError("gate ref must be an immutable tag")
    contract.stable_tag(payload["ref"].removeprefix("refs/tags/"))
    contract.stable_tag(payload["tag"])
    if payload["ref"] != f"refs/tags/{payload['tag']}":
        raise contract.ReceiptValidationError("gate tag/ref mismatch")
    contract.git_sha(payload["controller_workflow_sha"], "controller_workflow_sha")


def _requested(payload: Mapping[str, Any]) -> None:
    extras = {
        "action",
        "webhook_delivery_id",
        "webhook_payload_sha256",
        "requested_at",
    }
    contract.exact_keys(payload, _COMMON_KEYS | extras, "PYPI_GATE_REQUESTED")
    _constants(
        payload,
        kind="PYPI_GATE_REQUESTED",
        state="PYPI_GATE_PENDING",
        action="requested",
    )
    _common(payload)
    contract.opaque(payload["webhook_delivery_id"], "webhook_delivery_id")
    contract.digest(payload["webhook_payload_sha256"], "webhook_payload_sha256")
    contract.timestamp(payload["requested_at"], "requested_at")


def _approved(payload: Mapping[str, Any]) -> None:
    extras = {
        "gate_request_provider_observation_sha256",
        "callback_request_sha256",
        "callback_response_sha256",
        "callback_http_status",
        "approved_at",
        "intent_state",
        *consumption.OUTCOME_KEYS,
    }
    contract.exact_keys(payload, _COMMON_KEYS | extras, "PYPI_GATE_APPROVED")
    _constants(
        payload,
        kind="PYPI_GATE_APPROVED",
        state="PYPI_GATE_APPROVED",
        callback_http_status=204,
        intent_state="CONSUMED",
    )
    _common(payload)
    contract.digest_fields(
        payload, "callback_request_sha256", "callback_response_sha256"
    )
    consumption.validate_outcome(payload)
    contract.timestamp(payload["approved_at"], "approved_at")


def _rejected(payload: Mapping[str, Any]) -> None:
    extras = {
        "gate_request_provider_observation_sha256",
        "reason_code",
        "callback_request_sha256",
        "callback_response_sha256",
        "callback_http_status",
        "rejected_at",
        "intent_state",
        *consumption.OUTCOME_KEYS,
    }
    contract.exact_keys(payload, _COMMON_KEYS | extras, "PYPI_GATE_REJECTED")
    _constants(
        payload,
        kind="PYPI_GATE_REJECTED",
        state="PYPI_GATE_REJECTED",
        callback_http_status=204,
        intent_state="CONSUMED",
    )
    _common(payload)
    contract.enum(
        payload["reason_code"],
        {
            "ACTIVATION_MISMATCH",
            "FENCE_LOST",
            "INTENT_INVALID",
            "LEASE_EXPIRED",
            "PROVIDER_MISMATCH",
        },
        "reason_code",
    )
    contract.digest_fields(
        payload, "callback_request_sha256", "callback_response_sha256"
    )
    consumption.validate_outcome(payload)
    contract.timestamp(payload["rejected_at"], "rejected_at")


def _ambiguous(payload: Mapping[str, Any]) -> None:
    extras = {
        "gate_request_provider_observation_sha256",
        "attempted_decision",
        "callback_request_sha256",
        "transport_evidence_sha256",
        "ambiguity_observed_at",
        "intent_state",
        "resolution_required",
        *consumption.OUTCOME_KEYS,
    }
    contract.exact_keys(payload, _COMMON_KEYS | extras, "PYPI_GATE_CALLBACK_AMBIGUOUS")
    _constants(
        payload,
        kind="PYPI_GATE_CALLBACK_AMBIGUOUS",
        state="PYPI_GATE_RECONCILIATION_REQUIRED",
        intent_state="CONSUMED",
        resolution_required=True,
    )
    _common(payload)
    contract.enum(
        payload["attempted_decision"], {"APPROVE", "REJECT"}, "attempted_decision"
    )
    consumption.validate_outcome(payload)
    contract.digest_fields(
        payload, "callback_request_sha256", "transport_evidence_sha256"
    )
    contract.timestamp(payload["ambiguity_observed_at"], "ambiguity_observed_at")


def _reconciled(payload: Mapping[str, Any]) -> None:
    extras = {
        "gate_request_provider_observation_sha256",
        "attempted_decision",
        "resolution",
        "original_ambiguity_receipt_id",
        "provider_query_sha256",
        "provider_response_sha256",
        "reconciled_at",
        "same_callback_retry_permitted",
        "new_publish_authority_issued",
        "new_decision_intent_required",
    }
    contract.exact_keys(payload, _COMMON_KEYS | extras, "PYPI_GATE_RECONCILED")
    _constants(
        payload,
        kind="PYPI_GATE_RECONCILED",
        new_publish_authority_issued=False,
    )
    _common(payload)
    decision = contract.enum(
        payload["attempted_decision"], {"APPROVE", "REJECT"}, "attempted_decision"
    )
    resolution = contract.enum(
        payload["resolution"],
        {"APPROVED_CONFIRMED", "REJECTED_CONFIRMED", "STILL_PENDING"},
        "resolution",
    )
    expected_state = {
        "APPROVED_CONFIRMED": "PYPI_GATE_APPROVED",
        "REJECTED_CONFIRMED": "PYPI_GATE_REJECTED",
        "STILL_PENDING": "PYPI_GATE_PENDING",
    }[resolution]
    if payload["state"] != expected_state:
        raise contract.ReceiptValidationError("reconciled gate state mismatch")
    if resolution.startswith("APPROVED") and decision != "APPROVE":
        raise contract.ReceiptValidationError("gate resolution/decision mismatch")
    if resolution.startswith("REJECTED") and decision != "REJECT":
        raise contract.ReceiptValidationError("gate resolution/decision mismatch")
    retry = contract.boolean(
        payload["same_callback_retry_permitted"], "same_callback_retry_permitted"
    )
    if retry is not False:
        raise contract.ReceiptValidationError("gate callback retry policy mismatch")
    new_intent = contract.boolean(
        payload["new_decision_intent_required"], "new_decision_intent_required"
    )
    if new_intent is not (resolution == "STILL_PENDING"):
        raise contract.ReceiptValidationError("gate decision intent policy mismatch")
    contract.digest_fields(
        payload,
        "original_ambiguity_receipt_id",
        "provider_query_sha256",
        "provider_response_sha256",
        "gate_request_provider_observation_sha256",
    )
    contract.timestamp(payload["reconciled_at"], "reconciled_at")


def _constants(payload: Mapping[str, Any], **expected: Any) -> None:
    for key, value in expected.items():
        if payload[key] != value or type(payload[key]) is not type(value):
            raise contract.ReceiptValidationError(f"{key} must be exactly {value!r}")
