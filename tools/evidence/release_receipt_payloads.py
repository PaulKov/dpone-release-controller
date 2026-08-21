"""Single closed dispatch table for all receipt-v2 payload variants."""

from __future__ import annotations

from typing import Any, Callable, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_payload_admission as admission
from tools.evidence import release_receipt_payload_bundle as bundle
from tools.evidence import release_receipt_payload_gate as gate
from tools.evidence import release_receipt_payload_publish as publish
from tools.evidence import release_receipt_payload_recovery as recovery
from tools.evidence import release_receipt_payload_state_contract as state_contract

Validator = Callable[[Mapping[str, Any]], contract.PayloadSemantics]

_VALIDATORS: Mapping[str, Validator] = {
    "REQUEST_ENQUEUED": admission.validate_request,
    "GOVERNANCE_SNAPSHOT": admission.validate_governance,
    "CANDIDATE_HANDOFF": admission.validate_candidate,
    "LEASE_ACQUIRED": admission.validate_lease,
    "LEASE_RENEWED": admission.validate_lease,
    "LEASE_RELEASED": admission.validate_lease,
    "LEASE_EXPIRED": admission.validate_lease,
    "TENANT_HYGIENE_VERIFIED": admission.validate_hygiene,
    "MUTATION_INTENT": bundle.validate_intent,
    "MUTATION_INTENT_CONSUMED": bundle.validate_consumed,
    "ATTESTATION_VERIFIED": bundle.validate_attestation,
    "PUBLIC_BUNDLE_VERIFIED": bundle.validate_public_bundle,
    "DRAFT_TRANSITION": bundle.validate_draft,
    "AUTHORIZED": bundle.validate_authorized,
    "PYPI_FILE_TRANSITION": publish.validate_pypi,
    "PYPI_UPLOAD_SET_OBSERVED": publish.validate_upload_set,
    "PYPI_GATE_REQUESTED": gate.validate,
    "PYPI_GATE_APPROVED": gate.validate,
    "PYPI_GATE_REJECTED": gate.validate,
    "PYPI_GATE_CALLBACK_AMBIGUOUS": gate.validate,
    "PYPI_GATE_RECONCILED": gate.validate,
    "GITHUB_RELEASE_TRANSITION": publish.validate_github,
    "CANCELLATION": recovery.validate_cancellation,
    "RECOVERY_OBSERVATION": recovery.validate_recovery,
    "RECOVERY_RESUMED": recovery.validate_resumed,
    "RECOVERY_CLOSED_EXACT": recovery.validate_closed_exact,
    "INCIDENT_HOLD": recovery.validate_hold,
    "INCIDENT_HOLD_RELEASED": recovery.validate_hold_released,
    "CLOSED": recovery.validate_closed,
}

if frozenset(_VALIDATORS) != contract.PAYLOAD_KINDS:
    raise RuntimeError("receipt payload dispatch table is incomplete")


def validate(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Validate one exact payload and return its envelope constraints."""

    kind = contract.enum(payload.get("kind"), contract.PAYLOAD_KINDS, "payload.kind")
    if kind != "CLOSED" and (
        payload.get("status") == "PASS" or payload.get("decision") == "GO"
    ):
        raise contract.ReceiptValidationError(
            "PASS/GO vocabulary is reserved for CLOSED"
        )
    semantics = _VALIDATORS[kind](payload)
    state_contract.require(payload)
    return semantics
