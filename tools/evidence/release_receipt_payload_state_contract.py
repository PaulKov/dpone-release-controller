"""Exact selector-to-state union shared by payload validators and routes."""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract

_SINGLE = {
    "ATTESTATION_VERIFIED": "ATTESTED",
    "AUTHORIZED": "AUTHORIZED",
    "CANDIDATE_HANDOFF": "CANDIDATE_HANDOFF",
    "CLOSED": "CLOSED",
    "INCIDENT_HOLD": "INCIDENT_HOLD",
    "INCIDENT_HOLD_RELEASED": "RECOVERY_REQUIRED",
    "LEASE_EXPIRED": "LEASE_EXPIRED",
    "LEASE_RENEWED": "LEASE_RENEWED",
    "PUBLIC_BUNDLE_VERIFIED": "PUBLIC_BUNDLE_VERIFIED",
    "PYPI_GATE_APPROVED": "PYPI_GATE_APPROVED",
    "PYPI_GATE_CALLBACK_AMBIGUOUS": "PYPI_GATE_RECONCILIATION_REQUIRED",
    "PYPI_GATE_REJECTED": "PYPI_GATE_REJECTED",
    "PYPI_GATE_REQUESTED": "PYPI_GATE_PENDING",
    "RECOVERY_CLOSED_EXACT": "RECOVERY_CLOSED_EXACT",
    "RECOVERY_OBSERVATION": "RECOVERY_RECONCILED",
    "RECOVERY_RESUMED": "RECOVERY_RESUMED",
    "REQUEST_ENQUEUED": "QUEUED",
    "TENANT_HYGIENE_VERIFIED": "TENANT_HYGIENE_VERIFIED",
}

STATES_BY_SELECTOR: dict[str, tuple[str, ...]] = {
    selector: (state,) for selector, state in _SINGLE.items()
}
STATES_BY_SELECTOR.update(
    {
        "LEASE_ACQUIRED:PRIMARY": ("LEASE_ACQUIRED",),
        "LEASE_ACQUIRED:RECOVERY": ("LEASE_ACQUIRED",),
        "LEASE_RELEASED:ABANDONED": ("LEASE_RELEASED",),
        "LEASE_RELEASED:CANCELLED": ("LEASE_RELEASED",),
        "LEASE_RELEASED:RECOVERY_REQUIRED": ("LEASE_RELEASED",),
        **{f"GOVERNANCE_SNAPSHOT:{label}": (f"GOVERNANCE_{label}",) for label in "ABC"},
        **{
            f"MUTATION_INTENT:{operation}": ("MUTATION_INTENT_RECORDED",)
            for operation in (
                "ATTESTATION_CREATE",
                "GITHUB_DRAFT_ASSET_UPLOAD",
                "GITHUB_DRAFT_CREATE",
                "GITHUB_DRAFT_UPDATE",
                "GITHUB_RELEASE_PUBLISH",
                "PYPI_DEPLOYMENT_APPROVE",
                "PYPI_DEPLOYMENT_REJECT",
                "PYPI_FILE_UPLOAD_SET",
            )
        },
        **{
            f"MUTATION_INTENT_CONSUMED:{operation}": ("MUTATION_INTENT_CONSUMED",)
            for operation in (
                "ATTESTATION_CREATE",
                "GITHUB_DRAFT_ASSET_UPLOAD",
                "GITHUB_DRAFT_CREATE",
                "GITHUB_DRAFT_UPDATE",
                "GITHUB_RELEASE_PUBLISH",
                "PYPI_DEPLOYMENT_APPROVE",
                "PYPI_DEPLOYMENT_REJECT",
                "PYPI_FILE_UPLOAD_SET",
            )
        },
        "CANCELLATION": ("CANCELLED", "RECOVERY_REQUIRED"),
        "DRAFT_TRANSITION:ASSET_UPLOADED": ("DRAFT_STAGING",),
        "DRAFT_TRANSITION:CREATED": ("DRAFT_CREATED",),
        "DRAFT_TRANSITION:STAGED": ("DRAFT_STAGED",),
        "DRAFT_TRANSITION:VERIFIED": ("DRAFT_VERIFIED",),
        "GITHUB_RELEASE_TRANSITION:IMMUTABLE_VERIFIED": ("GITHUB_IMMUTABLE_PUBLISHED",),
        "GITHUB_RELEASE_TRANSITION:PUBLISH_ACCEPTED": ("GITHUB_RELEASE_PUBLISHING",),
        "PYPI_FILE_TRANSITION:ALREADY_PUBLISHED_EXACT": (
            "PYPI_PARTIAL_EXACT",
            "PYPI_VERIFIED",
        ),
        "PYPI_FILE_TRANSITION:CONFLICT": ("PYPI_CONFLICT",),
        "PYPI_FILE_TRANSITION:INTEGRITY_VERIFIED": (
            "PYPI_PARTIAL_EXACT",
            "PYPI_VERIFIED",
        ),
        "PYPI_FILE_TRANSITION:PENDING_UPLOAD": ("PYPI_PUBLISHING",),
        "PYPI_FILE_TRANSITION:SEALED_FOR_UPLOAD": ("PYPI_PUBLISHING",),
        "PYPI_GATE_RECONCILED": (
            "PYPI_GATE_PENDING",
            "PYPI_GATE_APPROVED",
            "PYPI_GATE_REJECTED",
        ),
        "PYPI_UPLOAD_SET_OBSERVED": (
            "PYPI_UPLOAD_SET_COMPLETE",
            "RECOVERY_REQUIRED",
        ),
    }
)


def selector_for(payload: Mapping[str, Any]) -> str:
    """Return the exact state-contract discriminator for one receipt payload."""

    kind = payload["kind"]
    if kind == "LEASE_ACQUIRED":
        return (
            "LEASE_ACQUIRED:RECOVERY"
            if payload["recovery_acquisition"]
            else "LEASE_ACQUIRED:PRIMARY"
        )
    if kind == "LEASE_RELEASED":
        return f"LEASE_RELEASED:{payload['reason']}"
    branch = {
        "DRAFT_TRANSITION": "transition",
        "GITHUB_RELEASE_TRANSITION": "transition",
        "GOVERNANCE_SNAPSHOT": "label",
        "MUTATION_INTENT": "operation",
        "MUTATION_INTENT_CONSUMED": "operation",
        "PYPI_FILE_TRANSITION": "transition",
    }.get(kind)
    return kind if branch is None else f"{kind}:{payload[branch]}"


def require(payload: Mapping[str, Any]) -> None:
    """Reject any validator result outside its exact selector state union."""

    selector = selector_for(payload)
    states = STATES_BY_SELECTOR.get(selector)
    if states is None or payload.get("state") not in states:
        raise contract.ReceiptValidationError(
            "payload selector/state contract mismatch"
        )
