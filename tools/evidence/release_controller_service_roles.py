"""Closed receipt-selector to trusted internal service-role ownership."""

from __future__ import annotations

_EXACT = {
    "ATTESTATION_VERIFIED": "attestation_reader",
    "CANCELLATION": "cancellation_observer",
    "GITHUB_RELEASE_TRANSITION:IMMUTABLE_VERIFIED": "github_governance_reader",
    "GITHUB_RELEASE_TRANSITION:PUBLISH_ACCEPTED": "github_release_mutator",
    "INCIDENT_HOLD": "ledger_orchestrator",
    "LEASE_RELEASED:ABANDONED": "lease_orchestrator",
    "LEASE_RELEASED:CANCELLED": "ledger_orchestrator",
    "LEASE_RELEASED:RECOVERY_REQUIRED": "ledger_orchestrator",
    "PYPI_UPLOAD_SET_OBSERVED": "pypi_reader",
    "RECOVERY_CLOSED_EXACT": "ledger_orchestrator",
    "RECOVERY_OBSERVATION": "recovery_observer",
    "RECOVERY_RESUMED": "ledger_orchestrator",
    "TENANT_HYGIENE_VERIFIED": "tenant_scanner",
    "MUTATION_INTENT:ATTESTATION_CREATE": "ledger_orchestrator",
    "MUTATION_INTENT:GITHUB_RELEASE_PUBLISH": "ledger_orchestrator",
    "MUTATION_INTENT_CONSUMED:ATTESTATION_CREATE": "attestation_mutator",
    "MUTATION_INTENT_CONSUMED:GITHUB_RELEASE_PUBLISH": "github_release_mutator",
}

SERVICE_ROLES = frozenset(
    {
        "attestation_mutator",
        "attestation_reader",
        "cancellation_observer",
        "closed_check_mutator",
        "controller_run_reader",
        "draft_ledger_orchestrator",
        "github_draft_mutator",
        "github_governance_reader",
        "github_release_mutator",
        "lease_orchestrator",
        "ledger_orchestrator",
        "pypi_deployment_gate",
        "pypi_reader",
        "recovery_observer",
        "tenant_scanner",
    }
)

AUTHORITY_ROLE_BY_SERVICE_ROLE = {
    "attestation_mutator": "attestation_mutator",
    "attestation_reader": "governance_reader",
    "cancellation_observer": "release_authority_ingress",
    "closed_check_mutator": "closed_projector",
    "controller_run_reader": "controller_run_reader",
    "draft_ledger_orchestrator": "release_authority_ingress",
    "github_draft_mutator": "release_mutator",
    "github_governance_reader": "governance_reader",
    "github_release_mutator": "release_mutator",
    "lease_orchestrator": "release_authority_ingress",
    "ledger_orchestrator": "release_authority_ingress",
    "pypi_deployment_gate": "pypi_deployment_gate",
    "pypi_reader": "pypi_reader",
    "recovery_observer": "release_authority_ingress",
    "tenant_scanner": "tenant_scanner",
}

if set(AUTHORITY_ROLE_BY_SERVICE_ROLE) != SERVICE_ROLES:
    raise RuntimeError("logical service roles lack an activated authority mapping")


def role_for_selector(selector: str) -> str:
    """Return the only service role allowed to produce ``selector``."""

    if selector in _EXACT:
        return _EXACT[selector]
    if selector.startswith("GOVERNANCE_SNAPSHOT:"):
        return "github_governance_reader"
    if selector.startswith("DRAFT_TRANSITION:"):
        return "github_governance_reader"
    if selector.startswith("MUTATION_INTENT:GITHUB_DRAFT_"):
        return "draft_ledger_orchestrator"
    if selector.startswith("MUTATION_INTENT_CONSUMED:GITHUB_DRAFT_"):
        return "github_draft_mutator"
    if selector.startswith("PYPI_FILE_TRANSITION:") and not selector.endswith(
        ("PENDING_UPLOAD", "SEALED_FOR_UPLOAD")
    ):
        return "pypi_reader"
    if (
        selector.startswith("PYPI_GATE_")
        or selector.startswith("MUTATION_INTENT:PYPI_DEPLOYMENT_")
        or selector.startswith("MUTATION_INTENT_CONSUMED:PYPI_DEPLOYMENT_")
    ):
        return "pypi_deployment_gate"
    raise KeyError(selector)
