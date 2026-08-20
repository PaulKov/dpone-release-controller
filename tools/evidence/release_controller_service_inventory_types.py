"""Shared immutable types and closed constants for service inventories."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

SCHEMA = "dpone.release-service-authority-inventory.v1"
SCHEMA_VERSION = 1
INGRESS_ROLE = "release_authority_ingress"

AUTHORITY_BINDINGS = {
    "attestation_mutator": "ATTESTATION_MUTATOR",
    "candidate_reader": "CANDIDATE_READER",
    "cloudflare_deployment_observer": "CLOUDFLARE_DEPLOYMENT_OBSERVER",
    "closed_projector": "CLOSED_PROJECTOR",
    "controller_run_reader": "CONTROLLER_RUN_READER",
    "governance_reader": "GOVERNANCE_READER",
    "pypi_deployment_gate": "PYPI_DEPLOYMENT_GATE",
    "pypi_reader": "PYPI_READER",
    INGRESS_ROLE: "INGRESS",
    "release_mutator": "RELEASE_MUTATOR",
    "runtime_deployment_gate": "RUNTIME_DEPLOYMENT_GATE",
    "tenant_scanner": "TENANT_SCANNER",
    "worm_mirror": "WORM_MIRROR",
    "worm_version_observer": "WORM_VERSION_OBSERVER",
}


class ServiceInventoryError(ValueError):
    """The service authority inventory or one producer binding is invalid."""


@dataclass(frozen=True, slots=True)
class CompiledServiceInventory:
    """One fully validated inventory indexed once for a receipt stream."""

    document: Mapping[str, Any]
    indexed: Mapping[str, Mapping[str, Any]]
    sha256: str
