"""Deterministic activated service-authority inventory for receipt tests."""

from __future__ import annotations

import hashlib
import copy
from functools import lru_cache
from typing import Any, Mapping

from tools.evidence import release_controller_service_inventory as inventory_contract
from tools.evidence import release_controller_service_activation as activation_contract
from tools.evidence.release_controller_service_roles import (
    AUTHORITY_ROLE_BY_SERVICE_ROLE,
)

# Deliberately non-routable fixture identity. Checked-in artifacts must never
# carry a copied Cloudflare control-plane account identifier.
ACCOUNT_ID = "0" * 32
SOURCE_COMMIT_SHA = "1" * 40
INGRESS_SERVICE = "dpone-release-authority-broker"
INGRESS_FINAL_VERSION = "00000000-0000-4000-8000-000000000001"
INGRESS_BOOTSTRAP_VERSION = "00000000-0000-4000-8000-000000000002"

_SERVICE_NAMES = {
    "attestation_mutator": "dpone-release-attestation-mutator",
    "candidate_reader": "dpone-release-candidate-reader",
    "cloudflare_deployment_observer": ("dpone-release-cloudflare-deployment-observer"),
    "closed_projector": "dpone-release-closed-projector",
    "controller_run_reader": "dpone-release-controller-run-reader",
    "governance_reader": "dpone-release-governance-reader",
    "pypi_deployment_gate": "dpone-release-pypi-deployment-gate",
    "pypi_reader": "dpone-release-pypi-reader",
    "release_authority_ingress": INGRESS_SERVICE,
    "release_mutator": "dpone-release-mutator",
    "runtime_deployment_gate": "dpone-release-runtime-deployment-gate",
    "tenant_scanner": "dpone-release-tenant-scanner",
    "worm_mirror": "dpone-release-worm-mirror",
    "worm_version_observer": "dpone-release-worm-version-observer",
}


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def cloudflare_uuid(label: str) -> str:
    """Return a deterministic provider ID in the synthetic fixture namespace."""

    suffix = hashlib.sha256(label.encode()).hexdigest()[:12]
    return f"00000000-0000-4000-8000-{suffix}"


def authority_inventory() -> dict[str, Any]:
    """Return a new validated inventory document for adversarial mutation."""

    return copy.deepcopy(_authority_inventory())


@lru_cache(maxsize=1)
def _authority_inventory() -> dict[str, Any]:
    """Build the immutable fixture source once per test process."""

    authorities = [
        _authority(role) for role in sorted(inventory_contract.AUTHORITY_BINDINGS)
    ]
    pre = _versions({INGRESS_BOOTSTRAP_VERSION: 100, INGRESS_FINAL_VERSION: 0})
    post = _versions({INGRESS_FINAL_VERSION: 100})
    return inventory_contract.document(
        account_id=ACCOUNT_ID,
        authorities=authorities,
        ingress_promotion={
            "pre_promotion_deployment_id": cloudflare_uuid("ingress deployment pre"),
            "pre_promotion_deployment_observation_sha256": digest(
                "ingress pre promotion observation"
            ),
            "pre_promotion_deployment_observation_record_id": digest(
                "ingress pre promotion observation WORM record id"
            ),
            "pre_promotion_deployment_observation_record_sha256": digest(
                "ingress pre promotion observation WORM record bytes"
            ),
            "pre_promotion_deployment_versions": pre,
            "post_promotion_deployment_id": cloudflare_uuid("ingress deployment post"),
            "post_promotion_deployment_observation_sha256": digest(
                "ingress post promotion observation"
            ),
            "post_promotion_deployment_observation_record_id": digest(
                "ingress post promotion observation WORM record id"
            ),
            "post_promotion_deployment_observation_record_sha256": digest(
                "ingress post promotion observation WORM record bytes"
            ),
            "post_promotion_deployment_versions": post,
        },
    )


def expected_authorities() -> dict[str, Any]:
    """Return the A0 document with provider-observed staging membership."""

    return copy.deepcopy(_expected_authorities())


@lru_cache(maxsize=1)
def _expected_authorities() -> dict[str, Any]:
    """Build the immutable expected-authority fixture once."""

    final = _authority_inventory()
    promotion = final["ingress_promotion"]
    authorities: list[dict[str, Any]] = []
    for source in final["authorities"]:
        row = dict(source)
        if row["authority_role"] == "release_authority_ingress":
            for key in (
                "deployment_id",
                "deployment_observation_sha256",
                "deployment_observation_record_id",
                "deployment_observation_record_sha256",
                "deployment_versions",
            ):
                row[key] = promotion[f"pre_promotion_{key}"]
        else:
            row["deployment_observation_record_id"] = digest(
                f"{row['authority_role']} A0 observation WORM record id"
            )
            row["deployment_observation_record_sha256"] = digest(
                f"{row['authority_role']} A0 observation WORM record bytes"
            )
        row["configuration_sha256"] = digest(f"{row['authority_role']} configuration")
        row["version_resource_projection_sha256"] = digest(
            f"{row['authority_role']} version resources"
        )
        authorities.append(row)
    return activation_contract.expected_document(
        account_id=ACCOUNT_ID,
        broker_source_commit_sha=SOURCE_COMMIT_SHA,
        authorities=authorities,
        provider_observed_at="2026-08-14T23:57:50Z",
    )


def service_activation_record() -> dict[str, Any]:
    """Return the self-excluding post-A1 WORM record body."""

    return copy.deepcopy(_service_activation_record())


@lru_cache(maxsize=1)
def _service_activation_record() -> dict[str, Any]:
    """Build the immutable activation-record fixture once."""

    return activation_contract.activation_document(
        provisioned_record_id=digest("A0"),
        provisioned_record_sha256=digest("A0 bytes"),
        previous_record_id=digest("A1"),
        previous_record_sha256=digest("A1 bytes"),
        expected_service_authorities=_expected_authorities(),
        activated_service_authorities=_authority_inventory(),
        promotion_started_at="2026-08-14T23:58:00Z",
        promotion_completed_at="2026-08-14T23:59:00Z",
        provider_observation_started_at="2026-08-14T23:59:00Z",
        provider_observation_completed_at="2026-08-14T23:59:10Z",
        broker_accepted_at="2026-08-14T23:59:11Z",
    )


@lru_cache(maxsize=1)
def activation_record_id() -> str:
    return activation_contract.activation_record_id(_service_activation_record())


@lru_cache(maxsize=1)
def activation_record_sha256() -> str:
    return activation_contract.activation_record_sha256(_service_activation_record())


def authority_head() -> dict[str, Any]:
    """Return the global monotonic head committed after final observation."""

    return copy.deepcopy(_authority_head())


@lru_cache(maxsize=1)
def _authority_head() -> dict[str, Any]:
    """Build the immutable authority-head fixture once."""

    return activation_contract.authority_head_document(
        generation=1,
        previous={"kind": "GENESIS"},
        service_authority_activation_record=_service_activation_record(),
        committed_at="2026-08-14T23:59:12Z",
    )


@lru_cache(maxsize=1)
def authority_head_sha256() -> str:
    return activation_contract.authority_head_sha256(
        _authority_head(), _service_activation_record()
    )


@lru_cache(maxsize=1)
def authority_head_record_id() -> str:
    return activation_contract.authority_head_record_id(
        _authority_head(), _service_activation_record()
    )


def authority_for_role(authority_role: str) -> Mapping[str, Any]:
    """Return one immutable-looking activated authority fixture row."""

    return _authority_index()[authority_role]


@lru_cache(maxsize=1)
def _authority_index() -> Mapping[str, Mapping[str, Any]]:
    return inventory_contract.validate(_authority_inventory())


@lru_cache(maxsize=1)
def authority_inventory_sha256() -> str:
    return inventory_contract.digest(_authority_inventory())


@lru_cache(maxsize=1)
def expected_authorities_sha256() -> str:
    return activation_contract.expected_digest(_expected_authorities())


def producer_common(service_role: str) -> dict[str, Any]:
    """Return the five exact authority fields common to service producers."""

    authority_role = AUTHORITY_ROLE_BY_SERVICE_ROLE[service_role]
    authority = authority_for_role(authority_role)
    return {
        "kind": "trusted_controller_service",
        "service_role": service_role,
        "service_authority_role": authority_role,
        "service_identity": authority["service_identity"],
        "service_version_id": authority["worker_version_id"],
        "deployment_observation_sha256": authority["deployment_observation_sha256"],
        "deployment_observation_record_id": authority[
            "deployment_observation_record_id"
        ],
        "deployment_observation_record_sha256": authority[
            "deployment_observation_record_sha256"
        ],
        "service_authority_inventory_sha256": authority_inventory_sha256(),
        "activated_authority_head_record_id": authority_head_record_id(),
        "activated_authority_head_record_sha256": authority_head_sha256(),
        "activated_authority_head_generation": 1,
    }


def composite_constituents() -> dict[str, str]:
    """Return the independently activated GitHub and PyPI reader pins."""

    github = authority_for_role("governance_reader")
    pypi = authority_for_role("pypi_reader")
    return {
        "github_reader_service_authority_role": "governance_reader",
        "github_reader_service_identity": github["service_identity"],
        "github_reader_service_version_id": github["worker_version_id"],
        "github_reader_deployment_observation_sha256": github[
            "deployment_observation_sha256"
        ],
        "github_reader_deployment_observation_record_id": github[
            "deployment_observation_record_id"
        ],
        "github_reader_deployment_observation_record_sha256": github[
            "deployment_observation_record_sha256"
        ],
        "pypi_reader_service_authority_role": "pypi_reader",
        "pypi_reader_service_identity": pypi["service_identity"],
        "pypi_reader_service_version_id": pypi["worker_version_id"],
        "pypi_reader_deployment_observation_sha256": pypi[
            "deployment_observation_sha256"
        ],
        "pypi_reader_deployment_observation_record_id": pypi[
            "deployment_observation_record_id"
        ],
        "pypi_reader_deployment_observation_record_sha256": pypi[
            "deployment_observation_record_sha256"
        ],
    }


def _authority(role: str) -> dict[str, Any]:
    service = _SERVICE_NAMES[role]
    version = (
        INGRESS_FINAL_VERSION
        if role == "release_authority_ingress"
        else (cloudflare_uuid(f"{role} worker version"))
    )
    deployment_id = (
        cloudflare_uuid("ingress deployment post")
        if role == "release_authority_ingress"
        else cloudflare_uuid(f"{role} deployment")
    )
    observation = digest(
        "ingress post promotion observation"
        if role == "release_authority_ingress"
        else f"{role} deployment observation"
    )
    versions = (
        _versions({INGRESS_FINAL_VERSION: 100})
        if role == "release_authority_ingress"
        else [{"percentage": 100, "worker_version_id": version}]
    )
    return {
        "authority_role": role,
        "binding": inventory_contract.AUTHORITY_BINDINGS[role],
        "service": service,
        "service_identity": f"cloudflare-worker:{ACCOUNT_ID}/{service}@{version}",
        "worker_version_id": version,
        "deployment_id": deployment_id,
        "deployment_observation_sha256": observation,
        "deployment_observation_record_id": digest(
            "ingress post promotion observation WORM record id"
            if role == "release_authority_ingress"
            else f"{role} post observation WORM record id"
        ),
        "deployment_observation_record_sha256": digest(
            "ingress post promotion observation WORM record bytes"
            if role == "release_authority_ingress"
            else f"{role} post observation WORM record bytes"
        ),
        "deployment_versions": versions,
        "source_commit_sha": SOURCE_COMMIT_SHA,
        "source_sha256": digest(f"{role} source"),
        "configuration_sha256": digest(f"{role} configuration"),
        "version_resource_projection_sha256": digest(f"{role} version resources"),
    }


def _versions(values: Mapping[str, int]) -> list[dict[str, Any]]:
    return [
        {"percentage": values[version], "worker_version_id": version}
        for version in sorted(values)
    ]
