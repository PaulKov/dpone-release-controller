"""Cross-bind receipt authority projections to one compiled inventory.

The boundary consumes a prevalidated immutable context.  It never reparses or
rehashes the 14-row activation document per receipt, keeping offline closure
verification linear in the receipt count.
"""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence.release_controller_service_inventory_types import (
    INGRESS_ROLE,
    CompiledServiceInventory,
    ServiceInventoryError,
)
from tools.evidence.release_controller_service_roles import (
    AUTHORITY_ROLE_BY_SERVICE_ROLE,
)


def bind_committer(
    committer: Mapping[str, Any], context: CompiledServiceInventory
) -> None:
    """Cross-bind the broker committer and post-promotion inventory."""

    inventory = context.document
    ingress = context.indexed[INGRESS_ROLE]
    if (
        committer.get("cloudflare_account_id") != inventory["account_id"]
        or committer.get("service_authority_inventory_sha256") != context.sha256
        or committer.get("service_identity") != ingress["service_identity"]
        or committer.get("worker_version_id") != ingress["worker_version_id"]
        or committer.get("source_sha256") != ingress["source_sha256"]
        or committer.get("deployment_observation_record_id")
        != ingress["deployment_observation_record_id"]
        or committer.get("deployment_observation_record_sha256")
        != ingress["deployment_observation_record_sha256"]
        or committer.get("activated_authority_head_generation") != 1
    ):
        raise ServiceInventoryError("committer/service inventory authority mismatch")


def bind_producer(
    producer: Mapping[str, Any], context: CompiledServiceInventory
) -> None:
    """Bind one trusted producer to its activated executable authority row."""

    if producer.get("kind") == "release_authority_broker_timer":
        _bind_timer(producer, context)
        return
    if producer.get("kind") != "trusted_controller_service":
        return
    indexed = context.indexed
    service_role = producer.get("service_role")
    expected_authority = AUTHORITY_ROLE_BY_SERVICE_ROLE.get(service_role)
    if (
        expected_authority is None
        or producer.get("service_authority_role") != expected_authority
    ):
        raise ServiceInventoryError("producer logical/authority role mismatch")
    authority = indexed[expected_authority]
    if (
        producer.get("service_identity") != authority["service_identity"]
        or producer.get("service_version_id") != authority["worker_version_id"]
        or producer.get("deployment_observation_sha256")
        != authority["deployment_observation_sha256"]
        or producer.get("deployment_observation_record_id")
        != authority["deployment_observation_record_id"]
        or producer.get("deployment_observation_record_sha256")
        != authority["deployment_observation_record_sha256"]
        or producer.get("service_authority_inventory_sha256") != context.sha256
        or producer.get("activated_authority_head_generation") != 1
    ):
        raise ServiceInventoryError("producer service authority binding mismatch")
    if service_role in {"cancellation_observer", "recovery_observer"}:
        _bind_composite_constituents(producer, indexed)


def bind_candidate_reader(
    payload: Mapping[str, Any], context: CompiledServiceInventory
) -> None:
    """Bind candidate provider bytes to the activated route-less reader."""

    reader = context.indexed["candidate_reader"]
    if (
        payload.get("candidate_reader_service_identity") != reader["service_identity"]
        or payload.get("candidate_reader_service_version_id")
        != reader["worker_version_id"]
        or payload.get("candidate_reader_deployment_observation_record_id")
        != reader["deployment_observation_record_id"]
        or payload.get("candidate_reader_deployment_observation_record_sha256")
        != reader["deployment_observation_record_sha256"]
    ):
        raise ServiceInventoryError("candidate reader/activated authority mismatch")


def bind_authority_guard(
    guard: Mapping[str, Any],
    context: CompiledServiceInventory,
    *,
    head_record_id: str,
    head_record_sha256: str,
) -> None:
    """Bind a fresh effect guard's authorizer to the activated inventory row."""

    service_role = guard.get("service_role")
    authority_role = AUTHORITY_ROLE_BY_SERVICE_ROLE.get(service_role)
    if authority_role is None or guard.get("service_authority_role") != authority_role:
        raise ServiceInventoryError("authority guard role mapping mismatch")
    authority = context.indexed[authority_role]
    if (
        guard.get("service_identity") != authority["service_identity"]
        or guard.get("service_version_id") != authority["worker_version_id"]
        or guard.get("deployment_observation_sha256")
        != authority["deployment_observation_sha256"]
        or guard.get("deployment_observation_record_id")
        != authority["deployment_observation_record_id"]
        or guard.get("deployment_observation_record_sha256")
        != authority["deployment_observation_record_sha256"]
        or guard.get("service_authority_inventory_sha256") != context.sha256
        or guard.get("activated_authority_head_record_id") != head_record_id
        or guard.get("activated_authority_head_record_sha256") != head_record_sha256
        or guard.get("activated_authority_head_generation") != 1
    ):
        raise ServiceInventoryError("authority guard activated-service mismatch")


def _bind_composite_constituents(
    producer: Mapping[str, Any], indexed: Mapping[str, Mapping[str, Any]]
) -> None:
    github = indexed["governance_reader"]
    pypi = indexed["pypi_reader"]
    if (
        producer.get("github_reader_service_authority_role") != "governance_reader"
        or producer.get("github_reader_service_identity") != github["service_identity"]
        or producer.get("github_reader_service_version_id")
        != github["worker_version_id"]
        or producer.get("github_reader_deployment_observation_sha256")
        != github["deployment_observation_sha256"]
        or producer.get("github_reader_deployment_observation_record_id")
        != github["deployment_observation_record_id"]
        or producer.get("github_reader_deployment_observation_record_sha256")
        != github["deployment_observation_record_sha256"]
        or producer.get("pypi_reader_service_authority_role") != "pypi_reader"
        or producer.get("pypi_reader_service_identity") != pypi["service_identity"]
        or producer.get("pypi_reader_service_version_id") != pypi["worker_version_id"]
        or producer.get("pypi_reader_deployment_observation_sha256")
        != pypi["deployment_observation_sha256"]
        or producer.get("pypi_reader_deployment_observation_record_id")
        != pypi["deployment_observation_record_id"]
        or producer.get("pypi_reader_deployment_observation_record_sha256")
        != pypi["deployment_observation_record_sha256"]
    ):
        raise ServiceInventoryError("composite observer constituent authority mismatch")


def _bind_timer(producer: Mapping[str, Any], context: CompiledServiceInventory) -> None:
    ingress = context.indexed[INGRESS_ROLE]
    if (
        producer.get("service_authority_role") != INGRESS_ROLE
        or producer.get("service_identity") != ingress["service_identity"]
        or producer.get("worker_version_id") != ingress["worker_version_id"]
        or producer.get("deployment_observation_sha256")
        != ingress["deployment_observation_sha256"]
        or producer.get("deployment_observation_record_id")
        != ingress["deployment_observation_record_id"]
        or producer.get("deployment_observation_record_sha256")
        != ingress["deployment_observation_record_sha256"]
        or producer.get("service_authority_inventory_sha256") != context.sha256
        or producer.get("activated_authority_head_generation") != 1
    ):
        raise ServiceInventoryError("broker timer/ingress authority mismatch")
