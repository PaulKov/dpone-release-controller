"""Incident-hold and final CLOSED payload validation."""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract

JOB_PRODUCERS = frozenset({"github_actions_job"})
SERVICE_PRODUCERS = frozenset({"trusted_controller_service"})
MAINTAINER_PRODUCERS = frozenset({"maintainer_incident_action"})
HOLD_REASONS = {
    "CANDIDATE_CONFLICT",
    "GITHUB_CONFLICT",
    "GOVERNANCE_DRIFT",
    "PROVENANCE_CONFLICT",
    "PYPI_CONFLICT",
}


def validate_hold(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Validate a durable incident hold that survives lease expiry."""

    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "hold_id",
            "recovery_id",
            "reason_code",
            "incident_record_sha256",
            "provider_actor_id",
            "started_at",
            "retention_floor_days",
        },
        "INCIDENT_HOLD payload",
    )
    _constant(payload, "kind", "INCIDENT_HOLD")
    _constant(payload, "state", "INCIDENT_HOLD")
    _constant(payload, "retention_floor_days", contract.WORM_RETENTION_DAYS)
    contract.digest_fields(payload, "hold_id", "recovery_id", "incident_record_sha256")
    contract.positive_int(payload["provider_actor_id"], "provider_actor_id")
    contract.enum(payload["reason_code"], HOLD_REASONS, "reason_code")
    contract.timestamp(payload["started_at"], "started_at")
    return contract.PayloadSemantics("recovery", True, SERVICE_PRODUCERS)


def validate_hold_released(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Validate the pre-lease maintainer transition back to recovery-required."""

    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "hold_id",
            "recovery_id",
            "release_record_sha256",
            "provider_actor_id",
            "released_at",
            "next_state",
        },
        "INCIDENT_HOLD_RELEASED payload",
    )
    _constant(payload, "kind", "INCIDENT_HOLD_RELEASED")
    _constant(payload, "state", "RECOVERY_REQUIRED")
    _constant(payload, "next_state", "RECOVERY_REQUIRED")
    contract.digest_fields(payload, "hold_id", "recovery_id", "release_record_sha256")
    contract.positive_int(payload["provider_actor_id"], "provider_actor_id")
    contract.timestamp(payload["released_at"], "released_at")
    return contract.PayloadSemantics("recovery", False, MAINTAINER_PRODUCERS)


def validate_closed(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Validate the decision record before closure projection/finalization."""

    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "status",
            "decision",
            "release_identity_id",
            "release_authority_id",
            "candidate_id",
            "attempt_id",
            "authorization_id",
            "controller_action_commit_sha",
            "controller_action_metadata_blob_sha",
            "controller_action_bundle_sha256",
            "public_bundle_manifest_sha256",
            "snapshot_a_sha256",
            "snapshot_b_sha256",
            "snapshot_c_sha256",
            "pypi_inventory_sha256",
            "github_release_inventory_sha256",
            "receipt_chain_verified",
            "blockers",
        },
        "CLOSED payload",
    )
    for key, value in {
        "kind": "CLOSED",
        "state": "CLOSED",
        "status": "PASS",
        "decision": "GO",
        "receipt_chain_verified": True,
    }.items():
        _constant(payload, key, value)
    contract.digest_fields(
        payload,
        "release_identity_id",
        "release_authority_id",
        "candidate_id",
        "attempt_id",
        "authorization_id",
        "controller_action_bundle_sha256",
        "public_bundle_manifest_sha256",
        "snapshot_a_sha256",
        "snapshot_b_sha256",
        "snapshot_c_sha256",
        "pypi_inventory_sha256",
        "github_release_inventory_sha256",
    )
    contract.git_sha(
        payload["controller_action_commit_sha"], "controller_action_commit_sha"
    )
    contract.git_sha(
        payload["controller_action_metadata_blob_sha"],
        "controller_action_metadata_blob_sha",
    )
    contract.empty_list(payload["blockers"], "blockers")
    return contract.PayloadSemantics("authorization", True, JOB_PRODUCERS)


def _constant(payload: Mapping[str, Any], key: str, expected: Any) -> None:
    if payload[key] != expected or type(payload[key]) is not type(expected):
        raise contract.ReceiptValidationError(f"{key} must be exactly {expected!r}")
