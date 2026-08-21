"""Closed mutation-intent, attestation, bundle, draft, and authorization payloads."""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_consumption as consumption
from tools.evidence import release_receipt_inventory as inventory
from tools.evidence import release_receipt_intents as intents
from tools.evidence import release_receipt_payload_draft as draft

_JOB = frozenset({"github_actions_job"})
_SERVICE = frozenset({"trusted_controller_service"})


def validate_intent(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Delegate to the sole closed one-use intent contract."""

    return intents.validate_intent(payload)


def validate_consumed(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Delegate to the sole closed pre-mutation consumption contract."""

    return consumption.validate_receipt(payload)


def validate_attestation(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "candidate_id",
            "subject_manifest_sha256",
            "attestation_set_sha256",
            "provider_receipt_inventory_sha256",
            "subject_count",
            "signer_repository_id",
            "signer_workflow_sha",
            "cryptographically_verified",
            *consumption.OUTCOME_KEYS,
        },
        "ATTESTATION_VERIFIED payload",
    )
    _constants(
        payload,
        kind="ATTESTATION_VERIFIED",
        state="ATTESTED",
        subject_count=8,
        signer_repository_id=contract.CONTROLLER_REPOSITORY_ID,
        cryptographically_verified=True,
    )
    contract.digest_fields(
        payload,
        "candidate_id",
        "subject_manifest_sha256",
        "attestation_set_sha256",
        "provider_receipt_inventory_sha256",
    )
    contract.git_sha(payload["signer_workflow_sha"], "signer_workflow_sha")
    consumption.validate_outcome(payload)
    return contract.PayloadSemantics("candidate", True, _SERVICE)


def validate_public_bundle(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "candidate_id",
            "public_bundle_id",
            "artifact_id",
            "artifact_digest",
            "manifest_sha256",
            "file_count",
            "total_bytes",
            "verifier_receipt_sha256",
            "expected_asset_count",
            "release_asset_inventory",
            "expected_asset_inventory_sha256",
        },
        "PUBLIC_BUNDLE_VERIFIED payload",
    )
    _constants(
        payload,
        kind="PUBLIC_BUNDLE_VERIFIED",
        state="PUBLIC_BUNDLE_VERIFIED",
    )
    contract.digest_fields(
        payload,
        "candidate_id",
        "public_bundle_id",
        "artifact_digest",
        "manifest_sha256",
        "verifier_receipt_sha256",
        "expected_asset_inventory_sha256",
    )
    contract.positive_fields(payload, "artifact_id", "file_count", "total_bytes")
    asset_count = contract.positive_int(
        payload["expected_asset_count"], "expected_asset_count"
    )
    assets = inventory.github_asset_inventory(
        payload["release_asset_inventory"], expected_count=asset_count
    )
    inventory.require_digest(
        payload["expected_asset_inventory_sha256"],
        inventory.GITHUB_ASSET_SCHEMA,
        assets,
        "expected_asset_inventory_sha256",
    )
    return contract.PayloadSemantics("candidate", True, _JOB)


def validate_draft(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    return draft.validate(payload)


def validate_authorized(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "authorization_state",
            "authorization_id",
            "candidate_id",
            "public_bundle_id",
            "public_bundle_manifest_sha256",
            "snapshot_a_sha256",
            "snapshot_b_sha256",
            "lease_id",
            "fencing_token",
            "expires_at",
            "blockers",
        },
        "AUTHORIZED payload",
    )
    _constants(
        payload,
        kind="AUTHORIZED",
        state="AUTHORIZED",
        authorization_state="AUTHORIZED",
    )
    contract.digest_fields(
        payload,
        "authorization_id",
        "candidate_id",
        "public_bundle_id",
        "public_bundle_manifest_sha256",
        "snapshot_a_sha256",
        "snapshot_b_sha256",
        "lease_id",
    )
    contract.positive_int(payload["fencing_token"], "fencing_token")
    contract.timestamp(payload["expires_at"], "expires_at")
    contract.empty_list(payload["blockers"], "blockers")
    return contract.PayloadSemantics("authorization", True, _JOB)


def _constants(payload: Mapping[str, Any], **expected: Any) -> None:
    for key, value in expected.items():
        if payload[key] != value or type(payload[key]) is not type(value):
            raise contract.ReceiptValidationError(f"{key} must be exactly {value!r}")
