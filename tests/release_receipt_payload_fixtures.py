"""Payload constructors for deterministic receipt-v2 fixtures."""

from __future__ import annotations

from typing import Any

from tests import release_service_authority_fixtures as service_authority
from tests.release_receipt_fixture_identity import (
    ATTEMPT_ID,
    CANDIDATE_ID,
    CANDIDATE_INVENTORY_SHA256,
    COMMIT_SHA,
    LEASE_ID,
    QUEUE_ID,
    RECOVERY_ID,
    TAG,
    TAG_OBJECT_SHA,
    WORKFLOW_SHA,
    digest,
    distributions as distribution_inventory,
)
from tools.evidence import release_receipt_inventory as inventory


def request_payload() -> dict[str, Any]:
    activation_record = service_authority.service_activation_record()
    authority_head = service_authority.authority_head()
    return {
        "kind": "REQUEST_ENQUEUED",
        "state": "QUEUED",
        "queue_sequence": 0,
        "pending_count": 1,
        "max_pending_attempts": 32,
        "service_authority_activation_record": activation_record,
        "service_authority_activation_record_id": (
            service_authority.activation_record_id()
        ),
        "service_authority_activation_record_sha256": (
            service_authority.activation_record_sha256()
        ),
        "activated_authority_head": authority_head,
        "activated_authority_head_record_id": (
            service_authority.authority_head_record_id()
        ),
        "activated_authority_head_record_sha256": (
            service_authority.authority_head_sha256()
        ),
    }


def governance_payload(label: str) -> dict[str, Any]:
    return {
        "kind": "GOVERNANCE_SNAPSHOT",
        "state": f"GOVERNANCE_{label}",
        "label": label,
        "snapshot_sha256": digest(f"snapshot-{label}"),
        "provider_observation_sha256": digest(f"observation-{label}"),
        "started_at": "2026-08-15T00:00:00Z",
        "completed_at": "2026-08-15T00:00:10Z",
        "read_count": 2,
        "attempt_number": 1,
        "pagination_complete": True,
        "protected_base_sha": COMMIT_SHA,
        "tag": TAG,
        "tag_ref": f"refs/tags/{TAG}",
        "tag_object_type": "tag",
        "tag_object_sha": TAG_OBJECT_SHA,
        "peeled_commit_sha": COMMIT_SHA,
        "tag_created_by_controller": False,
        "tag_mutation_performed": False,
        "tag_ruleset_id": 2_000_001,
        "tag_ruleset_version": 3,
        "ruleset_projection_sha256": digest("rulesets"),
        "activation_bypass_actors_sha256": digest("A0 bypass actors"),
        "tag_rule_suites_sha256": digest(f"tag rule suites {label}"),
        "tag_rule_suite_count": 1,
        "tag_rule_suite_transition_result": "pass",
        "tag_ruleset_bypass_observed": False,
        "required_checks_sha256": digest("checks"),
        "actions_policy_observation_sha256": digest("actions policy"),
        "actions_allowed": "selected",
        "actions_sha_pinning_required": True,
        "github_owned_allowed": True,
        "verified_allowed": False,
        "patterns_allowed_sha256": digest("actions patterns"),
        "immutable_releases_enabled": True,
    }


def candidate_payload() -> dict[str, Any]:
    artifact_digest = digest("provider zip")
    distributions = distribution_inventory()
    candidate_reader = service_authority.authority_for_role("candidate_reader")
    return {
        "kind": "CANDIDATE_HANDOFF",
        "state": "CANDIDATE_HANDOFF",
        "candidate_id": CANDIDATE_ID,
        "candidate_inventory_sha256": CANDIDATE_INVENTORY_SHA256,
        "candidate_run_id": 31_900_000_001,
        "candidate_run_attempt": 1,
        "candidate_artifact_id": 9_300_000_001,
        "candidate_artifact_digest": artifact_digest,
        "candidate_manifest_sha256": digest("manifest"),
        "file_count": 25,
        "total_bytes": 101,
        "candidate_artifact_raw_zip_sha256": artifact_digest,
        "candidate_artifact_raw_zip_size_bytes": 97,
        "candidate_artifact_provider_response_sha256": digest("provider response"),
        "candidate_artifact_provider_observation_sha256": digest(
            "provider observation"
        ),
        "candidate_artifact_broker_request_id": "request-01HXDPONE",
        "candidate_artifact_provider_metadata_schema": (
            "dpone.github-actions-artifact-observation.v1"
        ),
        "candidate_artifact_provider_api_version": "2026-03-10",
        "candidate_artifact_created_at": "2026-08-15T00:00:00Z",
        "candidate_artifact_expires_at": "2026-08-15T00:02:00Z",
        "candidate_artifact_source_url_expires_at": "2026-08-15T00:01:00Z",
        "candidate_artifact_source_url_sha256": digest("private source URL"),
        "candidate_reader_service_identity": candidate_reader["service_identity"],
        "candidate_reader_service_version_id": candidate_reader["worker_version_id"],
        "candidate_reader_deployment_observation_record_id": candidate_reader[
            "deployment_observation_record_id"
        ],
        "candidate_reader_deployment_observation_record_sha256": candidate_reader[
            "deployment_observation_record_sha256"
        ],
        "candidate_artifact_tag_object_sha": TAG_OBJECT_SHA,
        "candidate_artifact_policy_blob_sha": "e" * 40,
        "candidate_artifact_policy_sha256": digest("policy"),
        "candidate_artifact_file_count": 25,
        "candidate_artifact_expanded_bytes": 100,
        "distribution_inventory": distributions,
        "distribution_inventory_sha256": inventory.inventory_sha256(
            inventory.DISTRIBUTION_SCHEMA, distributions
        ),
    }


def lease_acquired_payload() -> dict[str, Any]:
    return {
        "kind": "LEASE_ACQUIRED",
        "state": "LEASE_ACQUIRED",
        "lease_id": LEASE_ID,
        "fencing_token": 3,
        "acquired_at": "2026-08-15T00:00:00Z",
        "expires_at": "2026-08-15T00:05:00Z",
        "ttl_seconds": 300,
        "renew_interval_seconds": 45,
        "attempt_id": ATTEMPT_ID,
        "queue_entry_id": QUEUE_ID,
        "recovery_acquisition": False,
    }


def lease_renewed_payload() -> dict[str, Any]:
    return {
        "kind": "LEASE_RENEWED",
        "state": "LEASE_RENEWED",
        "lease_id": LEASE_ID,
        "fencing_token": 3,
        "previous_expires_at": "2026-08-15T00:05:00Z",
        "renewed_at": "2026-08-15T00:00:45Z",
        "expires_at": "2026-08-15T00:05:45Z",
        "ttl_seconds": 300,
    }


def lease_released_payload() -> dict[str, Any]:
    return {
        "kind": "LEASE_RELEASED",
        "state": "LEASE_RELEASED",
        "lease_id": LEASE_ID,
        "fencing_token": 3,
        "released_at": "2026-08-15T00:03:21Z",
        "reason": "RECOVERY_REQUIRED",
    }


def abandoned_lease_release_payload() -> dict[str, Any]:
    payload = lease_released_payload()
    payload["reason"] = "ABANDONED"
    return payload


def lease_expired_payload() -> dict[str, Any]:
    return {
        "kind": "LEASE_EXPIRED",
        "state": "LEASE_EXPIRED",
        "lease_id": LEASE_ID,
        "fencing_token": 3,
        "expired_at": "2026-08-15T00:06:00Z",
        "external_commit_observed": True,
        "next_state": "RECOVERY_REQUIRED",
        "recovery_id": RECOVERY_ID,
    }


def hygiene_payload() -> dict[str, Any]:
    return {
        "kind": "TENANT_HYGIENE_VERIFIED",
        "state": "TENANT_HYGIENE_VERIFIED",
        "candidate_id": CANDIDATE_ID,
        "scanner_service_version_id": service_authority.authority_for_role(
            "tenant_scanner"
        )["worker_version_id"],
        "policy_sha256": digest("hygiene policy"),
        "tag_tree_archive_sha256": digest("tag tree"),
        "tag_tree_result_sha256": digest("tag result"),
        "candidate_archives_inventory_sha256": digest("archive inventory"),
        "archive_results_sha256": digest("archive results"),
        "archive_count": 8,
        "finding_count": 0,
        "decision": "CLEAN",
    }


def attestation_payload() -> dict[str, Any]:
    from tests import release_receipt_intent_fixtures as intent_fixture

    return {
        "kind": "ATTESTATION_VERIFIED",
        "state": "ATTESTED",
        "candidate_id": CANDIDATE_ID,
        "subject_manifest_sha256": digest("subjects"),
        "attestation_set_sha256": digest("attestations"),
        "provider_receipt_inventory_sha256": digest("attestation receipts"),
        "subject_count": 8,
        "signer_repository_id": 1_305_993_853,
        "signer_workflow_sha": WORKFLOW_SHA,
        "cryptographically_verified": True,
        **intent_fixture.consumption("ATTESTATION_CREATE"),
    }


def release_assets() -> list[dict[str, Any]]:
    return [
        {
            "name": f"release-asset-{index:02d}.json",
            "size_bytes": 10 + index,
            "sha256": digest(f"draft asset {index}"),
        }
        for index in range(17)
    ]


def bundle_payload() -> dict[str, Any]:
    assets = release_assets()
    return {
        "kind": "PUBLIC_BUNDLE_VERIFIED",
        "state": "PUBLIC_BUNDLE_VERIFIED",
        "candidate_id": CANDIDATE_ID,
        "public_bundle_id": digest("bundle id"),
        "artifact_id": 9_400_000_001,
        "artifact_digest": digest("bundle artifact"),
        "manifest_sha256": digest("bundle manifest"),
        "file_count": 19,
        "total_bytes": 202,
        "verifier_receipt_sha256": digest("bundle verifier"),
        "expected_asset_count": len(assets),
        "release_asset_inventory": assets,
        "expected_asset_inventory_sha256": inventory.inventory_sha256(
            inventory.GITHUB_ASSET_SCHEMA, assets
        ),
    }


def draft_created_payload() -> dict[str, Any]:
    from tests import release_receipt_intent_fixtures as intent_fixture

    return {
        "kind": "DRAFT_TRANSITION",
        "state": "DRAFT_CREATED",
        "transition": "CREATED",
        "release_id": 5_000_000_001,
        "candidate_id": CANDIDATE_ID,
        "tag": TAG,
        "release_body_sha256": digest("body"),
        "public_bundle_manifest_sha256": digest("bundle manifest"),
        "draft": True,
        "prerelease": False,
        "immutable": False,
        "provider_response_sha256": digest("draft create response"),
        **intent_fixture.consumption("GITHUB_DRAFT_CREATE"),
    }


def draft_asset_payload(asset_index: int = 0) -> dict[str, Any]:
    from tests import release_receipt_intent_fixtures as intent_fixture

    asset = release_assets()[asset_index]
    return {
        "kind": "DRAFT_TRANSITION",
        "state": "DRAFT_STAGING",
        "transition": "ASSET_UPLOADED",
        "release_id": 5_000_000_001,
        "candidate_id": CANDIDATE_ID,
        "tag": TAG,
        "public_bundle_manifest_sha256": digest("bundle manifest"),
        "asset": {
            "asset_id": 6_000_000_001 + asset_index,
            **asset,
            "state": "uploaded",
        },
        "provider_response_sha256": digest(f"asset response {asset_index}"),
        **intent_fixture.consumption(
            "GITHUB_DRAFT_ASSET_UPLOAD", asset_index=asset_index
        ),
    }


def draft_inventory_payload(transition: str) -> dict[str, Any]:
    from tests import release_receipt_intent_fixtures as intent_fixture

    assets = release_assets()
    payload = {
        "kind": "DRAFT_TRANSITION",
        "state": "DRAFT_STAGED" if transition == "STAGED" else "DRAFT_VERIFIED",
        "transition": transition,
        "release_id": 5_000_000_001,
        "candidate_id": CANDIDATE_ID,
        "tag": TAG,
        "release_body_sha256": digest("body"),
        "public_bundle_manifest_sha256": digest("bundle manifest"),
        "asset_count": 17,
        "assets_sha256": inventory.inventory_sha256(
            inventory.GITHUB_ASSET_SCHEMA, assets
        ),
        "draft": True,
        "prerelease": False,
        "immutable": False,
        "provider_observation_sha256": digest(f"draft {transition}"),
    }
    if transition == "STAGED":
        payload.update(intent_fixture.consumption("GITHUB_DRAFT_UPDATE"))
    return payload
