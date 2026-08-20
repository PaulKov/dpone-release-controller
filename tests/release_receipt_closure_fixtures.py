"""INTERNAL/CONFIDENTIAL receipt prototypes; NOT PUBLICATION fixtures."""

from __future__ import annotations

import hashlib
from typing import Any

from tests import release_receipt_fixtures as base

from tests.release_receipt_fixtures import (
    ATTEMPT_ID,
    AUTHORITY_ID,
    AUTHORIZATION_ID,
    CANDIDATE_ID,
    RELEASE_ID,
    TAG,
    TAG_OBJECT_SHA,
    COMMIT_SHA,
    WORKFLOW_SHA,
    ACTION_COMMIT_SHA,
    ACTION_METADATA_BLOB_SHA,
    ACTION_BUNDLE_SHA256,
    digest,
)
from tools.evidence import release_private_closed_marker as marker_contract
from tests.release_closed_marker_fixtures import marker as build_closed_marker
from tests import release_receipt_intent_fixtures as intent_fixture
from tools.evidence import release_receipt_inventory as inventory


def closed() -> dict[str, Any]:
    return {
        "kind": "CLOSED",
        "state": "CLOSED",
        "status": "PASS",
        "decision": "GO",
        "release_identity_id": RELEASE_ID,
        "release_authority_id": AUTHORITY_ID,
        "candidate_id": CANDIDATE_ID,
        "attempt_id": ATTEMPT_ID,
        "authorization_id": AUTHORIZATION_ID,
        "controller_action_commit_sha": ACTION_COMMIT_SHA,
        "controller_action_metadata_blob_sha": ACTION_METADATA_BLOB_SHA,
        "controller_action_bundle_sha256": ACTION_BUNDLE_SHA256,
        "public_bundle_manifest_sha256": digest("bundle manifest"),
        "snapshot_a_sha256": digest("snapshot-A"),
        "snapshot_b_sha256": digest("snapshot-B"),
        "snapshot_c_sha256": digest("snapshot-C"),
        "pypi_inventory_sha256": inventory.inventory_sha256(
            inventory.DISTRIBUTION_SCHEMA, base._distributions()
        ),
        "github_release_inventory_sha256": inventory.inventory_sha256(
            inventory.GITHUB_ASSET_SCHEMA, base._release_assets()
        ),
        "receipt_chain_verified": True,
        "blockers": [],
    }


def closure_artifact() -> dict[str, Any]:
    artifact_digest = digest("closure artifact")
    intent = intent_fixture.intent("GITHUB_CLOSURE_ARTIFACT_UPLOAD")
    members = intent["subject"]["member_inventory"]
    return {
        "kind": "CLOSURE_ARTIFACT_VERIFIED",
        "state": "CLOSURE_ARTIFACT_VERIFIED",
        "release_identity_id": RELEASE_ID,
        "release_authority_id": AUTHORITY_ID,
        "candidate_id": CANDIDATE_ID,
        "authorization_id": AUTHORIZATION_ID,
        "tag": TAG,
        "tag_object_sha": TAG_OBJECT_SHA,
        "peeled_commit_sha": COMMIT_SHA,
        "closed_receipt_id": digest("closed receipt id"),
        "closed_receipt_sha256": digest("closed receipt bytes"),
        "closure_artifact_id": 9_500_000_001,
        "controller_run_id": 123_456_789,
        "controller_run_attempt": 2,
        "controller_workflow_id": 316_322_127,
        "controller_workflow_sha": WORKFLOW_SHA,
        "controller_action_commit_sha": ACTION_COMMIT_SHA,
        "controller_action_metadata_blob_sha": ACTION_METADATA_BLOB_SHA,
        "controller_action_bundle_sha256": ACTION_BUNDLE_SHA256,
        "closure_artifact_name": "release-controller-closure-123456789-2",
        "closure_artifact_digest": artifact_digest,
        "closure_artifact_raw_zip_sha256": artifact_digest,
        "closure_artifact_size_bytes": 4096,
        "closure_artifact_expanded_bytes": sum(
            member["size_bytes"] for member in members
        ),
        "closure_artifact_file_count": 4,
        "closure_artifact_member_inventory": members,
        "closure_artifact_member_inventory_sha256": intent["subject"][
            "member_inventory_sha256"
        ],
        "closure_manifest_sha256": digest("closure manifest"),
        "release_evidence_sha256": digest("release evidence"),
        "receipt_chain_sha256": digest("receipt chain"),
        "provider_response_sha256": digest("closure upload response"),
        "provider_observation_sha256": digest("closure artifact observation"),
        "provider_api_version": "2026-03-10",
        "artifact_created_at": "2026-08-15T00:03:00Z",
        "artifact_expires_at": "2026-11-13T00:03:00Z",
        **intent_fixture.consumption("GITHUB_CLOSURE_ARTIFACT_UPLOAD"),
    }


def closed_check(transition: str) -> dict[str, Any]:
    artifact = closure_artifact()
    marker = build_closed_marker(artifact)
    marker_sha256 = marker_contract.sha256(marker)
    summary_sha256 = (
        "sha256:"
        + hashlib.sha256(marker_contract.summary(marker).encode("ascii")).hexdigest()
    )
    payload: dict[str, Any] = {
        "kind": "CLOSED_CHECK_TRANSITION",
        "state": f"CLOSED_CHECK_{transition}",
        "transition": transition,
        "authorization_id": AUTHORIZATION_ID,
        "release_identity_id": RELEASE_ID,
        "release_authority_id": AUTHORITY_ID,
        "candidate_id": CANDIDATE_ID,
        "tag": TAG,
        "tag_object_sha": TAG_OBJECT_SHA,
        "peeled_commit_sha": COMMIT_SHA,
        "closed_receipt_id": artifact["closed_receipt_id"],
        "closed_receipt_sha256": artifact["closed_receipt_sha256"],
        "closure_artifact_id": artifact["closure_artifact_id"],
        "closure_artifact_name": artifact["closure_artifact_name"],
        "closure_artifact_digest": artifact["closure_artifact_digest"],
        "closure_artifact_member_inventory_sha256": artifact[
            "closure_artifact_member_inventory_sha256"
        ],
        "closure_manifest_sha256": artifact["closure_manifest_sha256"],
        "release_evidence_sha256": artifact["release_evidence_sha256"],
        "receipt_chain_sha256": artifact["receipt_chain_sha256"],
        "closed_marker_sha256": marker_sha256,
        "check_app_id": 11_000_001,
        "check_installation_id": 12_000_001,
        "check_run_id": 13_000_001,
        "check_name": "Release controller CLOSED",
        "external_id": (f"dpone-release-controller.closed.v1|{RELEASE_ID}|123456789|2"),
        "controller_run_id": 123_456_789,
        "controller_run_attempt": 2,
        "controller_workflow_id": 316_322_127,
        "controller_workflow_sha": WORKFLOW_SHA,
        "controller_action_commit_sha": ACTION_COMMIT_SHA,
        "controller_action_metadata_blob_sha": ACTION_METADATA_BLOB_SHA,
        "controller_action_bundle_sha256": ACTION_BUNDLE_SHA256,
        "check_head_sha": COMMIT_SHA,
        "check_status": "completed",
        "check_conclusion": "success",
        "output_marker_schema": "dpone.release-controller-closed-check.v1",
        "output_marker": marker,
        "output_marker_sha256": marker_sha256,
        "output_title": marker_contract.OUTPUT_TITLE,
        "output_summary_sha256": summary_sha256,
        "provider_api_version": "2026-03-10",
    }
    if transition == "PROJECTED":
        payload["provider_response_sha256"] = digest("closed check response")
        payload["projected_at"] = "2026-08-15T00:03:10Z"
        payload.update(intent_fixture.consumption("GITHUB_CLOSED_CHECK_PROJECT"))
    else:
        payload["provider_observation_sha256"] = digest("closed check observation")
        payload["verified_at"] = "2026-08-15T00:03:20Z"
    return payload
