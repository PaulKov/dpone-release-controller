"""INTERNAL/CONFIDENTIAL marker fixture; NOT PUBLICATION data."""

from __future__ import annotations

from typing import Any, Mapping

from tests import release_receipt_fixtures as base
from tools.evidence import release_private_closed_marker as marker_contract


def marker(artifact: Mapping[str, Any]) -> dict[str, Any]:
    """Build the post-upload marker binding the provider artifact tuple."""

    return marker_contract.build(
        target_repository_id=1_255_975_556,
        tag=base.TAG,
        tag_object_sha=base.TAG_OBJECT_SHA,
        peeled_commit_sha=base.COMMIT_SHA,
        release_identity_id=base.RELEASE_ID,
        release_authority_id=base.AUTHORITY_ID,
        candidate_id=base.CANDIDATE_ID,
        controller_repository_id=1_305_993_853,
        controller_workflow_id=artifact["controller_workflow_id"],
        controller_workflow_sha=artifact["controller_workflow_sha"],
        controller_action_commit_sha=artifact["controller_action_commit_sha"],
        controller_action_metadata_blob_sha=artifact[
            "controller_action_metadata_blob_sha"
        ],
        controller_action_bundle_sha256=artifact["controller_action_bundle_sha256"],
        controller_run_id=artifact["controller_run_id"],
        controller_run_attempt=artifact["controller_run_attempt"],
        closed_receipt_id=artifact["closed_receipt_id"],
        closed_receipt_sha256=artifact["closed_receipt_sha256"],
        evidence_artifact_id=artifact["closure_artifact_id"],
        evidence_artifact_name=artifact["closure_artifact_name"],
        evidence_artifact_digest=artifact["closure_artifact_digest"],
        evidence_artifact_member_inventory_sha256=artifact[
            "closure_artifact_member_inventory_sha256"
        ],
        closure_manifest_sha256=artifact["closure_manifest_sha256"],
        release_evidence_sha256=artifact["release_evidence_sha256"],
        receipt_chain_sha256=artifact["receipt_chain_sha256"],
    )
