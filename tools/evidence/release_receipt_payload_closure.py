"""INTERNAL/CONFIDENTIAL receipt prototypes; NOT PUBLICATION contracts.

These historical payload validators are quarantined from the active receipt
union. They preserve review context only and do not grant a build, route, wire,
or publication capability.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_private_closed_marker as marker_contract
from tools.evidence import release_receipt_consumption as consumption
from tools.evidence import release_private_closure_inventory as closure_inventory

_JOB = frozenset({"github_actions_job"})
_SERVICE = frozenset({"trusted_controller_service"})
_ARTIFACT_NAME_TEMPLATE = "release-controller-closure-{run_id}-{run_attempt}"
_CHECK_NAME = "Release controller CLOSED"
_MARKER_SCHEMA = "dpone.release-controller-closed-check.v1"
_API_VERSION = contract.GITHUB_API_VERSION
_CHECK_COMMON = {
    "kind",
    "state",
    "transition",
    "authorization_id",
    "release_identity_id",
    "release_authority_id",
    "candidate_id",
    "tag",
    "tag_object_sha",
    "peeled_commit_sha",
    "closed_receipt_id",
    "closed_receipt_sha256",
    "closure_artifact_id",
    "closure_artifact_name",
    "closure_artifact_digest",
    "closure_artifact_member_inventory_sha256",
    "closure_manifest_sha256",
    "release_evidence_sha256",
    "receipt_chain_sha256",
    "closed_marker_sha256",
    "check_app_id",
    "check_installation_id",
    "check_run_id",
    "check_name",
    "external_id",
    "controller_run_id",
    "controller_run_attempt",
    "controller_workflow_id",
    "controller_workflow_sha",
    "controller_action_commit_sha",
    "controller_action_metadata_blob_sha",
    "controller_action_bundle_sha256",
    "check_head_sha",
    "check_status",
    "check_conclusion",
    "output_marker_schema",
    "output_marker",
    "output_marker_sha256",
    "output_title",
    "output_summary_sha256",
    "provider_api_version",
}


def validate_closure_artifact(
    payload: Mapping[str, Any],
) -> contract.PayloadSemantics:
    """Require the provider-complete closure artifact created after CLOSED."""

    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "release_identity_id",
            "release_authority_id",
            "candidate_id",
            "authorization_id",
            "tag",
            "tag_object_sha",
            "peeled_commit_sha",
            "closed_receipt_id",
            "closed_receipt_sha256",
            "closure_artifact_id",
            "controller_run_id",
            "controller_run_attempt",
            "controller_workflow_id",
            "controller_workflow_sha",
            "controller_action_commit_sha",
            "controller_action_metadata_blob_sha",
            "controller_action_bundle_sha256",
            "closure_artifact_name",
            "closure_artifact_digest",
            "closure_artifact_raw_zip_sha256",
            "closure_artifact_size_bytes",
            "closure_artifact_expanded_bytes",
            "closure_artifact_file_count",
            "closure_artifact_member_inventory",
            "closure_artifact_member_inventory_sha256",
            "closure_manifest_sha256",
            "release_evidence_sha256",
            "receipt_chain_sha256",
            "provider_response_sha256",
            "provider_observation_sha256",
            "provider_api_version",
            "artifact_created_at",
            "artifact_expires_at",
            *consumption.OUTCOME_KEYS,
        },
        "CLOSURE_ARTIFACT_VERIFIED payload",
    )
    _constants(
        payload,
        kind="CLOSURE_ARTIFACT_VERIFIED",
        state="CLOSURE_ARTIFACT_VERIFIED",
        closure_artifact_file_count=4,
        provider_api_version=_API_VERSION,
    )
    contract.digest_fields(
        payload,
        "release_identity_id",
        "release_authority_id",
        "candidate_id",
        "authorization_id",
        "closed_receipt_id",
        "closed_receipt_sha256",
        "closure_artifact_digest",
        "closure_artifact_raw_zip_sha256",
        "closure_artifact_member_inventory_sha256",
        "closure_manifest_sha256",
        "release_evidence_sha256",
        "receipt_chain_sha256",
        "provider_response_sha256",
        "provider_observation_sha256",
        "controller_action_bundle_sha256",
    )
    contract.positive_fields(
        payload,
        "closure_artifact_id",
        "controller_run_id",
        "controller_run_attempt",
        "controller_workflow_id",
    )
    contract.bounded_int(
        payload["closure_artifact_size_bytes"],
        1,
        closure_inventory.MAX_ARCHIVE_BYTES,
        "closure_artifact_size_bytes",
    )
    contract.bounded_int(
        payload["closure_artifact_expanded_bytes"],
        1,
        closure_inventory.MAX_TOTAL_BYTES,
        "closure_artifact_expanded_bytes",
    )
    _artifact_name(payload)
    members = closure_inventory.validate(payload["closure_artifact_member_inventory"])
    if (
        closure_inventory.digest(members)
        != payload["closure_artifact_member_inventory_sha256"]
        or sum(member["size_bytes"] for member in members)
        != payload["closure_artifact_expanded_bytes"]
    ):
        raise contract.ReceiptValidationError("closure member inventory mismatch")
    expected_member_digests = {
        closure_inventory.CLOSED_RECEIPT_PATH: payload["closed_receipt_sha256"],
        closure_inventory.RECEIPT_CHAIN_PATH: payload["receipt_chain_sha256"],
        closure_inventory.RELEASE_EVIDENCE_PATH: payload["release_evidence_sha256"],
        closure_inventory.MANIFEST_PATH: payload["closure_manifest_sha256"],
    }
    if any(
        member["sha256"] != expected_member_digests[member["path"]]
        for member in members
    ):
        raise contract.ReceiptValidationError("closure member digest binding mismatch")
    consumption.validate_outcome(payload)
    if payload["closure_artifact_digest"] != payload["closure_artifact_raw_zip_sha256"]:
        raise contract.ReceiptValidationError(
            "closure provider/raw ZIP digest mismatch"
        )
    _tag_binding(payload)
    contract.git_sha(payload["controller_workflow_sha"], "controller_workflow_sha")
    _action_binding(payload)
    contract.ordered_timestamps(
        payload["artifact_created_at"],
        payload["artifact_expires_at"],
        "artifact_created_at",
        "artifact_expires_at",
    )
    return contract.PayloadSemantics("authorization", True, _SERVICE)


def validate_closed_check(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Validate projection or provider re-observation of the CLOSED check."""

    transition = contract.enum(
        payload.get("transition"), {"PROJECTED", "VERIFIED"}, "transition"
    )
    extra = (
        {"provider_response_sha256", "projected_at", *consumption.OUTCOME_KEYS}
        if transition == "PROJECTED"
        else {"provider_observation_sha256", "verified_at"}
    )
    contract.exact_keys(
        payload,
        _CHECK_COMMON | extra,
        f"CLOSED_CHECK_TRANSITION {transition} payload",
    )
    _constants(
        payload,
        kind="CLOSED_CHECK_TRANSITION",
        state=(
            "CLOSED_CHECK_PROJECTED"
            if transition == "PROJECTED"
            else "CLOSED_CHECK_VERIFIED"
        ),
        check_name=_CHECK_NAME,
        check_status="completed",
        check_conclusion="success",
        output_marker_schema=_MARKER_SCHEMA,
        output_title=marker_contract.OUTPUT_TITLE,
        provider_api_version=_API_VERSION,
    )
    _artifact_name(payload)
    contract.digest_fields(
        payload,
        "authorization_id",
        "release_identity_id",
        "release_authority_id",
        "candidate_id",
        "closed_receipt_id",
        "closed_receipt_sha256",
        "closure_artifact_digest",
        "closure_artifact_member_inventory_sha256",
        "closure_manifest_sha256",
        "release_evidence_sha256",
        "receipt_chain_sha256",
        "closed_marker_sha256",
        "output_marker_sha256",
        "output_summary_sha256",
    )
    proof_field = (
        "provider_response_sha256"
        if transition == "PROJECTED"
        else "provider_observation_sha256"
    )
    contract.digest(payload[proof_field], proof_field)
    contract.positive_fields(
        payload,
        "closure_artifact_id",
        "check_app_id",
        "check_installation_id",
        "check_run_id",
        "controller_run_id",
        "controller_run_attempt",
        "controller_workflow_id",
    )
    _tag_binding(payload)
    contract.git_sha(payload["controller_workflow_sha"], "controller_workflow_sha")
    _action_binding(payload)
    contract.git_sha(payload["check_head_sha"], "check_head_sha")
    if payload["check_head_sha"] != payload["peeled_commit_sha"]:
        raise contract.ReceiptValidationError("closed check head SHA mismatch")
    expected_external_id = (
        "dpone-release-controller.closed.v1|"
        f"{payload['release_identity_id']}|"
        f"{payload['controller_run_id']}|{payload['controller_run_attempt']}"
    )
    if payload["external_id"] != expected_external_id:
        raise contract.ReceiptValidationError("closed check external_id mismatch")
    if payload["output_marker_sha256"] != payload["closed_marker_sha256"]:
        raise contract.ReceiptValidationError("closed check marker digest mismatch")
    marker = contract.mapping(payload["output_marker"], "output_marker")
    marker_contract.verify(marker)
    if marker_contract.sha256(marker) != payload["output_marker_sha256"]:
        raise contract.ReceiptValidationError("closed check marker bytes mismatch")
    summary_digest = (
        "sha256:"
        + hashlib.sha256(marker_contract.summary(marker).encode("ascii")).hexdigest()
    )
    if summary_digest != payload["output_summary_sha256"]:
        raise contract.ReceiptValidationError("closed check summary digest mismatch")
    _marker_binding(payload, marker)
    if transition == "PROJECTED":
        consumption.validate_outcome(payload)
    observed_at = "projected_at" if transition == "PROJECTED" else "verified_at"
    contract.timestamp(payload[observed_at], observed_at)
    return contract.PayloadSemantics("authorization", True, _SERVICE)


def _marker_binding(payload: Mapping[str, Any], marker: Mapping[str, Any]) -> None:
    expected = {
        "tag": payload["tag"],
        "tag_object_sha": payload["tag_object_sha"],
        "peeled_commit_sha": payload["peeled_commit_sha"],
        "release_identity_id": payload["release_identity_id"],
        "release_authority_id": payload["release_authority_id"],
        "candidate_id": payload["candidate_id"],
        "controller_workflow_id": payload["controller_workflow_id"],
        "controller_workflow_sha": payload["controller_workflow_sha"],
        "controller_action_commit_sha": payload["controller_action_commit_sha"],
        "controller_action_metadata_blob_sha": payload[
            "controller_action_metadata_blob_sha"
        ],
        "controller_action_bundle_sha256": payload["controller_action_bundle_sha256"],
        "controller_run_id": payload["controller_run_id"],
        "controller_run_attempt": payload["controller_run_attempt"],
        "closed_receipt_id": payload["closed_receipt_id"],
        "closed_receipt_sha256": payload["closed_receipt_sha256"],
        "evidence_artifact_id": payload["closure_artifact_id"],
        "evidence_artifact_name": payload["closure_artifact_name"],
        "evidence_artifact_digest": payload["closure_artifact_digest"],
        "evidence_artifact_member_inventory_sha256": payload[
            "closure_artifact_member_inventory_sha256"
        ],
        "closure_manifest_sha256": payload["closure_manifest_sha256"],
        "release_evidence_sha256": payload["release_evidence_sha256"],
        "receipt_chain_sha256": payload["receipt_chain_sha256"],
    }
    if any(marker[key] != value for key, value in expected.items()):
        raise contract.ReceiptValidationError("closed marker/check binding mismatch")


def _tag_binding(payload: Mapping[str, Any]) -> None:
    contract.stable_tag(payload["tag"])
    contract.git_sha(payload["tag_object_sha"], "tag_object_sha")
    contract.git_sha(payload["peeled_commit_sha"], "peeled_commit_sha")
    if payload["tag_object_sha"] == payload["peeled_commit_sha"]:
        raise contract.ReceiptValidationError("closure tag must be annotated")


def _action_binding(payload: Mapping[str, Any]) -> None:
    contract.git_sha(
        payload["controller_action_commit_sha"], "controller_action_commit_sha"
    )
    contract.git_sha(
        payload["controller_action_metadata_blob_sha"],
        "controller_action_metadata_blob_sha",
    )
    contract.digest(
        payload["controller_action_bundle_sha256"],
        "controller_action_bundle_sha256",
    )
    if payload["controller_action_commit_sha"] == payload["controller_workflow_sha"]:
        raise contract.ReceiptValidationError(
            "Commit A must differ from workflow Commit P"
        )


def _artifact_name(payload: Mapping[str, Any]) -> None:
    expected = _ARTIFACT_NAME_TEMPLATE.format(
        run_id=payload["controller_run_id"],
        run_attempt=payload["controller_run_attempt"],
    )
    if payload["closure_artifact_name"] != expected:
        raise contract.ReceiptValidationError("closure artifact name mismatch")


def _constants(payload: Mapping[str, Any], **expected: Any) -> None:
    for key, value in expected.items():
        if payload[key] != value or type(payload[key]) is not type(value):
            raise contract.ReceiptValidationError(f"{key} must be exactly {value!r}")
