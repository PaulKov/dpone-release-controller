"""INTERNAL/CONFIDENTIAL private-ledger marker; NOT PUBLICATION data."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence.release_canonical import canonical_json_bytes

SCHEMA = "dpone.release-controller-closed-check.v1"
SCHEMA_VERSION = 1
TARGET_REPOSITORY_ID = 1_255_975_556
OUTPUT_TITLE = "dpone release controller CLOSED / PASS / GO"
SUMMARY_PREFIX = "DPONE_RELEASE_CONTROLLER_CLOSED_V1"
_KEYS = {
    "schema",
    "schema_version",
    "target_repository_id",
    "tag",
    "tag_object_sha",
    "peeled_commit_sha",
    "release_identity_id",
    "release_authority_id",
    "candidate_id",
    "controller_repository_id",
    "controller_workflow_id",
    "controller_workflow_sha",
    "controller_action_commit_sha",
    "controller_action_metadata_blob_sha",
    "controller_action_bundle_sha256",
    "controller_run_id",
    "controller_run_attempt",
    "closed_receipt_id",
    "closed_receipt_sha256",
    "evidence_artifact_id",
    "evidence_artifact_name",
    "evidence_artifact_digest",
    "evidence_artifact_member_inventory_sha256",
    "closure_manifest_sha256",
    "release_evidence_sha256",
    "receipt_chain_sha256",
}


def build(**fields: Any) -> dict[str, Any]:
    """Build the historical private-ledger marker object."""

    marker = {"schema": SCHEMA, "schema_version": SCHEMA_VERSION, **fields}
    verify(marker)
    return marker


def verify(marker: Mapping[str, Any]) -> None:
    """Validate the private marker without authorizing public projection."""

    contract.exact_keys(marker, _KEYS, "private CLOSED marker")
    expected = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "target_repository_id": TARGET_REPOSITORY_ID,
        "controller_repository_id": contract.CONTROLLER_REPOSITORY_ID,
    }
    for key, value in expected.items():
        if marker[key] != value or type(marker[key]) is not type(value):
            raise contract.ReceiptValidationError(f"marker {key} mismatch")
    contract.positive_fields(
        marker,
        "target_repository_id",
        "controller_repository_id",
        "controller_workflow_id",
        "controller_run_id",
        "controller_run_attempt",
        "evidence_artifact_id",
    )
    contract.stable_tag(marker["tag"])
    contract.git_sha(marker["tag_object_sha"], "marker.tag_object_sha")
    contract.git_sha(marker["peeled_commit_sha"], "marker.peeled_commit_sha")
    contract.git_sha(
        marker["controller_workflow_sha"], "marker.controller_workflow_sha"
    )
    contract.git_sha(
        marker["controller_action_commit_sha"],
        "marker.controller_action_commit_sha",
    )
    contract.git_sha(
        marker["controller_action_metadata_blob_sha"],
        "marker.controller_action_metadata_blob_sha",
    )
    contract.digest_fields(
        marker,
        "release_identity_id",
        "release_authority_id",
        "candidate_id",
        "closed_receipt_id",
        "closed_receipt_sha256",
        "evidence_artifact_digest",
        "evidence_artifact_member_inventory_sha256",
        "closure_manifest_sha256",
        "release_evidence_sha256",
        "receipt_chain_sha256",
        "controller_action_bundle_sha256",
    )
    if marker["controller_action_commit_sha"] == marker["controller_workflow_sha"]:
        raise contract.ReceiptValidationError(
            "marker Commit A must differ from workflow Commit P"
        )
    if marker["tag_object_sha"] == marker["peeled_commit_sha"]:
        raise contract.ReceiptValidationError("marker tag must be annotated")
    expected_name = (
        "release-controller-closure-"
        f"{marker['controller_run_id']}-{marker['controller_run_attempt']}"
    )
    if marker["evidence_artifact_name"] != expected_name:
        raise contract.ReceiptValidationError("marker artifact name mismatch")


def encode(marker: Mapping[str, Any]) -> bytes:
    """Return canonical private marker bytes for ledger fixture validation."""

    verify(marker)
    return canonical_json_bytes(marker)


def sha256(marker: Mapping[str, Any]) -> str:
    """Return the private marker digest bound by historical receipts."""

    return "sha256:" + hashlib.sha256(encode(marker)).hexdigest()


def summary(marker: Mapping[str, Any]) -> str:
    """Encode the historical marker summary for private receipt fixtures."""

    payload = base64.urlsafe_b64encode(encode(marker)).decode().rstrip("=")
    return f"{SUMMARY_PREFIX} {payload}"


def decode_summary(value: str) -> Mapping[str, Any]:
    """Decode the historical private marker; this grants no public authority."""

    prefix = f"{SUMMARY_PREFIX} "
    if "\n" in value or not value.startswith(prefix):
        raise contract.ReceiptValidationError("CLOSED check summary format mismatch")
    encoded = value.removeprefix(prefix)
    if not encoded or "=" in encoded:
        raise contract.ReceiptValidationError("CLOSED marker base64url mismatch")
    padding = "=" * (-len(encoded) % 4)
    try:
        raw = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
    except ValueError as exc:
        raise contract.ReceiptValidationError(
            "invalid CLOSED marker base64url"
        ) from exc
    try:
        marker = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise contract.ReceiptValidationError("invalid CLOSED marker JSON") from exc
    if raw != canonical_json_bytes(marker):
        raise contract.ReceiptValidationError("CLOSED marker is not canonical JSON")
    verify(marker)
    return marker
