"""Publication payload fixtures for receipt v2."""

from __future__ import annotations

from typing import Any

from tests import release_receipt_fixtures as base

from tests.release_receipt_fixtures import (
    AUTHORIZATION_ID,
    CANDIDATE_ID,
    LEASE_ID,
    RECOVERY_ID,
    TAG,
    TAG_OBJECT_SHA,
    VERSION,
    COMMIT_SHA,
    digest,
)
from tests import release_receipt_intent_fixtures as intent_fixture
from tools.evidence import release_receipt_inventory as inventory
from tools.evidence import release_composite_observation as composite_observation


def authorized() -> dict[str, Any]:
    return {
        "kind": "AUTHORIZED",
        "state": "AUTHORIZED",
        "authorization_state": "AUTHORIZED",
        "authorization_id": AUTHORIZATION_ID,
        "candidate_id": CANDIDATE_ID,
        "public_bundle_id": digest("bundle id"),
        "public_bundle_manifest_sha256": digest("bundle manifest"),
        "snapshot_a_sha256": digest("snapshot-A"),
        "snapshot_b_sha256": digest("snapshot-B"),
        "lease_id": LEASE_ID,
        "fencing_token": 3,
        "expires_at": "2026-08-15T00:05:45Z",
        "blockers": [],
    }


def pypi(transition: str, *, verified_count: int = 0) -> dict[str, Any]:
    filename = "dpone-0.74.0-py3-none-any.whl"
    file_digest = digest("pypi file")
    payload: dict[str, Any] = {
        "kind": "PYPI_FILE_TRANSITION",
        "state": "PYPI_PUBLISHING",
        "transition": transition,
        "authorization_id": AUTHORIZATION_ID,
        "candidate_id": CANDIDATE_ID,
        "project": "dpone",
        "version": VERSION,
        "filename": filename,
        "size_bytes": 10,
        "sha256": file_digest,
        "yanked": False,
        "provider_observation_sha256": digest(f"pypi observation {transition}"),
    }
    if transition == "SEALED_FOR_UPLOAD":
        payload["upload_subset_sha256"] = inventory.inventory_sha256(
            inventory.DISTRIBUTION_SCHEMA,
            base._distributions(),
        )
    elif transition in {"ALREADY_PUBLISHED_EXACT", "INTEGRITY_VERIFIED"}:
        payload["state"] = (
            "PYPI_VERIFIED" if verified_count == 8 else "PYPI_PARTIAL_EXACT"
        )
        payload["verified_file_count"] = verified_count
        payload["expected_file_count"] = 8
        payload["integrity"] = _integrity(filename, file_digest)
    elif transition == "CONFLICT":
        payload["state"] = "PYPI_CONFLICT"
        payload["conflict_reason"] = "DIGEST_MISMATCH"
        payload["conflict_evidence_sha256"] = digest("pypi conflict")
    return payload


def github(transition: str) -> dict[str, Any]:
    if transition == "PUBLISH_ACCEPTED":
        return {
            "kind": "GITHUB_RELEASE_TRANSITION",
            "state": "GITHUB_RELEASE_PUBLISHING",
            "transition": transition,
            "authorization_id": AUTHORIZATION_ID,
            "release_id": 5_000_000_001,
            "tag": TAG,
            "release_body_sha256": digest("body"),
            "public_bundle_manifest_sha256": digest("bundle manifest"),
            "asset_inventory_sha256": inventory.inventory_sha256(
                inventory.GITHUB_ASSET_SCHEMA,
                base._release_assets(),
            ),
            "provider_response_sha256": digest("publish response"),
            **intent_fixture.consumption("GITHUB_RELEASE_PUBLISH"),
        }
    return {
        "kind": "GITHUB_RELEASE_TRANSITION",
        "state": "GITHUB_IMMUTABLE_PUBLISHED",
        "transition": "IMMUTABLE_VERIFIED",
        "authorization_id": AUTHORIZATION_ID,
        "release_id": 5_000_000_001,
        "tag": TAG,
        "public_bundle_manifest_sha256": digest("bundle manifest"),
        "draft": False,
        "prerelease": False,
        "immutable": True,
        "release_body_sha256": digest("body"),
        "assets_sha256": inventory.inventory_sha256(
            inventory.GITHUB_ASSET_SCHEMA, base._release_assets()
        ),
        "asset_count": 17,
        "release_integrity_receipt_sha256": digest("release integrity"),
        "verified_asset_count": 17,
        "tag_object_sha": TAG_OBJECT_SHA,
        "peeled_commit_sha": COMMIT_SHA,
        "provider_observation_sha256": digest("immutable observation"),
    }


def upload_set(
    status: str = "COMPLETE",
    *,
    upload_files: list[dict[str, Any]] | None = None,
    accepted_files: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    uploaded = list(upload_files or base._distributions())
    accepted = list(uploaded if accepted_files is None else accepted_files)
    intent = intent_fixture.intent("PYPI_FILE_UPLOAD_SET", upload_files=uploaded)
    payload = {
        "kind": "PYPI_UPLOAD_SET_OBSERVED",
        "state": (
            "PYPI_UPLOAD_SET_COMPLETE" if status == "COMPLETE" else "RECOVERY_REQUIRED"
        ),
        "status": status,
        **intent["subject"],
        "accepted_file_count": len(accepted),
        "accepted_file_inventory": accepted,
        "accepted_file_inventory_sha256": inventory.inventory_sha256(
            inventory.DISTRIBUTION_SCHEMA, accepted
        ),
        "provider_response_sha256": digest(f"PyPI upload response/{status}"),
        "provider_observation_sha256": digest(f"PyPI upload observation/{status}"),
        "provider_api_version": "pypi-integrity-v1",
        "observed_at": "2026-08-15T00:02:40Z",
        **intent_fixture.consumption("PYPI_FILE_UPLOAD_SET", upload_files=uploaded),
    }
    if status != "COMPLETE":
        payload["recovery_id"] = RECOVERY_ID
    return payload


def cancellation(external: bool) -> dict[str, Any]:
    github_observation = digest(f"cancellation GitHub/{external}")
    pypi_observation = digest(f"cancellation PyPI/{external}")
    payload: dict[str, Any] = {
        "kind": "CANCELLATION",
        "state": "RECOVERY_REQUIRED" if external else "CANCELLED",
        "cancellation_id": digest(f"cancellation-{external}"),
        "reason_code": "USER_REQUESTED",
        "external_commit_observed": external,
        "cancelled_at": "2026-08-15T00:03:00Z",
        "github_provider_observation_sha256": github_observation,
        "github_provider_api_version": "2026-03-10",
        "pypi_provider_observation_sha256": pypi_observation,
        "pypi_provider_api_version": "pypi-integrity-v1",
        "provider_observation_sha256": composite_observation.digest(
            github_observation, pypi_observation
        ),
        "external_commit_provider": "GITHUB" if external else "NONE",
    }
    if external:
        payload["recovery_id"] = RECOVERY_ID
    return payload


def _integrity(filename: str, file_digest: str) -> dict[str, Any]:
    return {
        "media_type": "application/vnd.pypi.integrity.v1+json",
        "api_path": f"/integrity/dpone/{VERSION}/{filename}/provenance",
        "accept": "application/vnd.pypi.integrity.v1+json",
        "file_url": f"https://files.pythonhosted.org/packages/aa/bb/{filename}",
        "provenance_sha256": digest("provenance"),
        "publisher_kind": "GitHub",
        "publisher_owner": "PaulKov",
        "publisher_repository": "dpone-release-controller",
        "publisher_workflow": "release-controller.yml",
        "publisher_environment": "pypi",
        "predicate_type": "https://docs.pypi.org/attestations/publish/v1",
        "repository_identity": ("https://github.com/PaulKov/dpone-release-controller"),
        "verifier": "pypi-attestations verify pypi",
        "verifier_version": "pypi-attestations-0.0.30",
        "verification_result": "VERIFIED",
        "subject_sha256": file_digest,
        "sigstore_bundle_sha256": digest("sigstore bundle"),
        "certificate_chain_sha256": digest("certificate chain"),
        "certificate_serial": "01ABCDEF",
        "transparency_entry_sha256": digest("rekor entry"),
        "rekor_log_index": 123456,
        "rekor_uuid": "rekor-01HXDPONE",
        "cryptographically_verified": True,
    }
