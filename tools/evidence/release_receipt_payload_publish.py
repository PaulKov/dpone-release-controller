"""Closed per-file PyPI Integrity and immutable GitHub publication payloads."""

from __future__ import annotations

import urllib.parse
from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_consumption as consumption
from tools.evidence import release_receipt_inventory as inventory
from tools.evidence import release_receipt_payload_github_publish as github_publish

_JOB = frozenset({"github_actions_job"})
_SERVICE = frozenset({"trusted_controller_service"})
_PYPI_TRANSITIONS = {
    "PENDING_UPLOAD",
    "SEALED_FOR_UPLOAD",
    "ALREADY_PUBLISHED_EXACT",
    "INTEGRITY_VERIFIED",
    "CONFLICT",
}
_CONFLICT_REASONS = {
    "DIGEST_MISMATCH",
    "DUPLICATE_FILENAME",
    "INVALID_PROVENANCE",
    "MISSING_PROVENANCE",
    "PUBLISHER_MISMATCH",
    "SIZE_MISMATCH",
    "UNEXPECTED_FILE",
    "YANKED",
}


def validate_pypi(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    transition = contract.enum(
        payload.get("transition"), _PYPI_TRANSITIONS, "transition"
    )
    extras: set[str] = set()
    if transition == "SEALED_FOR_UPLOAD":
        extras = {"upload_subset_sha256"}
    elif transition in {"ALREADY_PUBLISHED_EXACT", "INTEGRITY_VERIFIED"}:
        extras = {"integrity", "verified_file_count", "expected_file_count"}
    elif transition == "CONFLICT":
        extras = {"conflict_reason", "conflict_evidence_sha256"}
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "transition",
            "authorization_id",
            "candidate_id",
            "project",
            "version",
            "filename",
            "size_bytes",
            "sha256",
            "yanked",
            "provider_observation_sha256",
            *extras,
        },
        f"PYPI_FILE_TRANSITION {transition} payload",
    )
    _file_identity(payload)
    if transition in {"PENDING_UPLOAD", "SEALED_FOR_UPLOAD"}:
        _constant(payload, "state", "PYPI_PUBLISHING")
    elif transition in {"ALREADY_PUBLISHED_EXACT", "INTEGRITY_VERIFIED"}:
        _verified_file(payload)
    else:
        _constant(payload, "state", "PYPI_CONFLICT")
        contract.enum(payload["conflict_reason"], _CONFLICT_REASONS, "conflict_reason")
        contract.digest(payload["conflict_evidence_sha256"], "conflict_evidence_sha256")
    if transition == "SEALED_FOR_UPLOAD":
        contract.digest(payload["upload_subset_sha256"], "upload_subset_sha256")
    producers = (
        _JOB if transition in {"PENDING_UPLOAD", "SEALED_FOR_UPLOAD"} else _SERVICE
    )
    return contract.PayloadSemantics("authorization", True, producers)


def validate_upload_set(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Validate a provider-derived observation of one consumed upload set."""

    status = contract.enum(
        payload.get("status"), {"COMPLETE", "PARTIAL", "NONE"}, "status"
    )
    recovery_keys = {"recovery_id"} if status != "COMPLETE" else set()
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "status",
            "authorization_id",
            "candidate_id",
            "deployment_id",
            "environment_id",
            "candidate_file_inventory_sha256",
            "upload_file_count",
            "upload_file_inventory",
            "upload_file_inventory_sha256",
            "accepted_file_count",
            "accepted_file_inventory",
            "accepted_file_inventory_sha256",
            "provider_response_sha256",
            "provider_observation_sha256",
            "provider_api_version",
            "observed_at",
            *consumption.OUTCOME_KEYS,
            *recovery_keys,
        },
        "PYPI_UPLOAD_SET_OBSERVED payload",
    )
    _constant(payload, "kind", "PYPI_UPLOAD_SET_OBSERVED")
    _constant(
        payload,
        "state",
        "PYPI_UPLOAD_SET_COMPLETE" if status == "COMPLETE" else "RECOVERY_REQUIRED",
    )
    contract.digest_fields(
        payload,
        "authorization_id",
        "candidate_id",
        "candidate_file_inventory_sha256",
        "upload_file_inventory_sha256",
        "accepted_file_inventory_sha256",
        "provider_response_sha256",
        "provider_observation_sha256",
    )
    if status != "COMPLETE":
        contract.digest(payload["recovery_id"], "recovery_id")
    contract.positive_fields(payload, "deployment_id", "environment_id")
    upload_count = contract.bounded_int(
        payload["upload_file_count"], 1, 8, "upload_file_count"
    )
    upload_files = inventory.distribution_subset_inventory(
        payload["upload_file_inventory"]
    )
    if len(upload_files) != upload_count:
        raise contract.ReceiptValidationError("upload file count mismatch")
    inventory.require_digest(
        payload["upload_file_inventory_sha256"],
        inventory.DISTRIBUTION_SCHEMA,
        upload_files,
        "upload_file_inventory_sha256",
    )
    accepted_count = contract.bounded_int(
        payload["accepted_file_count"], 0, upload_count, "accepted_file_count"
    )
    accepted_files = inventory.distribution_subset_inventory(
        payload["accepted_file_inventory"]
    )
    if len(accepted_files) != accepted_count:
        raise contract.ReceiptValidationError("accepted file count mismatch")
    inventory.require_digest(
        payload["accepted_file_inventory_sha256"],
        inventory.DISTRIBUTION_SCHEMA,
        accepted_files,
        "accepted_file_inventory_sha256",
    )
    if any(item not in upload_files for item in accepted_files):
        raise contract.ReceiptValidationError("accepted file is outside upload set")
    if (status == "COMPLETE") != (accepted_files == upload_files):
        raise contract.ReceiptValidationError("upload-set completion mismatch")
    if status == "PARTIAL" and not 0 < accepted_count < upload_count:
        raise contract.ReceiptValidationError("partial upload set is not partial")
    if status == "NONE" and accepted_count != 0:
        raise contract.ReceiptValidationError("empty upload set has accepted files")
    if payload["provider_api_version"] != "pypi-integrity-v1":
        raise contract.ReceiptValidationError("upload observer API version mismatch")
    contract.timestamp(payload["observed_at"], "observed_at")
    consumption.validate_outcome(payload)
    return contract.PayloadSemantics("authorization", True, _SERVICE)


def validate_github(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Validate immutable GitHub publication through the stable facade."""

    return github_publish.validate(payload)


def _file_identity(payload: Mapping[str, Any]) -> None:
    _constant(payload, "kind", "PYPI_FILE_TRANSITION")
    contract.digest_fields(
        payload,
        "authorization_id",
        "candidate_id",
        "sha256",
        "provider_observation_sha256",
    )
    contract.enum(payload["project"], set(contract.PROJECTS), "project")
    contract.stable_version(payload["version"])
    contract.filename(payload["filename"])
    inventory.require_distribution_file_size(payload["size_bytes"], "size_bytes")
    if contract.boolean(payload["yanked"], "yanked") is not False:
        raise contract.ReceiptValidationError("PyPI exact file must not be yanked")


def _verified_file(payload: Mapping[str, Any]) -> None:
    expected = payload["expected_file_count"]
    verified = payload["verified_file_count"]
    if type(expected) is not int or expected != 8:
        raise contract.ReceiptValidationError("expected_file_count must be 8")
    contract.bounded_int(verified, 1, expected, "verified_file_count")
    expected_state = "PYPI_VERIFIED" if verified == expected else "PYPI_PARTIAL_EXACT"
    _constant(payload, "state", expected_state)
    integrity = contract.mapping(payload["integrity"], "integrity")
    contract.exact_keys(
        integrity,
        {
            "media_type",
            "api_path",
            "accept",
            "file_url",
            "provenance_sha256",
            "publisher_kind",
            "publisher_owner",
            "publisher_repository",
            "publisher_workflow",
            "publisher_environment",
            "predicate_type",
            "repository_identity",
            "verifier",
            "verifier_version",
            "verification_result",
            "subject_sha256",
            "sigstore_bundle_sha256",
            "certificate_chain_sha256",
            "certificate_serial",
            "transparency_entry_sha256",
            "rekor_log_index",
            "rekor_uuid",
            "cryptographically_verified",
        },
        "PyPI Integrity proof",
    )
    expected_constants = {
        "media_type": "application/vnd.pypi.integrity.v1+json",
        "accept": "application/vnd.pypi.integrity.v1+json",
        "publisher_kind": "GitHub",
        "publisher_owner": "PaulKov",
        "publisher_repository": "dpone-release-controller",
        "publisher_workflow": "release-controller.yml",
        "publisher_environment": "pypi",
        "predicate_type": "https://docs.pypi.org/attestations/publish/v1",
        "repository_identity": ("https://github.com/PaulKov/dpone-release-controller"),
        "verifier": "pypi-attestations verify pypi",
        "verification_result": "VERIFIED",
        "cryptographically_verified": True,
    }
    for key, value in expected_constants.items():
        _constant(integrity, key, value)
    contract.digest_fields(
        integrity,
        "provenance_sha256",
        "subject_sha256",
        "sigstore_bundle_sha256",
        "certificate_chain_sha256",
        "transparency_entry_sha256",
    )
    expected_path = (
        f"/integrity/{payload['project']}/{payload['version']}/"
        f"{payload['filename']}/provenance"
    )
    if integrity["api_path"] != expected_path:
        raise contract.ReceiptValidationError("PyPI Integrity API path mismatch")
    parsed_url = urllib.parse.urlsplit(integrity["file_url"])
    if (
        parsed_url.scheme != "https"
        or parsed_url.hostname != "files.pythonhosted.org"
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.port not in {None, 443}
        or not parsed_url.path.endswith(f"/{payload['filename']}")
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise contract.ReceiptValidationError("PyPI public file URL mismatch")
    contract.opaque(integrity["verifier_version"], "integrity.verifier_version")
    contract.opaque(integrity["certificate_serial"], "integrity.certificate_serial")
    contract.nonnegative_int(integrity["rekor_log_index"], "integrity.rekor_log_index")
    contract.opaque(integrity["rekor_uuid"], "integrity.rekor_uuid")
    if integrity["subject_sha256"] != payload["sha256"]:
        raise contract.ReceiptValidationError("PyPI Integrity subject digest mismatch")


def _constant(payload: Mapping[str, Any], key: str, expected: Any) -> None:
    if payload[key] != expected or type(payload[key]) is not type(expected):
        raise contract.ReceiptValidationError(f"{key} must be exactly {expected!r}")
