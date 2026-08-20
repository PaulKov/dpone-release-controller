"""Derive exact mutation-intent subjects from closed provider outcomes."""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract


def operation(payload: Mapping[str, Any]) -> str | None:
    """Return the sole intent operation consumed by ``payload``, if any."""

    kind = payload["kind"]
    if kind == "ATTESTATION_VERIFIED":
        return "ATTESTATION_CREATE"
    if kind == "DRAFT_TRANSITION":
        return {
            "CREATED": "GITHUB_DRAFT_CREATE",
            "ASSET_UPLOADED": "GITHUB_DRAFT_ASSET_UPLOAD",
            "STAGED": "GITHUB_DRAFT_UPDATE",
            "VERIFIED": None,
        }[payload["transition"]]
    if kind == "PYPI_GATE_APPROVED":
        return "PYPI_DEPLOYMENT_APPROVE"
    if kind == "PYPI_GATE_REJECTED":
        return "PYPI_DEPLOYMENT_REJECT"
    if kind == "PYPI_GATE_CALLBACK_AMBIGUOUS":
        return {
            "APPROVE": "PYPI_DEPLOYMENT_APPROVE",
            "REJECT": "PYPI_DEPLOYMENT_REJECT",
        }[payload["attempted_decision"]]
    if kind == "GITHUB_RELEASE_TRANSITION":
        return (
            "GITHUB_RELEASE_PUBLISH"
            if payload["transition"] == "PUBLISH_ACCEPTED"
            else None
        )
    if kind == "PYPI_UPLOAD_SET_OBSERVED":
        return "PYPI_FILE_UPLOAD_SET"
    return None


def subject(payload: Mapping[str, Any], operation_name: str) -> dict[str, Any]:
    """Project an outcome onto the immutable subject admitted by its intent."""

    builders = {
        "ATTESTATION_CREATE": _attestation,
        "GITHUB_DRAFT_CREATE": _draft_create,
        "GITHUB_DRAFT_ASSET_UPLOAD": _draft_asset,
        "GITHUB_DRAFT_UPDATE": _draft_update,
        "PYPI_DEPLOYMENT_APPROVE": deployment_subject,
        "PYPI_DEPLOYMENT_REJECT": deployment_subject,
        "GITHUB_RELEASE_PUBLISH": _release_publish,
        "PYPI_FILE_UPLOAD_SET": _pypi_upload_set,
    }
    try:
        return builders[operation_name](payload)
    except KeyError as exc:
        raise contract.ReceiptValidationError(
            "unsupported mutation outcome operation"
        ) from exc


def deployment_subject(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Bind a gate request/outcome to the exact eight-file publish authority."""

    return _select(
        payload,
        (
            "authorization_id",
            "candidate_id",
            "gate_request_id",
            "gate_request_provider_observation_sha256",
            "tag",
            "ref",
            "deployment_id",
            "environment_name",
            "environment_id",
            "protection_rule_id",
            "gate_app_id",
            "gate_installation_id",
            "app_slug",
            "controller_repository_id",
            "controller_workflow_id",
            "controller_workflow_sha",
            "controller_run_id",
            "controller_run_attempt",
            "expected_file_count",
            "expected_file_inventory_sha256",
        ),
    )


def _attestation(payload: Mapping[str, Any]) -> dict[str, Any]:
    return _select(payload, ("candidate_id", "subject_manifest_sha256"))


def _draft_create(payload: Mapping[str, Any]) -> dict[str, Any]:
    return _select(payload, ("candidate_id", "tag", "release_body_sha256"))


def _draft_asset(payload: Mapping[str, Any]) -> dict[str, Any]:
    asset = contract.mapping(payload["asset"], "asset")
    return {
        "candidate_id": payload["candidate_id"],
        "release_id": payload["release_id"],
        "name": asset["name"],
        "size_bytes": asset["size_bytes"],
        "sha256": asset["sha256"],
    }


def _draft_update(payload: Mapping[str, Any]) -> dict[str, Any]:
    return _select(
        payload,
        (
            "candidate_id",
            "release_id",
            "release_body_sha256",
            "assets_sha256",
        ),
        renames={"assets_sha256": "asset_inventory_sha256"},
    )


def _release_publish(payload: Mapping[str, Any]) -> dict[str, Any]:
    return _select(
        payload,
        (
            "authorization_id",
            "release_id",
            "release_body_sha256",
            "public_bundle_manifest_sha256",
            "asset_inventory_sha256",
        ),
    )


def _pypi_upload_set(payload: Mapping[str, Any]) -> dict[str, Any]:
    return _select(
        payload,
        (
            "authorization_id",
            "candidate_id",
            "deployment_id",
            "environment_id",
            "candidate_file_inventory_sha256",
            "upload_file_count",
            "upload_file_inventory",
            "upload_file_inventory_sha256",
        ),
    )


def _select(
    payload: Mapping[str, Any],
    keys: tuple[str, ...],
    *,
    renames: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    names = renames or {}
    return {names.get(key, key): payload[key] for key in keys}
