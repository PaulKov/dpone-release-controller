"""Immutable GitHub release transition payload validation."""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_receipt_consumption as consumption
from tools.evidence import release_receipt_contract as contract

SERVICE_PRODUCERS = frozenset({"trusted_controller_service"})


def validate(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Validate mutation outcome or independent immutable-release requery."""

    transition = contract.enum(
        payload.get("transition"),
        {"PUBLISH_ACCEPTED", "IMMUTABLE_VERIFIED"},
        "transition",
    )
    if transition == "PUBLISH_ACCEPTED":
        _accepted(payload)
    else:
        _immutable(payload)
    return contract.PayloadSemantics("authorization", True, SERVICE_PRODUCERS)


def _accepted(payload: Mapping[str, Any]) -> None:
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "transition",
            "authorization_id",
            "release_id",
            "tag",
            "release_body_sha256",
            "public_bundle_manifest_sha256",
            "asset_inventory_sha256",
            "provider_response_sha256",
            *consumption.OUTCOME_KEYS,
        },
        "GITHUB_RELEASE_TRANSITION PUBLISH_ACCEPTED payload",
    )
    _constant(payload, "kind", "GITHUB_RELEASE_TRANSITION")
    _constant(payload, "state", "GITHUB_RELEASE_PUBLISHING")
    contract.digest_fields(
        payload,
        "authorization_id",
        "release_body_sha256",
        "public_bundle_manifest_sha256",
        "asset_inventory_sha256",
        "provider_response_sha256",
    )
    consumption.validate_outcome(payload)
    contract.positive_int(payload["release_id"], "release_id")
    contract.stable_tag(payload["tag"])


def _immutable(payload: Mapping[str, Any]) -> None:
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "transition",
            "authorization_id",
            "release_id",
            "tag",
            "public_bundle_manifest_sha256",
            "draft",
            "prerelease",
            "immutable",
            "release_body_sha256",
            "assets_sha256",
            "asset_count",
            "release_integrity_receipt_sha256",
            "verified_asset_count",
            "tag_object_sha",
            "peeled_commit_sha",
            "provider_observation_sha256",
        },
        "GITHUB_RELEASE_TRANSITION IMMUTABLE_VERIFIED payload",
    )
    expected = {
        "kind": "GITHUB_RELEASE_TRANSITION",
        "state": "GITHUB_IMMUTABLE_PUBLISHED",
        "transition": "IMMUTABLE_VERIFIED",
        "draft": False,
        "prerelease": False,
        "immutable": True,
    }
    for key, value in expected.items():
        _constant(payload, key, value)
    contract.digest_fields(
        payload,
        "authorization_id",
        "public_bundle_manifest_sha256",
        "release_body_sha256",
        "assets_sha256",
        "release_integrity_receipt_sha256",
        "provider_observation_sha256",
    )
    contract.positive_fields(
        payload, "release_id", "asset_count", "verified_asset_count"
    )
    if payload["asset_count"] != payload["verified_asset_count"]:
        raise contract.ReceiptValidationError("every GitHub asset must be verified")
    contract.stable_tag(payload["tag"])
    contract.git_sha(payload["tag_object_sha"], "tag_object_sha")
    contract.git_sha(payload["peeled_commit_sha"], "peeled_commit_sha")
    if payload["tag_object_sha"] == payload["peeled_commit_sha"]:
        raise contract.ReceiptValidationError("GitHub release tag must be annotated")


def _constant(payload: Mapping[str, Any], key: str, expected: Any) -> None:
    if payload[key] != expected or type(payload[key]) is not type(expected):
        raise contract.ReceiptValidationError(f"{key} must be exactly {expected!r}")
