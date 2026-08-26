"""Closed GitHub draft creation, asset, staging, and requery receipts."""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_consumption as consumption


def validate(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    transition = contract.enum(
        payload.get("transition"),
        {"CREATED", "ASSET_UPLOADED", "STAGED", "VERIFIED"},
        "transition",
    )
    {
        "CREATED": _created,
        "ASSET_UPLOADED": _asset,
        "STAGED": _inventory,
        "VERIFIED": _inventory,
    }[transition](payload)
    return contract.PayloadSemantics(
        "candidate", True, frozenset({"trusted_controller_service"})
    )


def _created(payload: Mapping[str, Any]) -> None:
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "transition",
            "release_id",
            "candidate_id",
            "tag",
            "release_body_sha256",
            "public_bundle_manifest_sha256",
            "draft",
            "prerelease",
            "immutable",
            "provider_response_sha256",
            *consumption.OUTCOME_KEYS,
        },
        "DRAFT_TRANSITION CREATED payload",
    )
    _constants(
        payload,
        kind="DRAFT_TRANSITION",
        state="DRAFT_CREATED",
        transition="CREATED",
        draft=True,
        prerelease=False,
        immutable=False,
    )
    _common(payload)
    contract.digest_fields(payload, "release_body_sha256", "provider_response_sha256")
    consumption.validate_outcome(payload)


def _asset(payload: Mapping[str, Any]) -> None:
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "transition",
            "release_id",
            "candidate_id",
            "tag",
            "public_bundle_manifest_sha256",
            "asset",
            "provider_response_sha256",
            *consumption.OUTCOME_KEYS,
        },
        "DRAFT_TRANSITION ASSET_UPLOADED payload",
    )
    _constants(
        payload,
        kind="DRAFT_TRANSITION",
        state="DRAFT_STAGING",
        transition="ASSET_UPLOADED",
    )
    _common(payload)
    contract.digest(payload["provider_response_sha256"], "provider_response_sha256")
    asset = contract.mapping(payload["asset"], "asset")
    contract.exact_keys(
        asset, {"asset_id", "name", "size_bytes", "sha256", "state"}, "draft asset"
    )
    contract.positive_fields(asset, "asset_id", "size_bytes")
    contract.filename(asset["name"], "asset.name")
    contract.digest(asset["sha256"], "asset.sha256")
    _constants(asset, state="uploaded")
    consumption.validate_outcome(payload)


def _inventory(payload: Mapping[str, Any]) -> None:
    transition = payload["transition"]
    consumption_keys = (
        consumption.OUTCOME_KEYS if transition == "STAGED" else frozenset()
    )
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "transition",
            "release_id",
            "candidate_id",
            "tag",
            "release_body_sha256",
            "public_bundle_manifest_sha256",
            "asset_count",
            "assets_sha256",
            "draft",
            "prerelease",
            "immutable",
            "provider_observation_sha256",
            *consumption_keys,
        },
        f"DRAFT_TRANSITION {transition} payload",
    )
    _constants(
        payload,
        kind="DRAFT_TRANSITION",
        state="DRAFT_STAGED" if transition == "STAGED" else "DRAFT_VERIFIED",
        draft=True,
        prerelease=False,
        immutable=False,
    )
    _common(payload)
    contract.positive_int(payload["asset_count"], "asset_count")
    contract.digest_fields(
        payload,
        "release_body_sha256",
        "assets_sha256",
        "provider_observation_sha256",
    )
    if transition == "STAGED":
        consumption.validate_outcome(payload)


def _common(payload: Mapping[str, Any]) -> None:
    contract.positive_int(payload["release_id"], "release_id")
    contract.digest_fields(payload, "candidate_id", "public_bundle_manifest_sha256")
    contract.stable_tag(payload["tag"])


def _constants(payload: Mapping[str, Any], **expected: Any) -> None:
    for key, value in expected.items():
        if payload[key] != value or type(payload[key]) is not type(value):
            raise contract.ReceiptValidationError(f"{key} must be exactly {value!r}")
