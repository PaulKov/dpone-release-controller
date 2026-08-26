"""Publication-specific cross-binding for the receipt-v2 chain verifier.

The functions in this module mutate only :class:`ChainState` assembled from
already verified envelopes.  Provider observations remain untrusted until the
exact candidate, public-bundle, mutation-intent, and inventory bindings below
all match.
"""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_inventory as inventory
from tools.evidence import release_identity
from tools.evidence.release_receipt_chain_gate import apply_gate as apply_gate
from tools.evidence.release_receipt_chain_state import ChainState


def apply_pypi(state: ChainState, payload: Mapping[str, Any]) -> None:
    """Apply one exact per-file PyPI transition."""

    if state.phase not in {
        "PYPI_READY",
        "PYPI_PREPARING",
        "PYPI_ACTIVE",
        "PYPI_PARTIAL",
        "PYPI_RECOVERY",
    }:
        raise contract.ReceiptValidationError("PyPI transition phase mismatch")
    _equal(payload["authorization_id"], state.authorization_id, "PyPI authorization")
    _equal(payload["candidate_id"], state.candidate_id, "PyPI candidate")
    key = (payload["project"], payload["version"], payload["filename"])
    expected_file = state.distributions.get(key)
    if expected_file is None:
        raise contract.ReceiptValidationError("unexpected PyPI distribution")
    for name in ("size_bytes", "sha256"):
        _equal(payload[name], expected_file[name], f"PyPI {name}")
    current = state.pypi_files.get(key)
    transition = payload["transition"]
    if transition == "SEALED_FOR_UPLOAD":
        _equal(
            payload["upload_subset_sha256"],
            state.distribution_inventory_sha256,
            "PyPI sealed candidate inventory",
        )
    required = {
        "PENDING_UPLOAD": None,
        "SEALED_FOR_UPLOAD": "PENDING_UPLOAD",
        "INTEGRITY_VERIFIED": "UPLOAD_ACCEPTED",
    }
    if transition in required and current != required[transition]:
        raise contract.ReceiptValidationError("per-file PyPI transition mismatch")
    if transition == "ALREADY_PUBLISHED_EXACT":
        if (
            state.phase != "PYPI_RECOVERY"
            or key not in state.recovery_pypi_exact
            or current not in {"SEALED_FOR_UPLOAD", "UPLOAD_ACCEPTED"}
        ):
            raise contract.ReceiptValidationError(
                "already-published exact lacks recovery upload authority"
            )
        state.pypi_files[key] = "INTEGRITY_VERIFIED"
        state.pypi_verified_count += 1
        if payload["verified_file_count"] != state.pypi_verified_count:
            raise contract.ReceiptValidationError("PyPI verified count mismatch")
        state.phase = (
            "PYPI_VERIFIED"
            if state.pypi_verified_count == len(state.distributions)
            else "PYPI_RECOVERY"
        )
        return
    if transition == "CONFLICT":
        state.phase = "RECOVERY_REQUIRED"
        state.pypi_files[key] = transition
        return
    state.pypi_files[key] = transition
    if transition == "PENDING_UPLOAD":
        state.phase = "PYPI_PREPARING"
        return
    if transition == "SEALED_FOR_UPLOAD":
        sealed = sum(
            value == "SEALED_FOR_UPLOAD" for value in state.pypi_files.values()
        )
        state.phase = (
            "PYPI_SEALED" if sealed == len(state.distributions) else "PYPI_PREPARING"
        )
        return
    if transition == "INTEGRITY_VERIFIED":
        state.pypi_verified_count += 1
        if payload["verified_file_count"] != state.pypi_verified_count:
            raise contract.ReceiptValidationError("PyPI verified count mismatch")
        state.phase = (
            "PYPI_VERIFIED"
            if state.pypi_verified_count == len(state.distributions)
            else "PYPI_PARTIAL"
        )
    else:
        state.phase = "PYPI_ACTIVE"


def bind_upload_intent(state: ChainState, payload: Mapping[str, Any]) -> None:
    """Require a sealed exact subset and the gate-authorized deployment."""

    subject = payload["subject"]
    _equal(
        subject["candidate_file_inventory_sha256"],
        state.distribution_inventory_sha256,
        "PyPI candidate inventory",
    )
    _equal(subject["authorization_id"], state.authorization_id, "PyPI authorization")
    _equal(subject["candidate_id"], state.candidate_id, "PyPI candidate")
    if state.gate_binding is None:
        raise contract.ReceiptValidationError("PyPI gate binding is missing")
    for key in ("deployment_id", "environment_id"):
        _equal(subject[key], state.gate_binding[key], f"PyPI upload {key}")
    upload_records = {
        (item["project"], item["version"], item["filename"]): dict(item)
        for item in subject["upload_file_inventory"]
    }
    upload_keys = set(upload_records)
    expected = {
        key
        for key, transition in state.pypi_files.items()
        if transition == "SEALED_FOR_UPLOAD" and key not in state.recovery_pypi_exact
    }
    if upload_keys != expected or not upload_keys:
        raise contract.ReceiptValidationError("PyPI upload subset mismatch")
    if any(state.distributions.get(key) != upload_records[key] for key in upload_keys):
        raise contract.ReceiptValidationError("PyPI upload candidate file mismatch")


def apply_upload_set(state: ChainState, payload: Mapping[str, Any]) -> None:
    """Apply a re-queried public provider observation, never a job assertion."""

    _equal(
        payload["candidate_file_inventory_sha256"],
        state.distribution_inventory_sha256,
        "PyPI candidate inventory",
    )
    accepted = {
        (item["project"], item["version"], item["filename"]): item
        for item in payload["accepted_file_inventory"]
    }
    for key, item in accepted.items():
        if (
            state.distributions.get(key) != item
            or state.pypi_files.get(key) != "SEALED_FOR_UPLOAD"
        ):
            raise contract.ReceiptValidationError("PyPI accepted upload mismatch")
        state.pypi_files[key] = "UPLOAD_ACCEPTED"
    if payload["status"] == "COMPLETE":
        state.phase = "PYPI_ACTIVE"
        return
    state.recovery_id = payload["recovery_id"]
    state.recovery_origin_phase = "PYPI_UPLOAD_INTENT"
    state.phase = "RECOVERY_REQUIRED"


def bind_candidate(state: ChainState, payload: Mapping[str, Any]) -> None:
    """Freeze the exact eight-file candidate inventory."""

    if (
        state.release_identity_id is None
        or state.release_authority_id is None
        or state.tag_object_sha is None
        or state.peeled_commit_sha is None
    ):
        raise contract.ReceiptValidationError(
            "candidate canonical release authority is incomplete"
        )
    expected_authority_id = release_identity.release_authority_id(
        release_identity_id=state.release_identity_id,
        tag_object_sha=state.tag_object_sha,
        peeled_commit_sha=state.peeled_commit_sha,
        policy_sha256=payload["candidate_artifact_policy_sha256"],
    )
    _equal(
        state.release_authority_id,
        expected_authority_id,
        "canonical release authority",
    )
    expected_candidate_id = release_identity.candidate_id(
        release_authority_id=state.release_authority_id,
        candidate_inventory_sha256=payload["candidate_inventory_sha256"],
    )
    _equal(payload["candidate_id"], expected_candidate_id, "canonical candidate")
    records = inventory.distribution_inventory(payload["distribution_inventory"])
    inventory.require_digest(
        payload["distribution_inventory_sha256"],
        inventory.DISTRIBUTION_SCHEMA,
        records,
        "distribution_inventory_sha256",
    )
    state.candidate_id = payload["candidate_id"]
    state.distribution_inventory_sha256 = payload["distribution_inventory_sha256"]
    state.distributions = {
        (item["project"], item["version"], item["filename"]): dict(item)
        for item in records
    }


def bind_governance(state: ChainState, payload: Mapping[str, Any]) -> None:
    """Freeze the normalized provider-policy projection across snapshots A/B/C."""

    state.snapshots[payload["label"]] = payload["snapshot_sha256"]
    keys = (
        "protected_base_sha",
        "tag",
        "tag_ref",
        "tag_object_type",
        "tag_object_sha",
        "peeled_commit_sha",
        "tag_created_by_controller",
        "tag_mutation_performed",
        "tag_ruleset_id",
        "tag_ruleset_version",
        "ruleset_projection_sha256",
        "activation_bypass_actors_sha256",
        "tag_rule_suite_count",
        "tag_rule_suite_transition_result",
        "tag_ruleset_bypass_observed",
        "required_checks_sha256",
        "actions_allowed",
        "actions_sha_pinning_required",
        "github_owned_allowed",
        "verified_allowed",
        "patterns_allowed_sha256",
        "immutable_releases_enabled",
    )
    projection = {key: payload[key] for key in keys}
    if state.governance_projection is None:
        state.governance_projection = projection
    elif projection != state.governance_projection:
        raise contract.ReceiptValidationError("governance projection drift")


def bind_bundle(state: ChainState, payload: Mapping[str, Any]) -> None:
    """Freeze the exact public GitHub asset inventory."""

    _equal(payload["candidate_id"], state.candidate_id, "bundle candidate")
    records = inventory.github_asset_inventory(
        payload["release_asset_inventory"],
        expected_count=payload["expected_asset_count"],
    )
    state.expected_assets = {item["name"]: dict(item) for item in records}
    state.expected_asset_count = len(records)
    state.expected_asset_inventory_sha256 = payload["expected_asset_inventory_sha256"]
    state.public_bundle_manifest_sha256 = payload["manifest_sha256"]


def bind_draft(state: ChainState, payload: Mapping[str, Any], event: str) -> None:
    """Cross-bind draft identity, body, and every expected asset exactly once."""

    _equal(payload["candidate_id"], state.candidate_id, "draft candidate")
    _equal(
        payload["public_bundle_manifest_sha256"],
        state.public_bundle_manifest_sha256,
        "draft bundle",
    )
    if event == "DRAFT_CREATED":
        state.draft_release_id = payload["release_id"]
        state.release_body_sha256 = payload["release_body_sha256"]
        return
    _equal(payload["release_id"], state.draft_release_id, "draft release ID")
    if event == "DRAFT_ASSET_UPLOADED":
        asset = payload["asset"]
        expected = state.expected_assets.get(asset["name"])
        if expected is None:
            raise contract.ReceiptValidationError("unexpected draft asset")
        if asset["name"] in state.draft_assets:
            raise contract.ReceiptValidationError("duplicate draft asset receipt")
        for key in ("size_bytes", "sha256"):
            _equal(asset[key], expected[key], f"draft asset {key}")
        state.draft_assets[asset["name"]] = dict(asset)
        return
    _equal(payload["release_body_sha256"], state.release_body_sha256, "draft body")
    _equal(
        payload["assets_sha256"],
        state.expected_asset_inventory_sha256,
        "draft asset inventory",
    )
    if payload["asset_count"] != state.expected_asset_count:
        raise contract.ReceiptValidationError("draft asset count mismatch")
    if set(state.draft_assets) != set(state.expected_assets):
        raise contract.ReceiptValidationError("draft asset set is incomplete")


def bind_github_release(state: ChainState, payload: Mapping[str, Any]) -> None:
    """Cross-bind publication observations to the staged immutable release."""

    _equal(payload["release_id"], state.draft_release_id, "GitHub release ID")
    _equal(payload["release_body_sha256"], state.release_body_sha256, "GitHub body")
    assets_key = (
        "asset_inventory_sha256"
        if payload["transition"] == "PUBLISH_ACCEPTED"
        else "assets_sha256"
    )
    _equal(
        payload[assets_key],
        state.expected_asset_inventory_sha256,
        "GitHub asset inventory",
    )
    if payload["transition"] == "IMMUTABLE_VERIFIED":
        if (
            payload["asset_count"] != state.expected_asset_count
            or payload["verified_asset_count"] != state.expected_asset_count
        ):
            raise contract.ReceiptValidationError(
                "immutable release asset count mismatch"
            )
        state.immutable_release_verified = True


def _equal(actual: Any, expected: Any, name: str) -> None:
    if actual != expected:
        raise contract.ReceiptValidationError(f"{name} mismatch")
