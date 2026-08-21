"""Non-circular closure and CLOSED-check bindings for receipt-v2 chains."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence.release_receipt_chain_state import ChainState
from tools.evidence.release_receipt_envelope_v2 import encode
from tools.evidence.release_receipt_state_contract import receipt_chain_sha256


def bind_closed(state: ChainState, envelope: Mapping[str, Any]) -> None:
    """Verify terminal publication inventories and freeze the CLOSED receipt."""

    payload = envelope["payload"]
    if state.pypi_verified_count != len(state.distributions):
        raise contract.ReceiptValidationError("PyPI inventory is not complete")
    if not state.immutable_release_verified:
        raise contract.ReceiptValidationError("GitHub release is not immutable")
    for key, expected in {
        "release_identity_id": state.release_identity_id,
        "release_authority_id": state.release_authority_id,
        "candidate_id": state.candidate_id,
        "authorization_id": state.authorization_id,
        "public_bundle_manifest_sha256": state.public_bundle_manifest_sha256,
        "snapshot_a_sha256": state.snapshots.get("A"),
        "snapshot_b_sha256": state.snapshots.get("B"),
        "snapshot_c_sha256": state.snapshots.get("C"),
        "pypi_inventory_sha256": state.distribution_inventory_sha256,
        "github_release_inventory_sha256": state.expected_asset_inventory_sha256,
    }.items():
        _equal(payload[key], expected, f"CLOSED {key}")
    receipt_bytes = encode(envelope)
    if payload["controller_action_commit_sha"] == envelope["producer"]["workflow_sha"]:
        raise contract.ReceiptValidationError(
            "CLOSED Commit A must differ from workflow Commit P"
        )
    state.closed_binding = {
        "closed_receipt_id": envelope["receipt_id"],
        "closed_receipt_sha256": "sha256:" + hashlib.sha256(receipt_bytes).hexdigest(),
        "receipt_chain_sha256": receipt_chain_sha256(
            [*state.receipt_envelopes, envelope]
        ),
        "controller_action_commit_sha": payload["controller_action_commit_sha"],
        "controller_action_metadata_blob_sha": payload[
            "controller_action_metadata_blob_sha"
        ],
        "controller_action_bundle_sha256": payload["controller_action_bundle_sha256"],
    }
    state.lease_id = None
    state.lease_expires_at = None


def _equal(actual: Any, expected: Any, name: str) -> None:
    if actual != expected:
        raise contract.ReceiptValidationError(f"{name} mismatch")
