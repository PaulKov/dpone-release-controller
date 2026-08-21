"""Mutable aggregate rebuilt exclusively from verified receipt envelopes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from tools.evidence.release_receipt_intent_ledger import IntentLedger


@dataclass(slots=True)
class ChainState:
    """In-memory state used by the deterministic chain verifier."""

    phase: str = "START"
    receipt_ids: list[str] = field(default_factory=list)
    receipt_envelopes: list[dict[str, Any]] = field(default_factory=list)
    release_identity_id: str | None = None
    release_authority_id: str | None = None
    attempt: Mapping[str, Any] | None = None
    previous_attempt: Mapping[str, Any] | None = None
    committer: Mapping[str, Any] | None = None
    service_authority_activation_record: Mapping[str, Any] | None = None
    service_authority_inventory: Mapping[str, Any] | None = None
    activated_authority_head: Mapping[str, Any] | None = None
    activated_authority_head_record_id: str | None = None
    activated_authority_head_record_sha256: str | None = None
    controller_workflow_id: int | None = None
    controller_workflow_sha: str | None = None
    controller_runs: dict[str, tuple[int, int]] = field(default_factory=dict)
    last_committed_at: str | None = None
    lease_id: str | None = None
    fencing_token: int = 0
    lease_acquired_at: datetime | None = None
    lease_last_renewed_at: datetime | None = None
    lease_expires_at: datetime | None = None
    tag: str | None = None
    tag_object_sha: str | None = None
    peeled_commit_sha: str | None = None
    candidate_id: str | None = None
    distributions: dict[tuple[str, str, str], dict[str, Any]] = field(
        default_factory=dict
    )
    distribution_inventory_sha256: str | None = None
    public_bundle_manifest_sha256: str | None = None
    expected_assets: dict[str, dict[str, Any]] = field(default_factory=dict)
    expected_asset_inventory_sha256: str | None = None
    expected_asset_count: int = 0
    draft_release_id: int | None = None
    release_body_sha256: str | None = None
    authorization_id: str | None = None
    snapshots: dict[str, str] = field(default_factory=dict)
    governance_projection: dict[str, Any] | None = None
    intent_ledger: IntentLedger = field(default_factory=IntentLedger)
    draft_assets: dict[str, dict[str, Any]] = field(default_factory=dict)
    gate_binding: dict[str, Any] | None = None
    gate_ambiguity_receipt_id: str | None = None
    gate_ambiguity_decision: str | None = None
    recovery_id: str | None = None
    recovery_origin_phase: str | None = None
    recovery_observation_receipt_id: str | None = None
    recovery_observation_sha256: str | None = None
    recovery_next_action: str | None = None
    recovery_pypi_exact: dict[tuple[str, str, str], dict[str, Any]] = field(
        default_factory=dict
    )
    recovery_github_release: dict[str, Any] | None = None
    recovery_hold_id: str | None = None
    pypi_files: dict[tuple[str, str, str], str] = field(default_factory=dict)
    pypi_verified_count: int = 0
    immutable_release_verified: bool = False
    closed_binding: dict[str, str] | None = None
