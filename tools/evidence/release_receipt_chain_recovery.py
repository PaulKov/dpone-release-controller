"""Recovery-attempt and incident transitions for the receipt-v2 chain."""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_identity
from tools.evidence import release_receipt_contract as contract
from tools.evidence.release_receipt_chain_state import ChainState


def apply_recovery(state: ChainState, envelope: Mapping[str, Any], event: str) -> None:
    """Apply one recovery, cancellation, or incident-hold transition."""

    payload = envelope["payload"]
    if event == "CANCELLATION":
        old_phase = state.phase
        if old_phase not in CANCELLABLE_PHASES:
            raise contract.ReceiptValidationError(
                "cancellation source phase is forbidden"
            )
        require_external_observation_truth(state, payload)
        state.phase = (
            "RECOVERY_REQUIRED" if payload["external_commit_observed"] else "CANCELLED"
        )
        if payload["external_commit_observed"]:
            if state.recovery_id not in {None, payload["recovery_id"]}:
                raise contract.ReceiptValidationError("recovery identity drift")
            state.recovery_id = payload["recovery_id"]
            if state.recovery_origin_phase is None:
                state.recovery_origin_phase = old_phase
            state.intent_ledger.invalidate_unconsumed(
                lease_id=state.lease_id,
                fencing_token=state.fencing_token,
            )
    elif event == "RECOVERY_OBSERVATION" and state.phase == "RECOVERY_LEASED":
        _equal(payload["recovery_id"], state.recovery_id, "recovery identity")
        _equal(payload["candidate_id"], state.candidate_id, "recovery candidate")
        if "authorization_id" in payload:
            _equal(
                payload["authorization_id"],
                state.authorization_id,
                "recovery authorization",
            )
        elif state.authorization_id is not None:
            raise contract.ReceiptValidationError("recovery authorization is missing")
        _bind_recovery_observation(state, envelope)
        state.phase = "RECOVERY_OBSERVED"
    elif event == "RECOVERY_RESUMED" and state.phase == "RECOVERY_OBSERVED":
        _bind_recovery_edge(state, payload, "RESUME_ORIGINAL_CANDIDATE")
        github_state = (state.recovery_github_release or {}).get("state")
        if not state.recovery_pypi_exact and github_state == "NONE":
            expected_phase = "LEASED_RESTART"
            target_phase = "LEASED"
        elif state.pypi_verified_count == len(state.distributions):
            expected_phase = "PYPI_VERIFIED"
            target_phase = expected_phase
        else:
            expected_phase = "PYPI_RECOVERY"
            target_phase = expected_phase
        _equal(payload["resume_phase"], expected_phase, "recovery resume phase")
        state.phase = target_phase
    elif event == "RECOVERY_CLOSED_EXACT" and state.phase == "RECOVERY_OBSERVED":
        _bind_recovery_edge(state, payload, "CLOSE_EXACT")
        _equal(
            payload["pypi_inventory_sha256"],
            state.distribution_inventory_sha256,
            "recovery PyPI inventory",
        )
        _equal(
            payload["github_release_inventory_sha256"],
            state.expected_asset_inventory_sha256,
            "recovery GitHub inventory",
        )
        github = state.recovery_github_release or {}
        _equal(payload["release_id"], github.get("release_id"), "recovery release")
        state.draft_release_id = payload["release_id"]
        state.immutable_release_verified = True
        state.phase = "GITHUB_IMMUTABLE"
    elif event == "INCIDENT_HOLD" and state.phase in {
        "RECOVERY_REQUIRED",
        "RECOVERY_OBSERVED",
    }:
        _equal(payload["recovery_id"], state.recovery_id, "hold recovery")
        state.recovery_hold_id = payload["hold_id"]
        state.phase = "INCIDENT_HOLD"
    elif event == "INCIDENT_HOLD_RELEASED" and state.phase == "INCIDENT_HOLD":
        _equal(payload["recovery_id"], state.recovery_id, "hold recovery")
        _equal(payload["hold_id"], state.recovery_hold_id, "hold identity")
        state.recovery_hold_id = None
        state.phase = "RECOVERY_REQUIRED"
    else:
        raise contract.ReceiptValidationError("recovery transition mismatch")


def roll_recovery_attempt(state: ChainState, envelope: Mapping[str, Any]) -> None:
    """Admit a new controller run only at a fenced recovery acquisition."""

    payload = envelope["payload"]
    previous = state.attempt
    current = envelope["attempt"]
    if (
        payload["kind"] != "LEASE_ACQUIRED"
        or state.phase != "RECOVERY_REQUIRED"
        or state.lease_id is not None
        or not payload["recovery_acquisition"]
        or payload["recovery_id"] != state.recovery_id
        or previous is None
        or payload["previous_attempt_id"] != previous["attempt_id"]
        or payload["previous_queue_entry_id"] != previous["queue_entry_id"]
        or current["queue_entry_id"] != previous["queue_entry_id"]
        or current["attempt_id"] == previous["attempt_id"]
    ):
        raise contract.ReceiptValidationError("receipt attempt rollover mismatch")
    state.previous_attempt = dict(previous)
    state.attempt = dict(current)


def bind_controller_job(state: ChainState, envelope: Mapping[str, Any]) -> None:
    """Cross-bind every GHA producer to one workflow and canonical attempt."""

    producer = envelope["producer"]
    if producer["kind"] != "github_actions_job":
        return
    workflow = (producer["workflow_id"], producer["workflow_sha"])
    expected = (state.controller_workflow_id, state.controller_workflow_sha)
    if expected == (None, None):
        state.controller_workflow_id, state.controller_workflow_sha = workflow
    elif workflow != expected:
        raise contract.ReceiptValidationError("controller workflow authority drift")
    attempt_id = envelope["attempt"]["attempt_id"]
    run = (producer["run_id"], producer["run_attempt"])
    expected_attempt_id = release_identity.attempt_id(
        release_authority_id=state.release_authority_id,
        controller_workflow_id=producer["workflow_id"],
        controller_run_id=producer["run_id"],
        controller_run_attempt=producer["run_attempt"],
    )
    _equal(attempt_id, expected_attempt_id, "canonical controller attempt")
    previous_run = state.controller_runs.setdefault(attempt_id, run)
    if previous_run != run:
        raise contract.ReceiptValidationError("controller run/attempt drift")
    if state.previous_attempt is not None:
        old_run = state.controller_runs.get(state.previous_attempt["attempt_id"])
        if old_run == run:
            raise contract.ReceiptValidationError("recovery reused controller run")


def require_external_observation_truth(
    state: ChainState, payload: Mapping[str, Any]
) -> None:
    """Reject a clean observation after any verified external side effect."""

    known_external = (
        state.draft_release_id is not None
        or any(
            transition
            in {"UPLOAD_ACCEPTED", "INTEGRITY_VERIFIED", "ALREADY_PUBLISHED_EXACT"}
            for transition in state.pypi_files.values()
        )
        or state.immutable_release_verified
        or state.intent_ledger.has_ambiguous_consumption()
    )
    if known_external and not payload["external_commit_observed"]:
        raise contract.ReceiptValidationError(
            "external commit observation contradicts verified chain state"
        )


def _bind_recovery_observation(state: ChainState, envelope: Mapping[str, Any]) -> None:
    payload = envelope["payload"]
    exact: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in payload["pypi_exact_file_inventory"]:
        key = (item["project"], item["version"], item["filename"])
        if state.distributions.get(key) != item:
            raise contract.ReceiptValidationError("recovery PyPI inventory mismatch")
        current = state.pypi_files.get(key)
        if current not in {
            "SEALED_FOR_UPLOAD",
            "UPLOAD_ACCEPTED",
            "INTEGRITY_VERIFIED",
        }:
            raise contract.ReceiptValidationError(
                "recovery file lacks prior upload authority"
            )
        exact[key] = dict(item)
    github = dict(payload["github_release"])
    if github["state"] != "NONE":
        _equal(github["release_id"], state.draft_release_id, "recovery draft ID")
        _equal(
            github["release_body_sha256"],
            state.release_body_sha256,
            "recovery release body",
        )
        _equal(
            github["asset_inventory_sha256"],
            state.expected_asset_inventory_sha256,
            "recovery asset inventory",
        )
        if github["asset_count"] != state.expected_asset_count:
            raise contract.ReceiptValidationError("recovery asset count mismatch")
    state.recovery_observation_receipt_id = envelope["receipt_id"]
    state.recovery_observation_sha256 = payload["observation_sha256"]
    state.recovery_next_action = payload["next_action"]
    state.recovery_pypi_exact = exact
    state.recovery_github_release = github


def _bind_recovery_edge(
    state: ChainState, payload: Mapping[str, Any], expected_action: str
) -> None:
    _equal(payload["recovery_id"], state.recovery_id, "recovery identity")
    _equal(payload["candidate_id"], state.candidate_id, "recovery candidate")
    if "authorization_id" in payload:
        _equal(
            payload["authorization_id"],
            state.authorization_id,
            "recovery authorization",
        )
    elif state.authorization_id is not None:
        raise contract.ReceiptValidationError("recovery authorization is missing")
    _equal(payload["attempt_id"], state.attempt["attempt_id"], "recovery attempt")
    _equal(
        payload["observation_receipt_id"],
        state.recovery_observation_receipt_id,
        "recovery observation receipt",
    )
    _equal(
        payload["observation_sha256"],
        state.recovery_observation_sha256,
        "recovery observation",
    )
    _equal(state.recovery_next_action, expected_action, "recovery next action")


def _equal(actual: Any, expected: Any, name: str) -> None:
    if actual != expected:
        raise contract.ReceiptValidationError(f"{name} mismatch")


# Cancellation is same-attempt failure cleanup, never a generic escape hatch.
CANCELLABLE_PHASES = frozenset(
    {
        "LEASED",
        "HYGIENE_VERIFIED",
        "ATTESTATION_INTENT",
        "ATTESTED",
        "PUBLIC_BUNDLE_VERIFIED",
        "DRAFT_CREATE_INTENT",
        "DRAFT_CREATED",
        "DRAFT_ASSET_INTENT",
        "DRAFT_ASSETS",
        "DRAFT_UPDATE_INTENT",
        "DRAFT_STAGED",
        "DRAFT_VERIFIED",
        "GOVERNANCE_B",
        "AUTHORIZED",
        "PYPI_GATE_PENDING",
        "PYPI_GATE_DECISION_INTENT",
        "PYPI_GATE_RECONCILIATION",
        "PYPI_READY",
        "PYPI_PREPARING",
        "PYPI_ACTIVE",
        "PYPI_SEALED",
        "PYPI_UPLOAD_INTENT",
        "PYPI_UPLOAD_SET_COMPLETE",
        "PYPI_PARTIAL_EXACT",
        "PYPI_VERIFIED",
        "GITHUB_PUBLISH_INTENT",
        "GITHUB_PUBLISHING",
        "GITHUB_IMMUTABLE",
        "GOVERNANCE_C",
    }
)
