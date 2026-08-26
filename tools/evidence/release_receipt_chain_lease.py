"""Fenced lease lifecycle boundary for the receipt-v2 chain."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_chain_recovery as recovery
from tools.evidence.release_receipt_chain_state import ChainState


def apply_lease_boundary(
    state: ChainState, envelope: Mapping[str, Any], event: str
) -> None:
    """Validate and apply lease state before the receipt transition."""

    lease = envelope.get("lease")
    if event == "LEASE_ACQUIRED":
        _acquire(state, envelope, lease)
        return
    if lease is not None:
        if (
            state.lease_id is None
            or lease["lease_id"] != state.lease_id
            or lease["fencing_token"] != state.fencing_token
        ):
            raise contract.ReceiptValidationError("active lease/fence mismatch")
        if event != "LEASE_EXPIRED":
            _require_unexpired_lease(state, envelope)
    if event == "LEASE_RENEWED":
        _renew(state, envelope)
    elif event == "LEASE_EXPIRED":
        _expire(state, envelope)
    elif event == "LEASE_RELEASED":
        _release(state, envelope)


def _acquire(
    state: ChainState,
    envelope: Mapping[str, Any],
    lease: Mapping[str, Any] | None,
) -> None:
    if state.lease_id is not None or state.phase not in {
        "CANDIDATE_READY",
        "RECOVERY_REQUIRED",
        "RECOVERY_OBSERVED",
    }:
        raise contract.ReceiptValidationError("lease acquisition state mismatch")
    assert lease is not None
    if lease["fencing_token"] <= state.fencing_token:
        raise contract.ReceiptValidationError("fencing token did not advance")
    recovery_acquisition = envelope["payload"]["recovery_acquisition"]
    if (state.phase == "CANDIDATE_READY") == recovery_acquisition:
        raise contract.ReceiptValidationError("lease recovery mode mismatch")
    if recovery_acquisition and (
        envelope["payload"]["recovery_id"] != state.recovery_id
        or state.previous_attempt is None
    ):
        raise contract.ReceiptValidationError("lease recovery rollover mismatch")
    state.lease_id = lease["lease_id"]
    state.fencing_token = lease["fencing_token"]
    state.lease_acquired_at = contract.timestamp(
        envelope["payload"]["acquired_at"], "acquired_at"
    )
    state.lease_last_renewed_at = state.lease_acquired_at
    state.lease_expires_at = contract.timestamp(
        envelope["payload"]["expires_at"], "expires_at"
    )
    if state.lease_expires_at - state.lease_acquired_at != timedelta(
        seconds=contract.LEASE_TTL_SECONDS
    ):
        raise contract.ReceiptValidationError("lease acquisition TTL mismatch")
    _require_unexpired_lease(state, envelope)
    state.phase = "LEASED" if state.phase == "CANDIDATE_READY" else "RECOVERY_LEASED"


def _renew(state: ChainState, envelope: Mapping[str, Any]) -> None:
    payload = envelope["payload"]
    previous = contract.timestamp(payload["previous_expires_at"], "previous_expires_at")
    renewed = contract.timestamp(payload["renewed_at"], "renewed_at")
    expires = contract.timestamp(payload["expires_at"], "expires_at")
    if previous != state.lease_expires_at:
        raise contract.ReceiptValidationError("lease previous expiry mismatch")
    if state.lease_last_renewed_at is None or not (
        state.lease_last_renewed_at < renewed < previous
    ):
        raise contract.ReceiptValidationError("lease renewal time mismatch")
    if renewed - state.lease_last_renewed_at > timedelta(
        seconds=contract.LEASE_RENEW_INTERVAL_SECONDS
    ):
        raise contract.ReceiptValidationError("lease renewal cadence exceeded")
    if expires - renewed != timedelta(seconds=contract.LEASE_TTL_SECONDS):
        raise contract.ReceiptValidationError("lease renewal TTL mismatch")
    state.lease_last_renewed_at = renewed
    state.lease_expires_at = expires


def _expire(state: ChainState, envelope: Mapping[str, Any]) -> None:
    expired = contract.timestamp(envelope["payload"]["expired_at"], "expired_at")
    if state.lease_expires_at is None or expired < state.lease_expires_at:
        raise contract.ReceiptValidationError("lease expiry precedes active expiry")
    old_phase = state.phase
    recovery.require_external_observation_truth(state, envelope["payload"])
    expected_target = (
        "ABORTED"
        if old_phase == "CANCELLED"
        else "INCIDENT_HOLD"
        if old_phase == "INCIDENT_HOLD"
        else "RECOVERY_REQUIRED"
    )
    if envelope["payload"]["next_state"] != expected_target:
        raise contract.ReceiptValidationError("lease expiry state mismatch")
    if expected_target != "ABORTED":
        recovery_id = envelope["payload"]["recovery_id"]
        if state.recovery_id not in {None, recovery_id}:
            raise contract.ReceiptValidationError("lease recovery identity drift")
        state.recovery_id = recovery_id
        if state.recovery_origin_phase is None and old_phase != "INCIDENT_HOLD":
            state.recovery_origin_phase = old_phase
    state.intent_ledger.invalidate_unconsumed(
        lease_id=state.lease_id,
        fencing_token=state.fencing_token,
    )
    state.lease_id = None
    state.phase = expected_target


def _release(state: ChainState, envelope: Mapping[str, Any]) -> None:
    reason = envelope["payload"]["reason"]
    targets = {
        ("CANCELLED", "CANCELLED"): "ABORTED",
        ("RECOVERY_REQUIRED", "RECOVERY_REQUIRED"): "RECOVERY_REQUIRED",
        ("INCIDENT_HOLD", "ABANDONED"): "INCIDENT_HOLD",
    }
    target = targets.get((state.phase, reason))
    if target is None:
        raise contract.ReceiptValidationError("lease release state/reason mismatch")
    released = contract.timestamp(envelope["payload"]["released_at"], "released_at")
    if state.lease_expires_at is None or released > state.lease_expires_at:
        raise contract.ReceiptValidationError("lease released after expiry")
    state.phase = target
    state.lease_id = None


def _require_unexpired_lease(state: ChainState, envelope: Mapping[str, Any]) -> None:
    if state.lease_expires_at is None:
        raise contract.ReceiptValidationError("active lease expiry is missing")
    observed = contract.timestamp(
        envelope["timestamps"]["observed_at"], "timestamps.observed_at"
    )
    committed = contract.timestamp(
        envelope["timestamps"]["committed_at"], "timestamps.committed_at"
    )
    if observed >= state.lease_expires_at or committed >= state.lease_expires_at:
        raise contract.ReceiptValidationError(
            "receipt committed at or after lease expiry"
        )
