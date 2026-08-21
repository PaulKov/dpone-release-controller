"""Closed lease acquisition, renewal, release, and expiry payloads."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract

_JOB = frozenset({"github_actions_job"})


def validate_lease(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Validate one exact lease lifecycle payload."""

    kind = contract.enum(
        payload.get("kind"),
        {"LEASE_ACQUIRED", "LEASE_RENEWED", "LEASE_RELEASED", "LEASE_EXPIRED"},
        "kind",
    )
    if kind == "LEASE_ACQUIRED":
        _lease_acquired(payload)
    elif kind == "LEASE_RENEWED":
        _lease_renewed(payload)
    elif kind == "LEASE_RELEASED":
        _lease_released(payload)
    else:
        _lease_expired(payload)
    if kind == "LEASE_EXPIRED":
        producers = frozenset({"release_authority_broker_timer"})
    elif kind == "LEASE_RELEASED":
        producers = frozenset({"trusted_controller_service"})
    else:
        producers = _JOB
    return contract.PayloadSemantics("release", True, producers)


def _lease_acquired(payload: Mapping[str, Any]) -> None:
    recovery = contract.boolean(
        payload.get("recovery_acquisition"), "recovery_acquisition"
    )
    recovery_keys = (
        {"recovery_id", "previous_attempt_id", "previous_queue_entry_id"}
        if recovery
        else set()
    )
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "lease_id",
            "fencing_token",
            "acquired_at",
            "expires_at",
            "ttl_seconds",
            "renew_interval_seconds",
            "attempt_id",
            "queue_entry_id",
            "recovery_acquisition",
            *recovery_keys,
        },
        "LEASE_ACQUIRED payload",
    )
    _constants(
        payload,
        kind="LEASE_ACQUIRED",
        state="LEASE_ACQUIRED",
        ttl_seconds=contract.LEASE_TTL_SECONDS,
        renew_interval_seconds=contract.LEASE_RENEW_INTERVAL_SECONDS,
    )
    _lease_identity(payload)
    contract.digest_fields(payload, "attempt_id", "queue_entry_id")
    if recovery:
        contract.digest_fields(
            payload,
            "recovery_id",
            "previous_attempt_id",
            "previous_queue_entry_id",
        )
    contract.ordered_timestamps(
        payload["acquired_at"],
        payload["expires_at"],
        "acquired_at",
        "expires_at",
        exact_delta=timedelta(seconds=contract.LEASE_TTL_SECONDS),
    )


def _lease_renewed(payload: Mapping[str, Any]) -> None:
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "lease_id",
            "fencing_token",
            "previous_expires_at",
            "renewed_at",
            "expires_at",
            "ttl_seconds",
        },
        "LEASE_RENEWED payload",
    )
    _constants(
        payload,
        kind="LEASE_RENEWED",
        state="LEASE_RENEWED",
        ttl_seconds=contract.LEASE_TTL_SECONDS,
    )
    _lease_identity(payload)
    contract.timestamp(payload["previous_expires_at"], "previous_expires_at")
    contract.ordered_timestamps(
        payload["renewed_at"],
        payload["expires_at"],
        "renewed_at",
        "expires_at",
        exact_delta=timedelta(seconds=contract.LEASE_TTL_SECONDS),
    )


def _lease_released(payload: Mapping[str, Any]) -> None:
    contract.exact_keys(
        payload,
        {"kind", "state", "lease_id", "fencing_token", "released_at", "reason"},
        "LEASE_RELEASED payload",
    )
    _constants(payload, kind="LEASE_RELEASED", state="LEASE_RELEASED")
    _lease_identity(payload)
    contract.timestamp(payload["released_at"], "released_at")
    contract.enum(
        payload["reason"],
        {"CANCELLED", "ABANDONED", "RECOVERY_REQUIRED"},
        "reason",
    )


def _lease_expired(payload: Mapping[str, Any]) -> None:
    contract.boolean(
        payload.get("external_commit_observed"), "external_commit_observed"
    )
    next_state = contract.enum(
        payload.get("next_state"),
        {"ABORTED", "INCIDENT_HOLD", "RECOVERY_REQUIRED"},
        "next_state",
    )
    recovery_keys = set() if next_state == "ABORTED" else {"recovery_id"}
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "lease_id",
            "fencing_token",
            "expired_at",
            "external_commit_observed",
            "next_state",
            *recovery_keys,
        },
        "LEASE_EXPIRED payload",
    )
    _constants(payload, kind="LEASE_EXPIRED", state="LEASE_EXPIRED")
    _lease_identity(payload)
    contract.timestamp(payload["expired_at"], "expired_at")
    if recovery_keys:
        contract.digest(payload["recovery_id"], "recovery_id")


def _lease_identity(payload: Mapping[str, Any]) -> None:
    contract.digest(payload["lease_id"], "lease_id")
    contract.positive_int(payload["fencing_token"], "fencing_token")


def _constants(payload: Mapping[str, Any], **expected: Any) -> None:
    for key, value in expected.items():
        if payload[key] != value or type(payload[key]) is not type(value):
            raise contract.ReceiptValidationError(f"{key} must be exactly {value!r}")
