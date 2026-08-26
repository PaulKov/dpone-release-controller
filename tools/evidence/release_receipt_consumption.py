"""Durable, independently verifiable consumption of one-use mutation intents."""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_intents as intents
from tools.evidence import release_authority_guard as authority_guard
from tools.evidence.release_canonical import sha256_id

CONSUMER_DOMAIN = "dpone.release.intent-consumer.v2"
BASE_OUTCOME_KEYS = frozenset(
    {
        "intent_id",
        "intent_receipt_id",
        "intent_receipt_sha256",
        "intent_subject_sha256",
        "intent_consumption_receipt_id",
        "intent_consumption_receipt_sha256",
        "intent_consumed_once",
    }
)
OUTCOME_GUARD_KEYS = frozenset(
    {
        "authority_guard_sha256",
        "authority_guard_observed_at",
        "authority_guard_accepted_at",
        "authority_guard_expires_at",
        "capability_binding_sha256",
    }
)
OUTCOME_KEYS = BASE_OUTCOME_KEYS | OUTCOME_GUARD_KEYS


def validate_receipt(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Validate the WORM receipt appended before any provider mutation."""

    operation = contract.enum(payload.get("operation"), intents.OPERATIONS, "operation")
    scope = (
        "candidate" if operation in intents.CANDIDATE_OPERATIONS else "authorization"
    )
    scope_key = f"{scope}_id"
    guard_keys = (
        {
            "authority_guard",
            "authority_guard_sha256",
            "authority_guard_observed_at",
            "authority_guard_accepted_at",
            "authority_guard_expires_at",
            "capability_binding_sha256",
        }
        if operation in authority_guard.GUARDED_OPERATIONS
        else set()
    )
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "intent_id",
            "intent_receipt_id",
            "intent_receipt_sha256",
            "intent_subject_sha256",
            "lease_id",
            "fencing_token",
            "attempt_id",
            "operation",
            "capability_sha256",
            "consumer_identity_sha256",
            "consumed_at",
            scope_key,
            *guard_keys,
        },
        "MUTATION_INTENT_CONSUMED payload",
    )
    _constant(payload, "kind", "MUTATION_INTENT_CONSUMED")
    _constant(payload, "state", "MUTATION_INTENT_CONSUMED")
    contract.digest_fields(
        payload,
        "intent_id",
        "intent_receipt_id",
        "intent_receipt_sha256",
        "intent_subject_sha256",
        "lease_id",
        "attempt_id",
        "capability_sha256",
        "consumer_identity_sha256",
        scope_key,
    )
    contract.positive_int(payload["fencing_token"], "fencing_token")
    contract.timestamp(payload["consumed_at"], "consumed_at")
    if guard_keys:
        try:
            guard = authority_guard.validate(payload["authority_guard"])
        except authority_guard.AuthorityGuardError as exc:
            raise contract.ReceiptValidationError(str(exc)) from exc
        if (
            payload["authority_guard_sha256"] != authority_guard.digest(guard)
            or payload["authority_guard_observed_at"] != guard["observed_at"]
            or payload["authority_guard_accepted_at"] != guard["accepted_at"]
            or payload["authority_guard_expires_at"] != guard["expires_at"]
            or payload["capability_binding_sha256"]
            != authority_guard.capability_binding_sha256(payload)
        ):
            raise contract.ReceiptValidationError(
                "authority guard/capability binding mismatch"
            )
        contract.digest_fields(
            payload,
            "authority_guard_sha256",
            "capability_binding_sha256",
        )
    producer = (
        "trusted_controller_service"
        if operation
        in {
            "ATTESTATION_CREATE",
            "GITHUB_RELEASE_PUBLISH",
        }
        or operation.startswith(("PYPI_DEPLOYMENT_", "GITHUB_DRAFT_"))
        else "github_actions_job"
    )
    return contract.PayloadSemantics(scope, True, frozenset({producer}))


def validate_outcome(payload: Mapping[str, Any], *, require_guard: bool = True) -> None:
    """Validate an outcome's exact reference to a prior consumption envelope."""

    contract.digest_fields(
        payload, *sorted(BASE_OUTCOME_KEYS - {"intent_consumed_once"})
    )
    if (
        contract.boolean(payload["intent_consumed_once"], "intent_consumed_once")
        is not True
    ):
        raise contract.ReceiptValidationError("intent must be consumed exactly once")
    present = OUTCOME_GUARD_KEYS.intersection(payload)
    if require_guard and present != OUTCOME_GUARD_KEYS:
        raise contract.ReceiptValidationError("guarded outcome fields are incomplete")
    if not require_guard and present:
        raise contract.ReceiptValidationError("unguarded outcome carries guard fields")
    if require_guard:
        contract.digest_fields(
            payload,
            "authority_guard_sha256",
            "capability_binding_sha256",
        )
        observed = contract.timestamp(
            payload["authority_guard_observed_at"],
            "authority_guard_observed_at",
        )
        accepted = contract.timestamp(
            payload["authority_guard_accepted_at"],
            "authority_guard_accepted_at",
        )
        expires = contract.timestamp(
            payload["authority_guard_expires_at"],
            "authority_guard_expires_at",
        )
        if not observed <= accepted < expires:
            raise contract.ReceiptValidationError(
                "guarded outcome time projection is invalid"
            )


def consumer_identity_sha256(producer: Mapping[str, Any]) -> str:
    """Bind the full authenticated job/service projection without exposing tokens."""

    return sha256_id(CONSUMER_DOMAIN, {"producer": dict(producer)})


def _constant(payload: Mapping[str, Any], key: str, expected: Any) -> None:
    if payload[key] != expected or type(payload[key]) is not type(expected):
        raise contract.ReceiptValidationError(f"{key} must be exactly {expected!r}")
