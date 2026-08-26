"""Stateful one-use binding for mutation intents and provider outcomes."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_consumption as consumption
from tools.evidence import release_authority_guard as authority_guard
from tools.evidence.release_receipt_envelope_v2 import encode


@dataclass(slots=True)
class IntentRecord:
    """Immutable intent identity reconstructed from its mirrored envelope."""

    intent_id: str
    operation: str
    subject_identity_sha256: str
    subject: dict[str, Any]
    scope_kind: str
    scope_id: str
    attempt_id: str
    lease_id: str
    fencing_token: int
    receipt_id: str
    receipt_sha256: str
    intent_committed_at: str
    consumed: bool = False
    outcome_bound: bool = False
    invalidated: bool = False
    consumption_receipt_id: str | None = None
    consumption_receipt_sha256: str | None = None
    authority_guard_sha256: str | None = None
    authority_guard_observed_at: str | None = None
    authority_guard_accepted_at: str | None = None
    authority_guard_expires_at: str | None = None
    capability_binding_sha256: str | None = None
    consumption_committed_at: str | None = None
    authority_guard_variant: str | None = None


@dataclass(slots=True)
class IntentLedger:
    """Reject subject substitution, overwrite, and one-use replay."""

    by_id: dict[str, IntentRecord] = field(default_factory=dict)
    active_by_operation: dict[str, str] = field(default_factory=dict)

    def record(self, envelope: Mapping[str, Any]) -> IntentRecord:
        payload = envelope["payload"]
        if payload["kind"] != "MUTATION_INTENT":
            raise contract.ReceiptValidationError("intent record payload mismatch")
        intent_id = payload["intent_id"]
        operation = payload["operation"]
        if intent_id in self.by_id:
            raise contract.ReceiptValidationError("duplicate mutation intent")
        active_id = self.active_by_operation.get(operation)
        if active_id is not None and not (
            self.by_id[active_id].consumed or self.by_id[active_id].invalidated
        ):
            raise contract.ReceiptValidationError(
                "mutation intent operation already has unconsumed authority"
            )
        receipt_bytes = encode(envelope)
        scope = envelope["scope"]
        scope_key = f"{scope['kind']}_id"
        record = IntentRecord(
            intent_id=intent_id,
            operation=operation,
            subject_identity_sha256=payload["subject_identity_sha256"],
            subject=copy.deepcopy(dict(payload["subject"])),
            scope_kind=scope["kind"],
            scope_id=scope[scope_key],
            attempt_id=payload["attempt_id"],
            lease_id=payload["lease_id"],
            fencing_token=payload["fencing_token"],
            receipt_id=envelope["receipt_id"],
            receipt_sha256=("sha256:" + hashlib.sha256(receipt_bytes).hexdigest()),
            intent_committed_at=envelope["timestamps"]["committed_at"],
        )
        self.by_id[intent_id] = record
        self.active_by_operation[operation] = intent_id
        return record

    def consume(self, envelope: Mapping[str, Any]) -> IntentRecord:
        """Consume one intent using a verified, durable pre-mutation envelope."""

        payload = envelope["payload"]
        if payload["kind"] != "MUTATION_INTENT_CONSUMED":
            raise contract.ReceiptValidationError("intent consumption payload mismatch")
        record = self.by_id.get(payload["intent_id"])
        if record is None or record.operation != payload["operation"]:
            raise contract.ReceiptValidationError("mutation intent operation mismatch")
        if record.consumed:
            raise contract.ReceiptValidationError(
                "mutation intent was already consumed"
            )
        if record.invalidated:
            raise contract.ReceiptValidationError(
                "mutation intent fence was invalidated"
            )
        scope_key = f"{record.scope_kind}_id"
        expected = {
            "intent_receipt_id": record.receipt_id,
            "intent_receipt_sha256": record.receipt_sha256,
            "intent_subject_sha256": record.subject_identity_sha256,
            "attempt_id": record.attempt_id,
            "lease_id": record.lease_id,
            "fencing_token": record.fencing_token,
            scope_key: record.scope_id,
            "consumer_identity_sha256": consumption.consumer_identity_sha256(
                envelope["producer"]
            ),
        }
        if any(payload[key] != value for key, value in expected.items()):
            raise contract.ReceiptValidationError(
                "mutation intent consumption mismatch"
            )
        consumed_at = contract.timestamp(payload["consumed_at"], "consumed_at")
        intent_committed_at = contract.timestamp(
            record.intent_committed_at, "intent.timestamps.committed_at"
        )
        observed_at = contract.timestamp(
            envelope["timestamps"]["observed_at"], "timestamps.observed_at"
        )
        committed_at = contract.timestamp(
            envelope["timestamps"]["committed_at"], "timestamps.committed_at"
        )
        if (
            not intent_committed_at <= consumed_at <= observed_at
            or consumed_at > committed_at
        ):
            raise contract.ReceiptValidationError(
                "intent consumption timestamp outside intent/receipt interval"
            )
        if record.operation in authority_guard.GUARDED_OPERATIONS:
            try:
                guard = authority_guard.validate(payload["authority_guard"])
                authority_guard.bind_to_consumption(
                    guard, payload, envelope["producer"]
                )
            except authority_guard.AuthorityGuardError as exc:
                raise contract.ReceiptValidationError(str(exc)) from exc
            guard_observed = contract.timestamp(
                guard["observed_at"], "authority guard observed_at"
            )
            guard_accepted = contract.timestamp(
                guard["accepted_at"], "authority guard accepted_at"
            )
            guard_expires = contract.timestamp(
                guard["expires_at"], "authority guard expires_at"
            )
            if not (
                guard_observed
                <= guard_accepted
                <= consumed_at
                <= observed_at
                <= committed_at
                <= guard_expires
            ):
                raise contract.ReceiptValidationError(
                    "effect authority guard expired before consumption commit"
                )
        receipt_bytes = encode(envelope)
        record.consumed = True
        record.consumption_receipt_id = envelope["receipt_id"]
        record.consumption_receipt_sha256 = (
            "sha256:" + hashlib.sha256(receipt_bytes).hexdigest()
        )
        record.consumption_committed_at = envelope["timestamps"]["committed_at"]
        if record.operation in authority_guard.GUARDED_OPERATIONS:
            record.authority_guard_sha256 = payload["authority_guard_sha256"]
            record.authority_guard_observed_at = payload["authority_guard_observed_at"]
            record.authority_guard_accepted_at = payload["authority_guard_accepted_at"]
            record.authority_guard_expires_at = payload["authority_guard_expires_at"]
            record.capability_binding_sha256 = payload["capability_binding_sha256"]
            record.authority_guard_variant = payload["authority_guard"]["guard_variant"]
        return record

    def invalidate_unconsumed(self, *, lease_id: str, fencing_token: int) -> None:
        """Model durable loss of every unconsumed authority under an old fence."""

        for record in self.by_id.values():
            if (
                not record.consumed
                and record.lease_id == lease_id
                and record.fencing_token == fencing_token
            ):
                record.invalidated = True

    def require_outcome(
        self,
        payload: Mapping[str, Any],
        *,
        operation: str,
        expected_subject: Mapping[str, Any],
        outcome_observed_at: str,
        outcome_committed_at: str,
    ) -> IntentRecord:
        """Require an outcome to reference the exact prior consumption bytes."""

        guarded = operation in authority_guard.GUARDED_OPERATIONS
        consumption.validate_outcome(payload, require_guard=guarded)
        record = self.by_id.get(payload["intent_id"])
        if record is None or record.operation != operation or not record.consumed:
            raise contract.ReceiptValidationError("consumed mutation intent is missing")
        if record.outcome_bound:
            raise contract.ReceiptValidationError("mutation intent outcome replay")
        expected = {
            "intent_subject_sha256": record.subject_identity_sha256,
            "intent_receipt_id": record.receipt_id,
            "intent_receipt_sha256": record.receipt_sha256,
            "intent_consumption_receipt_id": record.consumption_receipt_id,
            "intent_consumption_receipt_sha256": record.consumption_receipt_sha256,
        }
        if guarded:
            expected.update(
                authority_guard_sha256=record.authority_guard_sha256,
                authority_guard_observed_at=record.authority_guard_observed_at,
                authority_guard_accepted_at=record.authority_guard_accepted_at,
                authority_guard_expires_at=record.authority_guard_expires_at,
                capability_binding_sha256=record.capability_binding_sha256,
            )
        if any(payload[key] != value for key, value in expected.items()):
            raise contract.ReceiptValidationError("mutation intent receipt mismatch")
        if dict(expected_subject) != record.subject:
            raise contract.ReceiptValidationError("mutation intent subject mismatch")
        if guarded:
            consumed_committed = contract.timestamp(
                record.consumption_committed_at,
                "consumption committed_at",
            )
            observed = contract.timestamp(outcome_observed_at, "outcome observed_at")
            committed = contract.timestamp(outcome_committed_at, "outcome committed_at")
            expires = contract.timestamp(
                record.authority_guard_expires_at,
                "authority guard expires_at",
            )
            private_effect = record.authority_guard_variant == "SERVICE_MUTATOR_EFFECT"
            if not consumed_committed <= observed <= committed or (
                private_effect and committed > expires
            ):
                raise contract.ReceiptValidationError(
                    "provider outcome is outside the consumed authority guard"
                )
        record.outcome_bound = True
        return record

    def pending(self, operation: str) -> IntentRecord:
        intent_id = self.active_by_operation.get(operation)
        record = self.by_id.get(intent_id) if intent_id is not None else None
        if record is None or record.consumed or record.invalidated:
            raise contract.ReceiptValidationError("required mutation intent is missing")
        return record

    def has_ambiguous_consumption(self) -> bool:
        """Return whether a consumed capability has no durable provider outcome."""

        return any(
            record.consumed and not record.outcome_bound
            for record in self.by_id.values()
        )
