"""Ordered, fenced state-machine verification for receipt-envelope v2."""

from __future__ import annotations

import copy
from typing import Any, Mapping, Sequence

from tools.evidence import release_controller_service_activation as service_activation
from tools.evidence import release_controller_service_inventory as service_inventory
from tools.evidence import release_identity
from tools.evidence import release_receipt_chain_closure as closure
from tools.evidence import release_receipt_chain_lease as lease
from tools.evidence import release_receipt_chain_publication as publication
from tools.evidence import release_receipt_chain_recovery as recovery
from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_outcome_bindings as outcome_bindings
from tools.evidence.release_receipt_chain_state import ChainState
from tools.evidence.release_receipt_envelope_v2 import verify
from tools.evidence.release_receipt_state_contract import RULE_BY_EVENT, event_key


def verify_chain(
    receipts: Sequence[Mapping[str, Any]],
    *,
    require_terminal: bool = False,
) -> ChainState:
    """Rebuild a self-contained stream under its immutable seq0 authority head."""

    if not receipts:
        raise contract.ReceiptValidationError("receipt chain must not be empty")
    state = ChainState()
    activation_record, authority_inventory, authority_head, head_id, head_sha256 = (
        _authority_genesis(receipts[0])
    )
    inventory_context = service_inventory.compile_inventory(authority_inventory)
    activation_bindings = service_activation.compile_committer_bindings(
        activation_record,
        record_id=receipts[0]["payload"]["service_authority_activation_record_id"],
        record_sha256=receipts[0]["payload"][
            "service_authority_activation_record_sha256"
        ],
    )
    state.service_authority_activation_record = copy.deepcopy(activation_record)
    state.service_authority_inventory = copy.deepcopy(authority_inventory)
    state.activated_authority_head = copy.deepcopy(authority_head)
    state.activated_authority_head_record_id = head_id
    state.activated_authority_head_record_sha256 = head_sha256
    for index, envelope in enumerate(receipts):
        verify(envelope)
        try:
            service_activation.bind_committer(
                envelope["committer"], activation_bindings
            )
            service_inventory.bind_committer(envelope["committer"], inventory_context)
            service_inventory.bind_producer(envelope["producer"], inventory_context)
            if envelope["producer"]["kind"] in {
                "trusted_controller_service",
                "release_authority_broker_timer",
            } and (
                envelope["producer"]["activated_authority_head_record_id"] != head_id
                or envelope["producer"]["activated_authority_head_record_sha256"]
                != head_sha256
            ):
                raise service_inventory.ServiceInventoryError(
                    "producer activated-authority head mismatch"
                )
            if envelope["payload"]["kind"] == "CANDIDATE_HANDOFF":
                service_inventory.bind_candidate_reader(
                    envelope["payload"], inventory_context
                )
            if envelope["payload"]["kind"] == "MUTATION_INTENT_CONSUMED":
                service_inventory.bind_authority_guard(
                    envelope["payload"]["authority_guard"],
                    inventory_context,
                    head_record_id=head_id,
                    head_record_sha256=head_sha256,
                )
            if (
                envelope["committer"]["activated_authority_head_record_id"] != head_id
                or envelope["committer"]["activated_authority_head_record_sha256"]
                != head_sha256
            ):
                raise service_inventory.ServiceInventoryError(
                    "committer activated-authority head mismatch"
                )
        except (
            service_inventory.ServiceInventoryError,
            service_activation.ServiceActivationError,
        ) as exc:
            raise contract.ReceiptValidationError(str(exc)) from exc
        _continuity(state, envelope, index)
        _apply(state, envelope)
        state.receipt_envelopes.append(copy.deepcopy(dict(envelope)))
        state.receipt_ids.append(envelope["receipt_id"])
    if require_terminal and state.phase != "TERMINAL":
        raise contract.ReceiptValidationError("receipt chain is not terminal")
    return state


def _authority_genesis(
    envelope: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], str, str]:
    verify(envelope)
    payload = envelope["payload"]
    if payload["kind"] != "REQUEST_ENQUEUED" or envelope["stream"]["sequence"] != 0:
        raise contract.ReceiptValidationError(
            "receipt stream authority genesis must be seq0 REQUEST_ENQUEUED"
        )
    record = payload["service_authority_activation_record"]
    inventory = record["activated_service_authorities"]
    head = payload["activated_authority_head"]
    head_id = service_activation.authority_head_record_id(head, record)
    head_sha256 = service_activation.authority_head_sha256(head, record)
    if (
        head_id != payload["activated_authority_head_record_id"]
        or head_sha256 != payload["activated_authority_head_record_sha256"]
    ):
        raise contract.ReceiptValidationError("authority genesis head digest mismatch")
    head_committed = contract.timestamp(
        head["committed_at"], "activated authority head committed_at"
    )
    receipt_observed = contract.timestamp(
        envelope["timestamps"]["observed_at"], "seq0 observed_at"
    )
    receipt_committed = contract.timestamp(
        envelope["timestamps"]["committed_at"], "seq0 committed_at"
    )
    if not head_committed <= receipt_observed <= receipt_committed:
        raise contract.ReceiptValidationError(
            "seq0 receipt precedes activated-authority head"
        )
    return record, inventory, head, head_id, head_sha256


def _continuity(state: ChainState, envelope: Mapping[str, Any], index: int) -> None:
    stream = envelope["stream"]
    expected_previous = "GENESIS" if index == 0 else state.receipt_ids[-1]
    if stream["sequence"] != index or stream["previous"] != expected_previous:
        raise contract.ReceiptValidationError("receipt sequence/previous mismatch")
    if index == 0:
        state.release_identity_id = stream["release_identity_id"]
        state.release_authority_id = stream["release_authority_id"]
        state.attempt = dict(envelope["attempt"])
        state.committer = dict(envelope["committer"])
    elif (
        stream["release_identity_id"] != state.release_identity_id
        or stream["release_authority_id"] != state.release_authority_id
        or envelope["committer"] != state.committer
    ):
        raise contract.ReceiptValidationError("receipt stream authority drift")
    elif envelope["attempt"] != state.attempt:
        recovery.roll_recovery_attempt(state, envelope)
    recovery.bind_controller_job(state, envelope)
    committed = envelope["timestamps"]["committed_at"]
    if state.last_committed_at is not None:
        contract.ordered_timestamps(
            state.last_committed_at,
            committed,
            "previous.committed_at",
            "current.committed_at",
        )
    state.last_committed_at = committed


def _apply(state: ChainState, envelope: Mapping[str, Any]) -> None:
    payload = envelope["payload"]
    event = event_key(payload)
    lease.apply_lease_boundary(state, envelope, event)
    _tag_boundary(state, payload)
    if event == "MUTATION_INTENT_CONSUMED":
        expected_phase = _CONSUMPTION_PHASES[payload["operation"]]
        if state.phase != expected_phase:
            raise contract.ReceiptValidationError("intent consumption phase mismatch")
        state.intent_ledger.consume(envelope)
        return
    if event.startswith("PYPI_FILE_"):
        publication.apply_pypi(state, payload)
        return
    if event == "PYPI_UPLOAD_SET_OBSERVED":
        if state.phase != "PYPI_UPLOAD_INTENT":
            raise contract.ReceiptValidationError("PyPI upload-set phase mismatch")
        _cross_bind(state, envelope, event)
        publication.apply_upload_set(state, payload)
        return
    if event.startswith("PYPI_GATE_"):
        publication.apply_gate(state, envelope, event)
        return
    if event in {
        "CANCELLATION",
        "RECOVERY_OBSERVATION",
        "RECOVERY_RESUMED",
        "RECOVERY_CLOSED_EXACT",
        "INCIDENT_HOLD",
        "INCIDENT_HOLD_RELEASED",
    }:
        recovery.apply_recovery(state, envelope, event)
        return
    if event.startswith("LEASE_"):
        return
    rule = RULE_BY_EVENT.get(event)
    if rule is None or state.phase not in rule.source:
        raise contract.ReceiptValidationError(
            f"state transition {state.phase} -> {event} is forbidden"
        )
    _cross_bind(state, envelope, event)
    state.phase = rule.target


def _tag_boundary(state: ChainState, payload: Mapping[str, Any]) -> None:
    if payload["kind"] == "GOVERNANCE_SNAPSHOT" and payload["label"] == "A":
        expected_release_identity = release_identity.release_identity_id(payload["tag"])
        _equal(
            state.release_identity_id,
            expected_release_identity,
            "canonical release identity",
        )
        state.tag = payload["tag"]
        state.tag_object_sha = payload["tag_object_sha"]
        state.peeled_commit_sha = payload["peeled_commit_sha"]
    for key in ("tag", "tag_object_sha", "peeled_commit_sha"):
        if key in payload and getattr(state, key) not in {None, payload[key]}:
            raise contract.ReceiptValidationError(f"release {key} drift")
    if payload["kind"] == "CANDIDATE_HANDOFF" and (
        state.tag_object_sha != payload["candidate_artifact_tag_object_sha"]
    ):
        raise contract.ReceiptValidationError("candidate/tag object mismatch")


def _cross_bind(state: ChainState, envelope: Mapping[str, Any], event: str) -> None:
    payload = envelope["payload"]
    operation = outcome_bindings.operation(payload)
    if operation is not None:
        state.intent_ledger.require_outcome(
            payload,
            operation=operation,
            expected_subject=outcome_bindings.subject(payload, operation),
            outcome_observed_at=envelope["timestamps"]["observed_at"],
            outcome_committed_at=envelope["timestamps"]["committed_at"],
        )
    if event == "CANDIDATE_HANDOFF":
        publication.bind_candidate(state, payload)
    elif event == "PUBLIC_BUNDLE_VERIFIED":
        publication.bind_bundle(state, payload)
    elif event.startswith("DRAFT_"):
        publication.bind_draft(state, payload, event)
    elif event.startswith("GOVERNANCE_"):
        publication.bind_governance(state, payload)
    elif event.startswith("INTENT_"):
        scope_value = (
            state.candidate_id if "candidate_id" in payload else state.authorization_id
        )
        scope_key = "candidate_id" if "candidate_id" in payload else "authorization_id"
        _equal(payload[scope_key], scope_value, "mutation intent scope")
        if payload["operation"].startswith("PYPI_DEPLOYMENT_"):
            if state.gate_binding is None:
                raise contract.ReceiptValidationError("gate request binding is missing")
            _equal(
                payload["subject"],
                outcome_bindings.deployment_subject(state.gate_binding),
                "gate decision intent subject",
            )
        elif payload["operation"] == "PYPI_FILE_UPLOAD_SET":
            publication.bind_upload_intent(state, payload)
        state.intent_ledger.record(envelope)
    elif event == "AUTHORIZED":
        _equal(payload["candidate_id"], state.candidate_id, "authorization candidate")
        _equal(payload["snapshot_a_sha256"], state.snapshots.get("A"), "snapshot A")
        _equal(payload["snapshot_b_sha256"], state.snapshots.get("B"), "snapshot B")
        _equal(
            contract.timestamp(payload["expires_at"], "authorization expires_at"),
            state.lease_expires_at,
            "authorization expiry",
        )
        state.authorization_id = payload["authorization_id"]
    elif event.startswith("GITHUB_RELEASE_"):
        _equal(
            payload["authorization_id"],
            state.authorization_id,
            "GitHub release authorization",
        )
        if "public_bundle_manifest_sha256" in payload:
            _equal(
                payload["public_bundle_manifest_sha256"],
                state.public_bundle_manifest_sha256,
                "GitHub release bundle",
            )
        publication.bind_github_release(state, payload)
    elif event == "CLOSED":
        closure.bind_closed(state, envelope)


def _equal(actual: Any, expected: Any, name: str) -> None:
    if actual != expected:
        raise contract.ReceiptValidationError(f"{name} mismatch")


_CONSUMPTION_PHASES = {
    "ATTESTATION_CREATE": "ATTESTATION_INTENT",
    "GITHUB_DRAFT_CREATE": "DRAFT_CREATE_INTENT",
    "GITHUB_DRAFT_ASSET_UPLOAD": "DRAFT_ASSET_INTENT",
    "GITHUB_DRAFT_UPDATE": "DRAFT_UPDATE_INTENT",
    "PYPI_DEPLOYMENT_APPROVE": "PYPI_GATE_DECISION_INTENT",
    "PYPI_DEPLOYMENT_REJECT": "PYPI_GATE_DECISION_INTENT",
    "PYPI_FILE_UPLOAD_SET": "PYPI_UPLOAD_INTENT",
    "GITHUB_RELEASE_PUBLISH": "GITHUB_PUBLISH_INTENT",
}
