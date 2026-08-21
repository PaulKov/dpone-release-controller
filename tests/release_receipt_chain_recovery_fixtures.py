"""Recovery rebinding helpers for receipt-v2 streams."""

from __future__ import annotations

import copy
from typing import Any, Mapping

from tests import release_receipt_publish_fixtures as publish
from tests import release_receipt_fixtures as base
from tools.evidence import release_receipt_intents as intents
from tools.evidence import release_receipt_payload_state_contract as state_contract
from tools.evidence import release_receipt_outcome_bindings as outcome_bindings
from tools.evidence.release_receipt_chain import verify_chain

from tests.release_receipt_chain_builder_fixtures import append_receipt


def append_recovery_tail(receipts: list[dict[str, Any]], start_selector: str) -> None:
    from tests.release_receipt_chain_happy_fixtures import successful_chain

    template = successful_chain()
    start = next(
        index
        for index, envelope in enumerate(template)
        if state_contract.selector_for(envelope["payload"]) == start_selector
    )
    closed = next(
        index
        for index, envelope in enumerate(template)
        if envelope["payload"]["kind"] == "CLOSED"
    )
    for envelope in template[start : closed + 1]:
        payload = recovery_payload(envelope["payload"])
        bind_latest_intent_id(receipts, payload)
        append_recovery(receipts, payload)


def bind_latest_intent_id(
    receipts: list[dict[str, Any]], payload: dict[str, Any]
) -> None:
    operation = (
        payload.get("operation")
        if payload["kind"] == "MUTATION_INTENT_CONSUMED"
        else outcome_bindings.operation(payload)
    )
    if operation is None:
        return
    latest = next(
        envelope["payload"]
        for envelope in reversed(receipts)
        if envelope["payload"]["kind"] == "MUTATION_INTENT"
        and envelope["payload"]["operation"] == operation
    )
    payload["intent_id"] = latest["intent_id"]


def recovery_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Rebind a fixture payload to the new recovery run, attempt, and fence."""

    def transform(item: Any, key: str | None = None) -> Any:
        if isinstance(item, Mapping):
            return {name: transform(child, name) for name, child in item.items()}
        if isinstance(item, list):
            return [transform(child) for child in item]
        if key == "lease_id" and item == base.LEASE_ID:
            return base.RECOVERY_LEASE_ID
        if key == "fencing_token" and item == 3:
            return 4
        if key in {"attempt_id", "previous_attempt_id"} and item == base.ATTEMPT_ID:
            return base.RECOVERY_ATTEMPT_ID
        if key == "controller_run_id" and item == 123_456_789:
            return 223_456_789
        if key == "controller_run_attempt" and item == 2:
            return 1
        if key in {"artifact_name", "closure_artifact_name"} and isinstance(item, str):
            return "release-controller-closure-223456789-1"
        if key == "external_id" and isinstance(item, str):
            return f"dpone-release-controller.closed.v1|{base.RELEASE_ID}|223456789|1"
        return item

    payload = transform(copy.deepcopy(dict(value)))
    assert isinstance(payload, dict)
    if payload["kind"] == "MUTATION_INTENT":
        payload["subject_identity_sha256"] = intents.subject_identity_sha256(
            payload["operation"], payload["subject"]
        )
    if payload["kind"] == "AUTHORIZED":
        payload["expires_at"] = "2026-08-15T00:11:02Z"
    if payload["kind"] == "LEASE_RELEASED":
        payload["released_at"] = "2026-08-15T00:09:21Z"
    return payload


def begin_recovery(receipts: list[dict[str, Any]]) -> None:
    # Provider-derived partial/ambiguous branches already entered
    # RECOVERY_REQUIRED.  Only an ordinary in-flight release first needs the
    # same-attempt cancellation edge; duplicating it would overwrite durable
    # recovery authority.
    if verify_chain(receipts).phase != "RECOVERY_REQUIRED":
        append_receipt(receipts, publish.cancellation(True))
    released = base._lease_released()
    released.update(
        released_at="2026-08-15T00:03:01Z",
        reason="RECOVERY_REQUIRED",
    )
    append_receipt(receipts, released)
    append_recovery(receipts, recovery_lease_acquired())


def append_recovery(receipts: list[dict[str, Any]], payload: Mapping[str, Any]) -> None:
    append_receipt(
        receipts,
        payload,
        attempt={
            "attempt_id": base.RECOVERY_ATTEMPT_ID,
            "queue_entry_id": base.QUEUE_ID,
        },
        lease={"lease_id": base.RECOVERY_LEASE_ID, "fencing_token": 4},
        producer_run=(223_456_789, 1),
    )


def recovery_lease_acquired() -> dict[str, Any]:
    return {
        "kind": "LEASE_ACQUIRED",
        "state": "LEASE_ACQUIRED",
        "lease_id": base.RECOVERY_LEASE_ID,
        "fencing_token": 4,
        "acquired_at": "2026-08-15T00:06:02Z",
        "expires_at": "2026-08-15T00:11:02Z",
        "ttl_seconds": 300,
        "renew_interval_seconds": 45,
        "attempt_id": base.RECOVERY_ATTEMPT_ID,
        "queue_entry_id": base.QUEUE_ID,
        "recovery_acquisition": True,
        "recovery_id": base.RECOVERY_ID,
        "previous_attempt_id": base.ATTEMPT_ID,
        "previous_queue_entry_id": base.QUEUE_ID,
    }
