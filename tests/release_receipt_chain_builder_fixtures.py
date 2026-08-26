"""Low-level receipt-v2 stream builder helpers."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from tests import release_receipt_fixtures as base
from tests import release_receipt_intent_fixtures as intent_fixture
from tools.evidence import release_authority_guard as authority_guard
from tools.evidence import release_receipt_contract as receipt_contract
from tools.evidence import release_receipt_intents as intents
from tools.evidence import release_receipt_consumption as consumption_contract
from tools.evidence import release_receipt_outcome_bindings as outcome_bindings
from tools.evidence.release_receipt_envelope_v2 import build, encode


def append_receipt(
    receipts: list[dict[str, Any]],
    payload: Mapping[str, Any],
    *,
    attempt: Mapping[str, Any] | None = None,
    lease: Mapping[str, Any] | None = None,
    producer_run: tuple[int, int] | None = None,
) -> None:
    bound_payload = copy.deepcopy(dict(payload))
    if bound_payload["kind"] == "MUTATION_INTENT_CONSUMED":
        intent = _intent_envelope(
            receipts, bound_payload["operation"], bound_payload["intent_id"]
        )
        source = intent["payload"]
        scope_key = (
            "candidate_id"
            if source["operation"] in intents.CANDIDATE_OPERATIONS
            else "authorization_id"
        )
        bound_payload.update(
            intent_receipt_id=intent["receipt_id"],
            intent_receipt_sha256=_byte_digest(intent),
            intent_subject_sha256=source["subject_identity_sha256"],
            lease_id=source["lease_id"],
            fencing_token=source["fencing_token"],
            attempt_id=source["attempt_id"],
            consumed_at=intent["timestamps"]["committed_at"],
        )
        bound_payload[scope_key] = source[scope_key]
        intent_fixture.attach_guard(bound_payload)
    operation = outcome_bindings.operation(bound_payload)
    if operation is not None:
        intent = _intent_envelope(receipts, operation, bound_payload["intent_id"])
        consumption = _consumption_envelope(receipts, intent["payload"]["intent_id"])
        if consumption is None:
            append_receipt(
                receipts,
                _consumption_payload(intent),
                attempt=attempt,
                lease=lease,
                producer_run=producer_run,
            )
            consumption = receipts[-1]
        bound_payload.update(
            intent_receipt_id=intent["receipt_id"],
            intent_receipt_sha256=_byte_digest(intent),
            intent_subject_sha256=intent["payload"]["subject_identity_sha256"],
            intent_consumption_receipt_id=consumption["receipt_id"],
            intent_consumption_receipt_sha256=_byte_digest(consumption),
        )
        for key in consumption_contract.OUTCOME_GUARD_KEYS:
            if key in consumption["payload"]:
                bound_payload[key] = consumption["payload"][key]
    producer = fixture_producer(
        bound_payload,
        producer_run=producer_run,
        sequence=len(receipts),
    )
    if bound_payload["kind"] == "MUTATION_INTENT_CONSUMED":
        if bound_payload["operation"] in authority_guard.GITHUB_ACTION_OPERATIONS:
            intent_fixture.attach_guard(bound_payload, github_consumer=producer)
        bound_payload["consumer_identity_sha256"] = (
            consumption_contract.consumer_identity_sha256(producer)
        )
    fixture = base.envelope_for(
        bound_payload,
        attempt=attempt,
        lease=lease,
        producer=producer,
    )
    sequence = len(receipts)
    previous = "GENESIS" if not receipts else receipts[-1]["receipt_id"]
    receipts.append(
        build(
            stream={
                **fixture["stream"],
                "sequence": sequence,
                "previous": previous,
            },
            scope=fixture["scope"],
            attempt=fixture["attempt"],
            lease=fixture.get("lease"),
            producer=producer,
            committer=fixture["committer"],
            timestamps=_timestamps(receipts, bound_payload),
            payload=fixture["payload"],
        )
    )


def fixture_producer(
    payload: Mapping[str, Any],
    *,
    producer_run: tuple[int, int] | None,
    sequence: int,
) -> dict[str, Any]:
    """Build the final producer projection used by both receipt and digest."""

    producer = dict(base._producer(payload))
    if producer_run is None or producer["kind"] != "github_actions_job":
        return producer
    producer["run_id"], producer["run_attempt"] = producer_run
    producer["check_run_id"] = producer_run[0] + 10_000
    producer["request_id"] = f"request-recovery-{sequence:04d}"
    producer["oidc_claims_sha256"] = base.digest(f"recovery OIDC claims/{sequence}")
    producer["oidc_jti_sha256"] = base.digest(f"recovery OIDC jti/{sequence}")
    producer["provider_job_observation_sha256"] = base.digest(
        f"recovery job observation/{sequence}"
    )
    return producer


def _byte_digest(envelope: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(encode(envelope)).hexdigest()


def _timestamps(
    receipts: list[dict[str, Any]], payload: Mapping[str, Any]
) -> dict[str, str]:
    floor = datetime(2026, 8, 15, tzinfo=timezone.utc)
    if receipts:
        floor = _parse(receipts[-1]["timestamps"]["committed_at"])
    events = [
        _parse(payload[key])
        for key in receipt_contract.HISTORICAL_EVENT_TIMESTAMP_FIELDS
        if key in payload
    ]
    observed = max([floor, *events])
    committed = observed + timedelta(seconds=1)
    return {"observed_at": _format(observed), "committed_at": _format(committed)}


def _intent_envelope(
    receipts: list[dict[str, Any]], operation: str, intent_id: str
) -> dict[str, Any]:
    for envelope in reversed(receipts):
        payload = envelope["payload"]
        if (
            payload["kind"] == "MUTATION_INTENT"
            and payload["operation"] == operation
            and payload["intent_id"] == intent_id
        ):
            return envelope
    raise AssertionError(f"fixture intent missing for {operation}")


def _consumption_envelope(
    receipts: list[dict[str, Any]], intent_id: str
) -> dict[str, Any] | None:
    return next(
        (
            envelope
            for envelope in reversed(receipts)
            if envelope["payload"]["kind"] == "MUTATION_INTENT_CONSUMED"
            and envelope["payload"]["intent_id"] == intent_id
        ),
        None,
    )


def _consumption_payload(intent: Mapping[str, Any]) -> dict[str, Any]:
    source = intent["payload"]
    operation = source["operation"]
    scope_key = (
        "candidate_id"
        if operation in intents.CANDIDATE_OPERATIONS
        else "authorization_id"
    )
    return {
        "kind": "MUTATION_INTENT_CONSUMED",
        "state": "MUTATION_INTENT_CONSUMED",
        "intent_id": source["intent_id"],
        "intent_receipt_id": intent["receipt_id"],
        "intent_receipt_sha256": _byte_digest(intent),
        "intent_subject_sha256": source["subject_identity_sha256"],
        "lease_id": source["lease_id"],
        "fencing_token": source["fencing_token"],
        "attempt_id": source["attempt_id"],
        "operation": operation,
        "capability_sha256": base.digest("capability/" + source["intent_id"]),
        "consumer_identity_sha256": base.digest("placeholder consumer"),
        "consumed_at": intent["timestamps"]["committed_at"],
        scope_key: source[scope_key],
    }


def _parse(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _format(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")
