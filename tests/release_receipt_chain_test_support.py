"""Shared support for receipt-v2 stream tests."""

from __future__ import annotations

import copy
from typing import Any, Mapping, Sequence

from tools.evidence.release_receipt_chain import verify_chain as _verify_chain
from tools.evidence.release_receipt_envelope_v2 import build


def verify_chain(
    receipts: Sequence[Mapping[str, Any]], *, require_terminal: bool = False
):
    """Verify self-contained streams using only their seq0 authority genesis."""

    return _verify_chain(receipts, require_terminal=require_terminal)


def _index(
    receipts: Sequence[Mapping[str, Any]], kind: str, transition: str | None = None
) -> int:
    return next(
        index
        for index, receipt in enumerate(receipts)
        if receipt["payload"]["kind"] == kind
        and (transition is None or receipt["payload"].get("transition") == transition)
    )


def _rebuilt(
    envelope: Mapping[str, Any],
    *,
    stream_sequence: int | None = None,
    fencing_token: int | None = None,
) -> dict[str, Any]:
    stream = dict(envelope["stream"])
    if stream_sequence is not None:
        stream["sequence"] = stream_sequence
    lease = copy.deepcopy(envelope.get("lease"))
    payload = copy.deepcopy(envelope["payload"])
    if fencing_token is not None:
        lease["fencing_token"] = fencing_token
        if "fencing_token" in payload:
            payload["fencing_token"] = fencing_token
    return build(
        stream=stream,
        scope=envelope["scope"],
        attempt=envelope["attempt"],
        lease=lease,
        producer=envelope["producer"],
        committer=envelope["committer"],
        timestamps=envelope["timestamps"],
        payload=payload,
    )


def _prior_consumption(
    receipts: Sequence[Mapping[str, Any]], outcome_index: int
) -> int:
    intent_id = receipts[outcome_index]["payload"]["intent_id"]
    return next(
        index
        for index in range(outcome_index - 1, -1, -1)
        if receipts[index]["payload"]["kind"] == "MUTATION_INTENT_CONSUMED"
        and receipts[index]["payload"]["intent_id"] == intent_id
    )


def _nth_index(receipts: Sequence[Mapping[str, Any]], kind: str, ordinal: int) -> int:
    matches = [
        index
        for index, receipt in enumerate(receipts)
        if receipt["payload"]["kind"] == kind
    ]
    return matches[ordinal - 1]


def _rechain(receipts: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for envelope in receipts:
        stream = {
            **envelope["stream"],
            "sequence": len(result),
            "previous": "GENESIS" if not result else result[-1]["receipt_id"],
        }
        result.append(_rebuilt({**envelope, "stream": stream}))
    return result
