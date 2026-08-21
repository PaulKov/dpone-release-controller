"""Happy-path receipt-v2 stream fixtures."""

from __future__ import annotations

import copy
from functools import lru_cache
from typing import Any

from tests import release_receipt_gate_fixtures as gate
from tests import release_receipt_publish_fixtures as publish
from tests import release_receipt_fixtures as base
from tests import release_receipt_intent_fixtures as intent_fixture

from tests.release_receipt_chain_builder_fixtures import append_receipt as _append
from tests.release_receipt_chain_pypi_fixtures import (
    PYPI_FILES as _PYPI_FILES,
    pypi_file as _pypi_file,
)


def successful_chain() -> list[dict[str, Any]]:
    """Return the exact active path ending at internal ledger CLOSED."""

    return copy.deepcopy(_successful_chain())


@lru_cache(maxsize=1)
def _successful_chain() -> list[dict[str, Any]]:
    """Build the expensive immutable happy-path fixture once per process."""

    payloads: list[dict[str, Any]] = [
        base._request(),
        base._governance("A"),
        base._candidate(),
        base._lease_acquired(),
        base._lease_renewed(),
        base._hygiene(),
        intent_fixture.intent("ATTESTATION_CREATE"),
        base._attestation(),
        base._bundle(),
        intent_fixture.intent("GITHUB_DRAFT_CREATE"),
        base._draft_created(),
    ]
    for index in range(17):
        intent = intent_fixture.intent("GITHUB_DRAFT_ASSET_UPLOAD", asset_index=index)
        asset = base._draft_asset(index)
        payloads.extend((intent, asset))
    payloads.extend(
        (
            intent_fixture.intent("GITHUB_DRAFT_UPDATE"),
            base._draft_inventory("STAGED"),
            base._draft_inventory("VERIFIED"),
            base._governance("B"),
            publish.authorized(),
            gate.requested(),
            intent_fixture.intent("PYPI_DEPLOYMENT_APPROVE"),
            gate.approved(),
        )
    )
    for project, filename in _PYPI_FILES:
        for transition in ("PENDING_UPLOAD", "SEALED_FOR_UPLOAD"):
            payloads.append(_pypi_file(project, filename, transition, 0))
    payloads.extend(
        (
            intent_fixture.intent("PYPI_FILE_UPLOAD_SET"),
            publish.upload_set(),
        )
    )
    for verified_count, (project, filename) in enumerate(_PYPI_FILES, start=1):
        payloads.append(
            _pypi_file(project, filename, "INTEGRITY_VERIFIED", verified_count)
        )
    payloads.extend(
        (
            intent_fixture.intent("GITHUB_RELEASE_PUBLISH"),
            publish.github("PUBLISH_ACCEPTED"),
            publish.github("IMMUTABLE_VERIFIED"),
            base._governance("C"),
            publish.closed(),
        )
    )
    receipts: list[dict[str, Any]] = []
    for payload in payloads:
        _append(receipts, payload)
    return receipts
