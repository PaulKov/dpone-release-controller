"""INTERNAL/CONFIDENTIAL historical chain tail; NOT PUBLICATION data."""

from __future__ import annotations

import copy
import hashlib
from typing import Any

from tests import release_receipt_publish_fixtures as publish
from tests import release_receipt_fixtures as base
from tests import release_receipt_intent_fixtures as intent_fixture
from tests.release_closed_marker_fixtures import marker as build_closed_marker
from tools.evidence import release_private_closed_marker as marker_contract
from tools.evidence import release_private_closure_inventory as closure_inventory
from tools.evidence import release_receipt_intents as intents
from tools.evidence.release_receipt_envelope_v2 import encode
from tools.evidence.release_receipt_state_contract import receipt_chain_sha256

from tests.release_receipt_chain_builder_fixtures import append_receipt
from tests.release_receipt_chain_recovery_fixtures import (
    append_recovery,
    recovery_payload,
)


def append_closure_suffix(receipts: list[dict[str, Any]], *, recovery: bool) -> None:
    """Append closure/check/release under the current fenced attempt."""

    append = append_recovery if recovery else append_receipt
    closed = receipts[-1]
    closure_intent = intent_fixture.intent("GITHUB_CLOSURE_ARTIFACT_UPLOAD")
    if recovery:
        closure_intent = recovery_payload(closure_intent)
    closure_intent["subject"].update(
        closed_receipt_id=closed["receipt_id"],
        closed_receipt_sha256=("sha256:" + hashlib.sha256(encode(closed)).hexdigest()),
    )
    chain_digest = receipt_chain_sha256(receipts)
    dynamic_member_digests = {
        closure_inventory.CLOSED_RECEIPT_PATH: closure_intent["subject"][
            "closed_receipt_sha256"
        ],
        closure_inventory.RECEIPT_CHAIN_PATH: chain_digest,
    }
    for member in closure_intent["subject"]["member_inventory"]:
        if member["path"] in dynamic_member_digests:
            member["sha256"] = dynamic_member_digests[member["path"]]
    closure_intent["subject"]["member_inventory_sha256"] = closure_inventory.digest(
        closure_intent["subject"]["member_inventory"]
    )
    closure_intent["subject_identity_sha256"] = intents.subject_identity_sha256(
        closure_intent["operation"], closure_intent["subject"]
    )
    append(receipts, closure_intent)
    closure = publish.closure_artifact()
    if recovery:
        closure = recovery_payload(closure)
    closure["closed_receipt_id"] = closed["receipt_id"]
    closure["closed_receipt_sha256"] = (
        "sha256:" + hashlib.sha256(encode(closed)).hexdigest()
    )
    closure["receipt_chain_sha256"] = chain_digest
    closure["closure_artifact_member_inventory"] = copy.deepcopy(
        closure_intent["subject"]["member_inventory"]
    )
    closure["closure_artifact_member_inventory_sha256"] = closure_intent["subject"][
        "member_inventory_sha256"
    ]
    closure["closure_artifact_expanded_bytes"] = closure_intent["subject"][
        "total_bytes"
    ]
    closure["intent_id"] = closure_intent["intent_id"]
    closure["intent_subject_sha256"] = closure_intent["subject_identity_sha256"]
    append(receipts, closure)
    check_intent = intent_fixture.intent("GITHUB_CLOSED_CHECK_PROJECT")
    if recovery:
        check_intent = recovery_payload(check_intent)
    check_intent["subject"].update(
        closed_receipt_id=closure["closed_receipt_id"],
        closure_artifact_id=closure["closure_artifact_id"],
        closure_artifact_digest=closure["closure_artifact_digest"],
    )
    check_intent["subject_identity_sha256"] = intents.subject_identity_sha256(
        check_intent["operation"], check_intent["subject"]
    )
    append(receipts, check_intent)
    for transition in ("PROJECTED", "VERIFIED"):
        check = publish.closed_check(transition)
        if recovery:
            check = recovery_payload(check)
        for key in _CLOSURE_BINDING_KEYS:
            check[key] = closure[key]
        marker = build_closed_marker(check)
        check["output_marker"] = marker
        check["closed_marker_sha256"] = marker_contract.sha256(marker)
        check["output_marker_sha256"] = check["closed_marker_sha256"]
        check["output_summary_sha256"] = (
            "sha256:"
            + hashlib.sha256(
                marker_contract.summary(marker).encode("ascii")
            ).hexdigest()
        )
        if transition == "PROJECTED":
            check["intent_id"] = check_intent["intent_id"]
            check["intent_subject_sha256"] = check_intent["subject_identity_sha256"]
        append(receipts, check)
    released = base._lease_released()
    if recovery:
        released = recovery_payload(released)
    append(receipts, released)


_CLOSURE_BINDING_KEYS = frozenset(
    {
        "release_identity_id",
        "tag",
        "tag_object_sha",
        "peeled_commit_sha",
        "closed_receipt_id",
        "closed_receipt_sha256",
        "closure_artifact_id",
        "controller_run_id",
        "controller_run_attempt",
        "controller_workflow_id",
        "controller_workflow_sha",
        "controller_action_commit_sha",
        "controller_action_metadata_blob_sha",
        "controller_action_bundle_sha256",
        "closure_artifact_name",
        "closure_artifact_digest",
        "closure_artifact_member_inventory_sha256",
        "closure_manifest_sha256",
        "release_evidence_sha256",
        "receipt_chain_sha256",
    }
)
