"""Gate and recovery scenario fixtures for receipt-v2 streams."""

from __future__ import annotations

import copy
from typing import Any

from tests import release_receipt_gate_fixtures as gate
from tests import release_receipt_publish_fixtures as publish
from tests import release_receipt_fixtures as base
from tests import release_receipt_intent_fixtures as intent_fixture
from tools.evidence import release_identity

from tests.release_receipt_chain_builder_fixtures import append_receipt
from tests.release_receipt_chain_happy_fixtures import successful_chain
from tests.release_receipt_chain_pypi_fixtures import PYPI_FILES, pypi_file
from tests.release_receipt_chain_recovery_fixtures import (
    append_recovery,
    append_recovery_tail,
    begin_recovery,
    recovery_lease_acquired,
)


def gate_decision_chain(
    decision: str,
    *,
    ambiguous: bool = False,
    resolution: str | None = None,
) -> list[dict[str, Any]]:
    """Return a verified prefix through one direct or reconciled gate decision."""

    if decision not in {"APPROVE", "REJECT"}:
        raise ValueError("gate decision must be APPROVE or REJECT")
    complete = successful_chain()
    requested_index = next(
        index
        for index, envelope in enumerate(complete)
        if envelope["payload"]["kind"] == "PYPI_GATE_REQUESTED"
    )
    receipts = copy.deepcopy(complete[: requested_index + 1])
    operation = f"PYPI_DEPLOYMENT_{decision}"
    append_receipt(receipts, intent_fixture.intent(operation))
    if ambiguous:
        outcome = gate.ambiguous()
        outcome["attempted_decision"] = decision
        outcome.update(intent_fixture.consumption(operation))
    else:
        outcome = gate.approved() if decision == "APPROVE" else gate.rejected()
    append_receipt(receipts, outcome)
    if resolution is not None:
        reconciled = gate.reconciled()
        reconciled["attempted_decision"] = decision
        reconciled["resolution"] = resolution
        reconciled["state"] = {
            "APPROVED_CONFIRMED": "PYPI_GATE_APPROVED",
            "REJECTED_CONFIRMED": "PYPI_GATE_REJECTED",
            "STILL_PENDING": "PYPI_GATE_PENDING",
        }[resolution]
        reconciled["original_ambiguity_receipt_id"] = receipts[-1]["receipt_id"]
        reconciled["new_decision_intent_required"] = resolution == "STILL_PENDING"
        append_receipt(receipts, reconciled)
    return receipts


def gate_retry_chain(decision: str = "APPROVE") -> list[dict[str, Any]]:
    """Return STILL_PENDING followed by a new, separately mirrored intent."""

    receipts = gate_decision_chain(decision, ambiguous=True, resolution="STILL_PENDING")
    retry = intent_fixture.intent(f"PYPI_DEPLOYMENT_{decision}")
    retry["intent_id"] = base.digest(f"gate retry/{decision}")
    append_receipt(receipts, retry)
    return receipts


def partial_pypi_recovery_chain() -> list[dict[str, Any]]:
    """Recover a provider-observed four-file partial pypa upload."""

    complete = successful_chain()
    complete_upload = next(
        index
        for index, envelope in enumerate(complete)
        if envelope["payload"]["kind"] == "PYPI_UPLOAD_SET_OBSERVED"
    )
    receipts = copy.deepcopy(complete[:complete_upload])
    first_four = base._distributions()[:4]
    append_receipt(
        receipts,
        publish.upload_set(
            "PARTIAL",
            accepted_files=first_four,
        ),
    )
    begin_recovery(receipts)
    observation = publish.recovery(file_count=4, github_state="DRAFT")
    append_recovery(receipts, observation)
    resumed = publish.recovery_resumed(file_count=4)
    resumed["observation_receipt_id"] = receipts[-1]["receipt_id"]
    append_recovery(receipts, resumed)
    for verified_count, (project, filename) in enumerate(PYPI_FILES[:4], start=1):
        recovered = pypi_file(
            project,
            filename,
            "ALREADY_PUBLISHED_EXACT",
            verified_count,
        )
        append_recovery(receipts, recovered)
    remaining = base._distributions()[4:]
    retry_intent = intent_fixture.intent("PYPI_FILE_UPLOAD_SET", upload_files=remaining)
    retry_intent.update(
        intent_id=base.digest("recovery PyPI upload intent"),
        lease_id=base.RECOVERY_LEASE_ID,
        fencing_token=4,
        attempt_id=base.RECOVERY_ATTEMPT_ID,
    )
    append_recovery(receipts, retry_intent)
    retry_observation = publish.upload_set(
        "COMPLETE", upload_files=remaining, accepted_files=remaining
    )
    retry_observation["intent_id"] = retry_intent["intent_id"]
    retry_observation["intent_subject_sha256"] = retry_intent["subject_identity_sha256"]
    append_recovery(receipts, retry_observation)
    for verified_count, (project, filename) in enumerate(PYPI_FILES[4:], start=5):
        append_recovery(
            receipts,
            pypi_file(
                project,
                filename,
                "INTEGRITY_VERIFIED",
                verified_count,
            ),
        )
    return receipts


def published_github_recovery_chain() -> list[dict[str, Any]]:
    """Reconcile an ambiguous immutable publish without mutating GitHub again."""

    complete = successful_chain()
    published = next(
        index
        for index, envelope in enumerate(complete)
        if envelope["payload"].get("transition") == "PUBLISH_ACCEPTED"
    )
    receipts = copy.deepcopy(complete[: published + 1])
    begin_recovery(receipts)
    observation = publish.recovery(file_count=8, github_state="PUBLISHED")
    append_recovery(receipts, observation)
    exact = publish.recovery_closed_exact()
    exact["observation_receipt_id"] = receipts[-1]["receipt_id"]
    append_recovery(receipts, exact)
    return receipts


def no_external_retry_chain() -> list[dict[str, Any]]:
    """Roll a lost pre-mutation lease into a fresh attempt and fence."""

    complete = successful_chain()
    hygiene = next(
        index
        for index, envelope in enumerate(complete)
        if envelope["payload"]["kind"] == "TENANT_HYGIENE_VERIFIED"
    )
    receipts = copy.deepcopy(complete[: hygiene + 1])
    expired = base._lease_expired()
    expired["external_commit_observed"] = False
    append_receipt(receipts, expired)
    append_recovery(receipts, recovery_lease_acquired())
    observation = publish.recovery(file_count=0, github_state="NONE")
    append_recovery(receipts, observation)
    resumed = publish.recovery_resumed(file_count=0)
    resumed["observation_receipt_id"] = receipts[-1]["receipt_id"]
    append_recovery(receipts, resumed)
    return receipts


def stale_intent_recovery_chain() -> list[dict[str, Any]]:
    """Invalidate an old publish intent and issue a new-fence replacement."""

    complete = successful_chain()
    old_intent = next(
        index
        for index, envelope in enumerate(complete)
        if envelope["payload"].get("operation") == "GITHUB_RELEASE_PUBLISH"
        and envelope["payload"]["kind"] == "MUTATION_INTENT"
    )
    receipts = copy.deepcopy(complete[: old_intent + 1])
    begin_recovery(receipts)
    observation = publish.recovery(file_count=8, github_state="DRAFT")
    append_recovery(receipts, observation)
    resumed = publish.recovery_resumed(file_count=8)
    resumed["observation_receipt_id"] = receipts[-1]["receipt_id"]
    append_recovery(receipts, resumed)
    replacement = intent_fixture.intent("GITHUB_RELEASE_PUBLISH")
    replacement.update(
        intent_id=base.digest("recovery GitHub publish intent"),
        lease_id=base.RECOVERY_LEASE_ID,
        fencing_token=4,
        attempt_id=base.RECOVERY_ATTEMPT_ID,
    )
    append_recovery(receipts, replacement)
    return receipts


def terminal_no_external_retry_chain() -> list[dict[str, Any]]:
    """Complete the full release pipeline under the rolled recovery attempt."""

    receipts = no_external_retry_chain()
    append_recovery_tail(receipts, "TENANT_HYGIENE_VERIFIED")
    return receipts


def terminal_partial_pypi_recovery_chain() -> list[dict[str, Any]]:
    """Continue a partial exact PyPI recovery through C5 and fenced release."""

    receipts = partial_pypi_recovery_chain()
    append_recovery_tail(receipts, "MUTATION_INTENT:GITHUB_RELEASE_PUBLISH")
    return receipts


def terminal_published_github_recovery_chain() -> list[dict[str, Any]]:
    """Continue provider-observed immutable GitHub state through terminal."""

    receipts = published_github_recovery_chain()
    append_recovery_tail(receipts, "GOVERNANCE_SNAPSHOT:C")
    return receipts


def terminal_stale_intent_recovery_chain() -> list[dict[str, Any]]:
    """Consume only the replacement-fence publish intent and reach terminal."""

    receipts = stale_intent_recovery_chain()
    append_recovery_tail(receipts, "MUTATION_INTENT_CONSUMED:GITHUB_RELEASE_PUBLISH")
    return receipts


def long_hold_reacquire_chain() -> list[dict[str, Any]]:
    """Preserve an incident hold across expiry and roll a fresh attempt after release."""

    complete = successful_chain()
    upload = next(
        index
        for index, envelope in enumerate(complete)
        if envelope["payload"]["kind"] == "PYPI_UPLOAD_SET_OBSERVED"
    )
    receipts = copy.deepcopy(complete[:upload])
    append_receipt(
        receipts,
        publish.upload_set("PARTIAL", accepted_files=base._distributions()[:4]),
    )
    begin_recovery(receipts)
    observation = publish.recovery(file_count=4, github_state="DRAFT")
    observation["next_action"] = "INCIDENT_HOLD"
    append_recovery(receipts, observation)
    held = publish.hold()
    held["started_at"] = "2026-08-15T00:06:05Z"
    append_recovery(receipts, held)
    expired = base._lease_expired()
    expired.update(
        lease_id=base.RECOVERY_LEASE_ID,
        fencing_token=4,
        expired_at="2026-08-15T00:11:02Z",
        next_state="INCIDENT_HOLD",
    )
    append_recovery(receipts, expired)
    append_receipt(
        receipts,
        publish.hold_released(),
        attempt={
            "attempt_id": base.RECOVERY_ATTEMPT_ID,
            "queue_entry_id": base.QUEUE_ID,
        },
        producer_run=(223_456_789, 1),
    )
    second_run = (323_456_789, 1)
    second_attempt = release_identity.attempt_id(
        release_authority_id=base.AUTHORITY_ID,
        controller_workflow_id=316_322_127,
        controller_run_id=second_run[0],
        controller_run_attempt=second_run[1],
    )
    second_lease = base.digest("second recovery lease")
    acquire = recovery_lease_acquired()
    acquire.update(
        lease_id=second_lease,
        fencing_token=5,
        acquired_at="2026-08-15T00:30:02Z",
        expires_at="2026-08-15T00:35:02Z",
        attempt_id=second_attempt,
        previous_attempt_id=base.RECOVERY_ATTEMPT_ID,
    )
    append_receipt(
        receipts,
        acquire,
        attempt={"attempt_id": second_attempt, "queue_entry_id": base.QUEUE_ID},
        lease={"lease_id": second_lease, "fencing_token": 5},
        producer_run=second_run,
    )
    return receipts
