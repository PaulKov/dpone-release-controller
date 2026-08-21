"""Stateful and adversarial tests for the receipt-v2 release stream."""

from __future__ import annotations

import copy
import unittest

from tests import release_receipt_chain_fixtures as chain_fixture
from tests import release_receipt_fixtures as base
from tests import release_receipt_intent_fixtures as intent_fixture
from tests import release_receipt_publish_fixtures as publish
from tests.release_receipt_chain_fixtures import (
    long_hold_reacquire_chain,
    no_external_retry_chain,
    partial_pypi_recovery_chain,
    published_github_recovery_chain,
    stale_intent_recovery_chain,
    successful_chain,
    terminal_no_external_retry_chain,
    terminal_partial_pypi_recovery_chain,
    terminal_published_github_recovery_chain,
    terminal_stale_intent_recovery_chain,
)
from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_consumption as consumption

from tests.release_receipt_chain_test_support import (
    _index,
    _nth_index,
    _rechain,
    verify_chain,
)


class ReleaseReceiptChainRecoveryTests(unittest.TestCase):
    def test_every_leased_receipt_commits_strictly_before_expiry(self) -> None:
        receipts = successful_chain()
        intent = next(
            index
            for index, receipt in enumerate(receipts)
            if receipt["payload"].get("operation") == "ATTESTATION_CREATE"
            and receipt["payload"]["kind"] == "MUTATION_INTENT"
        )
        for boundary in ("2026-08-15T00:06:00Z", "2026-08-15T00:06:01Z"):
            changed = copy.deepcopy(receipts)
            changed[intent]["timestamps"] = {
                "observed_at": boundary,
                "committed_at": boundary,
            }
            with self.assertRaisesRegex(
                contract.ReceiptValidationError, "at or after lease expiry"
            ):
                verify_chain(_rechain(changed))

    def test_recovery_rolls_attempt_once_and_reconciles_partial_or_published(
        self,
    ) -> None:
        retry = verify_chain(no_external_retry_chain())
        self.assertEqual(retry.phase, "LEASED")
        self.assertEqual(retry.recovery_origin_phase, "HYGIENE_VERIFIED")
        self.assertEqual(retry.attempt["queue_entry_id"], base.QUEUE_ID)
        self.assertNotEqual(
            retry.attempt["attempt_id"], retry.previous_attempt["attempt_id"]
        )

        partial = verify_chain(partial_pypi_recovery_chain())
        self.assertEqual(partial.phase, "PYPI_VERIFIED")
        self.assertEqual(partial.pypi_verified_count, 8)

        published = verify_chain(published_github_recovery_chain())
        self.assertEqual(published.phase, "GITHUB_IMMUTABLE")
        self.assertTrue(published.immutable_release_verified)

    def test_every_recovery_branch_continues_to_c5_and_fenced_terminal(self) -> None:
        traces = (
            terminal_no_external_retry_chain(),
            terminal_partial_pypi_recovery_chain(),
            terminal_published_github_recovery_chain(),
            terminal_stale_intent_recovery_chain(),
        )
        for receipts in traces:
            with self.subTest(receipt_count=len(receipts)):
                state = verify_chain(receipts, require_terminal=True)
                self.assertEqual(state.phase, "TERMINAL")
                self.assertEqual(state.attempt["attempt_id"], base.RECOVERY_ATTEMPT_ID)
                self.assertEqual(state.previous_attempt["attempt_id"], base.ATTEMPT_ID)
                recovery = _nth_index(receipts, "LEASE_ACQUIRED", 2)
                self.assertEqual(receipts[recovery]["producer"]["run_id"], 223_456_789)
                self.assertEqual(receipts[recovery]["lease"]["fencing_token"], 4)
                self.assertEqual(receipts[-1]["payload"]["kind"], "CLOSED")
                self.assertIsNone(state.lease_id)

    def test_incident_hold_survives_expiry_and_releases_before_new_lease(self) -> None:
        receipts = long_hold_reacquire_chain()
        state = verify_chain(receipts)
        self.assertEqual(state.phase, "RECOVERY_LEASED")
        self.assertEqual(state.fencing_token, 5)
        self.assertIsNone(state.recovery_hold_id)
        expired = _index(receipts, "LEASE_EXPIRED")
        released = _index(receipts, "INCIDENT_HOLD_RELEASED")
        reacquired = _nth_index(receipts, "LEASE_ACQUIRED", 3)
        self.assertNotIn("lease", receipts[released])
        self.assertLess(expired, released)
        self.assertLess(released, reacquired)

        wrong = copy.deepcopy(receipts[: released + 1])
        wrong[released]["payload"]["hold_id"] = base.digest("wrong hold")
        with self.assertRaisesRegex(contract.ReceiptValidationError, "hold identity"):
            verify_chain(_rechain(wrong))

        replay = copy.deepcopy(receipts[: released + 1])
        chain_fixture._append(
            replay,
            publish.hold_released(),
            attempt={
                "attempt_id": base.RECOVERY_ATTEMPT_ID,
                "queue_entry_id": base.QUEUE_ID,
            },
            producer_run=(223_456_789, 1),
        )
        with self.assertRaisesRegex(contract.ReceiptValidationError, "transition"):
            verify_chain(replay)

    def test_closed_is_atomic_and_other_lease_release_reasons_remain_exact(
        self,
    ) -> None:
        terminal = successful_chain()
        state = verify_chain(terminal, require_terminal=True)
        self.assertIsNone(state.lease_id)
        self.assertFalse(
            any(
                envelope["payload"]["kind"] == "LEASE_RELEASED" for envelope in terminal
            )
        )

        prefix = copy.deepcopy(
            terminal[: _index(terminal, "TENANT_HYGIENE_VERIFIED") + 1]
        )
        chain_fixture._append(prefix, publish.cancellation(False))
        released = base._lease_released()
        released.update(reason="CANCELLED", released_at="2026-08-15T00:03:01Z")
        chain_fixture._append(prefix, released)
        self.assertEqual(verify_chain(prefix).phase, "ABORTED")
        prefix[-1]["payload"]["reason"] = "RECOVERY_REQUIRED"
        prefix[-1]["producer"] = base._producer(prefix[-1]["payload"])
        with self.assertRaisesRegex(contract.ReceiptValidationError, "state/reason"):
            verify_chain(_rechain(prefix))

        crash = copy.deepcopy(
            terminal[: _index(terminal, "TENANT_HYGIENE_VERIFIED") + 1]
        )
        chain_fixture._append(crash, publish.cancellation(False))
        expired = base._lease_expired()
        expired.update(
            external_commit_observed=False,
            next_state="ABORTED",
            expired_at="2026-08-15T00:05:45Z",
        )
        del expired["recovery_id"]
        chain_fixture._append(crash, expired)
        self.assertEqual(verify_chain(crash).phase, "ABORTED")
        changed = copy.deepcopy(crash)
        changed[-1]["payload"]["next_state"] = "RECOVERY_REQUIRED"
        changed[-1]["payload"]["recovery_id"] = base.RECOVERY_ID
        with self.assertRaisesRegex(contract.ReceiptValidationError, "expiry state"):
            verify_chain(_rechain(changed))

    def test_cancellation_cannot_overwrite_hold_or_closed_finalization(self) -> None:
        successful = successful_chain()
        prefixes = (
            successful,
            long_hold_reacquire_chain()[
                : _index(long_hold_reacquire_chain(), "INCIDENT_HOLD") + 1
            ],
        )
        for prefix in prefixes:
            changed = copy.deepcopy(prefix)
            chain_fixture._append(
                changed,
                publish.cancellation(True),
                attempt=prefix[-1]["attempt"],
                lease=prefix[-1].get("lease"),
            )
            with (
                self.subTest(phase=verify_chain(prefix).phase),
                self.assertRaisesRegex(
                    contract.ReceiptValidationError,
                    "active lease/fence mismatch|cancellation source phase",
                ),
            ):
                verify_chain(changed)

    def test_recovery_rejects_same_attempt_queue_drift_and_old_fence_intent(
        self,
    ) -> None:
        receipts = no_external_retry_chain()
        recovery_lease = _nth_index(receipts, "LEASE_ACQUIRED", 2)

        changed = copy.deepcopy(receipts)
        changed[recovery_lease]["attempt"] = {
            "attempt_id": base.ATTEMPT_ID,
            "queue_entry_id": base.QUEUE_ID,
        }
        changed[recovery_lease]["payload"]["attempt_id"] = base.ATTEMPT_ID
        changed[recovery_lease]["producer"]["run_id"] = 123_456_789
        changed[recovery_lease]["producer"]["run_attempt"] = 2
        with self.assertRaisesRegex(contract.ReceiptValidationError, "rollover"):
            verify_chain(_rechain(changed))

        changed = copy.deepcopy(receipts)
        other_queue = base.digest("other queue")
        changed[recovery_lease]["attempt"]["queue_entry_id"] = other_queue
        changed[recovery_lease]["payload"]["queue_entry_id"] = other_queue
        with self.assertRaisesRegex(contract.ReceiptValidationError, "rollover"):
            verify_chain(_rechain(changed))

        state = verify_chain(stale_intent_recovery_chain())
        old = next(
            record
            for record in state.intent_ledger.by_id.values()
            if record.operation == "GITHUB_RELEASE_PUBLISH" and record.invalidated
        )
        self.assertFalse(old.consumed)
        stale_payload = {
            "kind": "MUTATION_INTENT_CONSUMED",
            "state": "MUTATION_INTENT_CONSUMED",
            "intent_id": old.intent_id,
            "intent_receipt_id": old.receipt_id,
            "intent_receipt_sha256": old.receipt_sha256,
            "intent_subject_sha256": old.subject_identity_sha256,
            "lease_id": base.RECOVERY_LEASE_ID,
            "fencing_token": 4,
            "attempt_id": base.RECOVERY_ATTEMPT_ID,
            "operation": old.operation,
            "capability_sha256": base.digest("stale capability"),
            "consumer_identity_sha256": base.digest("placeholder"),
            "consumed_at": "2026-08-15T00:06:10Z",
            "authorization_id": base.AUTHORIZATION_ID,
        }
        intent_fixture.attach_guard(stale_payload)
        producer = base._producer(stale_payload)
        stale_payload["consumer_identity_sha256"] = (
            consumption.consumer_identity_sha256(producer)
        )
        stale = base.envelope_for(
            stale_payload,
            attempt=state.attempt,
            lease={"lease_id": base.RECOVERY_LEASE_ID, "fencing_token": 4},
            producer=producer,
        )
        with self.assertRaisesRegex(contract.ReceiptValidationError, "invalidated"):
            state.intent_ledger.consume(stale)

    def test_external_state_and_ambiguous_consumption_cannot_be_abandoned(
        self,
    ) -> None:
        complete = successful_chain()
        endpoints = (
            _index(complete, "DRAFT_TRANSITION", "CREATED"),
            _index(complete, "PYPI_UPLOAD_SET_OBSERVED"),
            _index(complete, "MUTATION_INTENT_CONSUMED"),
        )
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                changed = copy.deepcopy(complete[: endpoint + 1])
                chain_fixture._append(changed, publish.cancellation(False))
                with self.assertRaisesRegex(
                    contract.ReceiptValidationError, "external commit observation"
                ):
                    verify_chain(changed)

        changed = copy.deepcopy(
            complete[: _index(complete, "DRAFT_TRANSITION", "CREATED") + 1]
        )
        expired = base._lease_expired()
        expired["external_commit_observed"] = False
        chain_fixture._append(changed, expired)
        with self.assertRaisesRegex(
            contract.ReceiptValidationError, "external commit observation"
        ):
            verify_chain(changed)
