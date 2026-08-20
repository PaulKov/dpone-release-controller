"""Stateful and adversarial tests for the receipt-v2 release stream."""

from __future__ import annotations

import copy
import unittest

from tests import release_receipt_fixtures as base
from tests import release_receipt_intent_fixtures as intent_fixture
from tests import release_receipt_publish_fixtures as publish
from tests.release_receipt_chain_fixtures import (
    gate_decision_chain,
    gate_retry_chain,
    successful_chain,
)
from tests.release_receipt_fixtures import envelope_for
from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_identity
from tools.evidence import release_receipt_intents as intents
from tools.evidence.release_receipt_state_contract import (
    receipt_chain_document,
    receipt_chain_sha256,
)
from tools.evidence.release_canonical import canonical_json_bytes

from tests.release_receipt_chain_test_support import (
    _index,
    _prior_consumption,
    _rebuilt,
    _rechain,
    verify_chain,
)


class ReleaseReceiptChainIntegrityTests(unittest.TestCase):
    def test_complete_stream_reaches_terminal_at_internal_closed(self) -> None:
        receipts = successful_chain()
        state = verify_chain(receipts, require_terminal=True)
        self.assertEqual(state.phase, "TERMINAL")
        self.assertEqual(state.pypi_verified_count, 8)
        self.assertEqual(len(state.draft_assets), 17)
        self.assertIsNone(state.lease_id)

    def test_release_authority_candidate_and_attempt_ids_are_rederived(self) -> None:
        receipts = successful_chain()
        governance_a = next(
            index
            for index, receipt in enumerate(receipts)
            if receipt["payload"].get("label") == "A"
        )
        candidate = _index(receipts, "CANDIDATE_HANDOFF")

        changed = copy.deepcopy(receipts[: governance_a + 1])
        alias = base.digest("release identity alias")
        for envelope in changed:
            envelope["stream"]["release_identity_id"] = alias
            if envelope["scope"]["kind"] == "release":
                envelope["scope"]["release_identity_id"] = alias
        with self.assertRaisesRegex(
            contract.ReceiptValidationError, "canonical release identity"
        ):
            verify_chain(_rechain(changed))

        changed = copy.deepcopy(receipts[: candidate + 1])
        authority_alias = base.digest("release authority alias")
        job_producer = next(
            envelope["producer"]
            for envelope in changed
            if envelope["producer"]["kind"] == "github_actions_job"
        )
        for envelope in changed:
            envelope["stream"]["release_authority_id"] = authority_alias
            envelope["attempt"]["attempt_id"] = release_identity.attempt_id(
                release_authority_id=authority_alias,
                controller_workflow_id=job_producer["workflow_id"],
                controller_run_id=job_producer["run_id"],
                controller_run_attempt=job_producer["run_attempt"],
            )
        with self.assertRaisesRegex(
            contract.ReceiptValidationError, "canonical release authority"
        ):
            verify_chain(_rechain(changed))

        changed = copy.deepcopy(receipts[: candidate + 1])
        changed[candidate]["payload"]["candidate_inventory_sha256"] = base.digest(
            "candidate inventory alias"
        )
        with self.assertRaisesRegex(
            contract.ReceiptValidationError, "canonical candidate"
        ):
            verify_chain(_rechain(changed))

        changed = copy.deepcopy(receipts[:1])
        changed[0]["attempt"]["attempt_id"] = base.digest("attempt alias")
        with self.assertRaisesRegex(
            contract.ReceiptValidationError, "canonical controller attempt"
        ):
            verify_chain(_rechain(changed))

    def test_internal_closed_binds_the_full_verified_envelope_chain(self) -> None:
        receipts = successful_chain()
        closed_index = _index(receipts, "CLOSED")
        closed_stream = receipts[: closed_index + 1]
        document = receipt_chain_document(closed_stream)
        encoded = canonical_json_bytes(document)
        self.assertGreater(len(encoded), 1_000)
        self.assertEqual(document["receipts"], closed_stream)
        self.assertEqual(
            verify_chain(receipts).closed_binding["receipt_chain_sha256"],
            receipt_chain_sha256(closed_stream),
        )

    def test_sequence_previous_and_fence_are_stateful_not_caller_claims(self) -> None:
        receipts = successful_chain()
        changed = copy.deepcopy(receipts)
        changed[8] = _rebuilt(changed[8], stream_sequence=99)
        with self.assertRaisesRegex(contract.ReceiptValidationError, "sequence"):
            verify_chain(changed)

        changed = copy.deepcopy(receipts)
        changed[4] = _rebuilt(changed[4], fencing_token=4)
        changed = _rechain(changed)
        with self.assertRaisesRegex(contract.ReceiptValidationError, "lease/fence"):
            verify_chain(changed)

    def test_lease_expiry_and_renewal_cadence_are_stateful(self) -> None:
        receipts = successful_chain()
        renewed = _index(receipts, "LEASE_RENEWED")
        changed = copy.deepcopy(receipts)
        changed[renewed]["payload"]["previous_expires_at"] = "2026-08-15T00:04:59Z"
        with self.assertRaisesRegex(contract.ReceiptValidationError, "previous expiry"):
            verify_chain(_rechain(changed))

        changed = copy.deepcopy(receipts)
        changed[renewed]["payload"].update(
            renewed_at="2026-08-15T00:01:01Z",
            expires_at="2026-08-15T00:06:01Z",
        )
        changed[renewed]["timestamps"] = {
            "observed_at": "2026-08-15T00:01:01Z",
            "committed_at": "2026-08-15T00:01:02Z",
        }
        with self.assertRaisesRegex(contract.ReceiptValidationError, "cadence"):
            verify_chain(_rechain(changed))

        closed = _index(receipts, "CLOSED")
        changed = copy.deepcopy(receipts)
        changed[closed]["timestamps"] = {
            "observed_at": "2026-08-15T00:05:45Z",
            "committed_at": "2026-08-15T00:05:46Z",
        }
        with self.assertRaisesRegex(
            contract.ReceiptValidationError,
            "at or after lease expiry",
        ):
            verify_chain(_rechain(changed))

    def test_authorization_expires_exactly_with_active_lease(self) -> None:
        receipts = successful_chain()
        authorized = _index(receipts, "AUTHORIZED")
        for expires_at in (
            "2026-08-15T00:05:44Z",
            "2026-08-15T00:05:46Z",
            "2099-08-15T00:05:45Z",
        ):
            with self.subTest(expires_at=expires_at):
                changed = copy.deepcopy(receipts)
                changed[authorized]["payload"]["expires_at"] = expires_at
                with self.assertRaisesRegex(
                    contract.ReceiptValidationError, "authorization expiry"
                ):
                    verify_chain(_rechain(changed))

    def test_public_closure_receipts_are_outside_the_active_payload_union(self) -> None:
        forbidden = {"CLOSURE_ARTIFACT_VERIFIED", "CLOSED_CHECK_TRANSITION"}
        self.assertTrue(forbidden.isdisjoint(contract.PAYLOAD_KINDS))
        for payload in (
            publish.closure_artifact(),
            publish.closed_check("PROJECTED"),
            publish.closed_check("VERIFIED"),
        ):
            with (
                self.subTest(kind=payload["kind"]),
                self.assertRaisesRegex(
                    contract.ReceiptValidationError, "outside the closed enum"
                ),
            ):
                envelope_for(payload)

    def test_public_closure_intents_are_outside_the_active_operation_union(
        self,
    ) -> None:
        forbidden = {
            "GITHUB_CLOSURE_ARTIFACT_UPLOAD",
            "GITHUB_CLOSED_CHECK_PROJECT",
        }
        self.assertTrue(forbidden.isdisjoint(intents.OPERATIONS))
        for operation in forbidden:
            payload = intent_fixture.intent("GITHUB_RELEASE_PUBLISH")
            payload["operation"] = operation
            with (
                self.subTest(operation=operation),
                self.assertRaisesRegex(
                    contract.ReceiptValidationError, "outside the closed enum"
                ),
            ):
                envelope_for(payload)

    def test_every_mutation_outcome_consumes_the_exact_intent_once(self) -> None:
        receipts = successful_chain()
        accepted = _index(receipts, "GITHUB_RELEASE_TRANSITION", "PUBLISH_ACCEPTED")
        changed = copy.deepcopy(receipts)
        changed[accepted]["payload"]["intent_receipt_id"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(contract.ReceiptValidationError, "intent receipt"):
            verify_chain(_rechain(changed))

        asset = _index(receipts, "DRAFT_TRANSITION", "ASSET_UPLOADED")
        changed = copy.deepcopy(receipts)
        changed[asset]["payload"]["asset"]["sha256"] = "sha256:" + "e" * 64
        with self.assertRaisesRegex(contract.ReceiptValidationError, "intent subject"):
            verify_chain(_rechain(changed))

        attestation = _index(receipts, "ATTESTATION_VERIFIED")
        changed = copy.deepcopy(receipts)
        changed[accepted]["payload"]["intent_consumption_receipt_sha256"] = changed[
            attestation
        ]["payload"]["intent_consumption_receipt_sha256"]
        with self.assertRaisesRegex(contract.ReceiptValidationError, "intent receipt"):
            verify_chain(_rechain(changed))

    def test_consumption_is_durable_temporal_and_phase_bound(self) -> None:
        receipts = successful_chain()
        accepted = _index(receipts, "GITHUB_RELEASE_TRANSITION", "PUBLISH_ACCEPTED")
        consumed = _prior_consumption(receipts, accepted)

        changed = copy.deepcopy(receipts)
        del changed[consumed]
        with self.assertRaisesRegex(
            contract.ReceiptValidationError, "consumed mutation intent"
        ):
            verify_chain(_rechain(changed))

        changed = copy.deepcopy(receipts)
        changed[consumed]["payload"]["consumer_identity_sha256"] = "sha256:" + "a" * 64
        with self.assertRaisesRegex(
            contract.ReceiptValidationError, "consumption mismatch"
        ):
            verify_chain(_rechain(changed))

        changed = copy.deepcopy(receipts)
        changed[consumed]["payload"]["consumed_at"] = "2026-08-14T23:59:59Z"
        with self.assertRaisesRegex(
            contract.ReceiptValidationError, "timestamp outside"
        ):
            verify_chain(_rechain(changed))

        attestation_consumed = _index(receipts, "MUTATION_INTENT_CONSUMED")
        prefix = copy.deepcopy(receipts[:6])
        prefix.append(copy.deepcopy(receipts[attestation_consumed]))
        with self.assertRaisesRegex(contract.ReceiptValidationError, "phase mismatch"):
            verify_chain(_rechain(prefix))

    def test_gate_decision_consumes_one_exact_intent_and_retry_uses_a_new_one(
        self,
    ) -> None:
        self.assertEqual(
            verify_chain(gate_decision_chain("APPROVE")).phase, "PYPI_READY"
        )
        self.assertEqual(
            verify_chain(gate_decision_chain("REJECT")).phase,
            "RECOVERY_REQUIRED",
        )
        self.assertEqual(
            verify_chain(
                gate_decision_chain(
                    "APPROVE", ambiguous=True, resolution="APPROVED_CONFIRMED"
                )
            ).phase,
            "PYPI_READY",
        )
        self.assertEqual(
            verify_chain(
                gate_decision_chain(
                    "REJECT", ambiguous=True, resolution="REJECTED_CONFIRMED"
                )
            ).phase,
            "RECOVERY_REQUIRED",
        )
        retry = gate_retry_chain("APPROVE")
        self.assertEqual(verify_chain(retry).phase, "PYPI_GATE_DECISION_INTENT")

        changed = copy.deepcopy(retry)
        old_intent = next(
            receipt
            for receipt in changed
            if receipt["payload"].get("operation") == "PYPI_DEPLOYMENT_APPROVE"
            and receipt["payload"]["kind"] == "MUTATION_INTENT"
        )
        changed[-1]["payload"]["intent_id"] = old_intent["payload"]["intent_id"]
        with self.assertRaisesRegex(contract.ReceiptValidationError, "duplicate"):
            verify_chain(_rechain(changed))
