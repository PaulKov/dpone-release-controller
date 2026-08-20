"""Adversarial service-authority, WORM-head, and effect-guard tests."""

from __future__ import annotations

import copy
import re
import unittest
from datetime import datetime, timedelta, timezone

from tests import release_receipt_chain_fixtures as chain_fixture
from tests import release_receipt_fixtures as receipt_fixture
from tests import release_receipt_intent_fixtures as intent_fixture
from tests import release_service_authority_fixtures as authority_fixture
from tools.evidence import release_authority_guard as authority_guard
from tools.evidence import release_controller_service_activation as activation
from tools.evidence import release_controller_service_inventory as inventory
from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_outcome_bindings as outcome_bindings
from tools.evidence import release_receipt_payloads
from tools.evidence.release_receipt_chain import verify_chain
from tools.evidence.release_receipt_envelope_v2 import build

_CLOUDFLARE_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)


class ServiceAuthorityTests(unittest.TestCase):
    """Prove exact activated-service and fresh-effect authority boundaries."""

    def test_inventory_has_exact_provider_shaped_rows_and_unique_worm_anchors(
        self,
    ) -> None:
        document = authority_fixture.authority_inventory()
        indexed = inventory.validate(document)

        self.assertEqual(set(indexed), set(inventory.AUTHORITY_BINDINGS))
        self.assertEqual(len(indexed), 14)
        self.assertEqual(
            len({row["deployment_observation_record_id"] for row in indexed.values()}),
            14,
        )
        self.assertEqual(
            len(
                {
                    row["deployment_observation_record_sha256"]
                    for row in indexed.values()
                }
            ),
            14,
        )
        for row in indexed.values():
            self.assertRegex(row["worker_version_id"], _CLOUDFLARE_UUID)
            self.assertRegex(row["deployment_id"], _CLOUDFLARE_UUID)

    def test_inventory_rejects_missing_duplicate_and_unmirrored_authority(self) -> None:
        document = authority_fixture.authority_inventory()
        cases = []

        missing = copy.deepcopy(document)
        missing["authorities"].pop()
        cases.append(missing)

        duplicate = copy.deepcopy(document)
        duplicate["authorities"][1]["deployment_observation_record_id"] = duplicate[
            "authorities"
        ][0]["deployment_observation_record_id"]
        cases.append(duplicate)

        malformed = copy.deepcopy(document)
        malformed["authorities"][0]["deployment_observation_record_sha256"] = (
            "not-worm-anchored"
        )
        cases.append(malformed)

        for changed in cases:
            with self.subTest(case=len(changed["authorities"])):
                with self.assertRaises(inventory.ServiceInventoryError):
                    inventory.validate(changed)

    def test_a0_observation_must_precede_promotion(self) -> None:
        record = authority_fixture.service_activation_record()
        record["expected_service_authorities"]["provider_observation"][
            "observed_at"
        ] = "2026-08-15T00:01:00Z"
        record["expected_service_authorities_sha256"] = activation.expected_digest(
            record["expected_service_authorities"]
        )
        with self.assertRaisesRegex(activation.ServiceActivationError, "chronology"):
            activation.validate_activation(record)

    def test_head_v1_rejects_rotation_and_seq0_before_head(self) -> None:
        record = authority_fixture.service_activation_record()
        head = authority_fixture.authority_head()

        changed = copy.deepcopy(head)
        changed["generation"] = 2
        with self.assertRaisesRegex(activation.ServiceActivationError, "generation"):
            activation.validate_authority_head(changed, record)

        payload = receipt_fixture._request()
        original = receipt_fixture.envelope_for(payload)
        early = build(
            stream=original["stream"],
            scope=original["scope"],
            attempt=original["attempt"],
            producer=original["producer"],
            committer=original["committer"],
            timestamps={
                "observed_at": "2026-08-14T23:59:10Z",
                "committed_at": "2026-08-14T23:59:11Z",
            },
            payload=payload,
        )
        with self.assertRaisesRegex(
            contract.ReceiptValidationError, "precedes activated-authority head"
        ):
            verify_chain([early])

    def test_every_mutation_operation_requires_a_closed_guard(self) -> None:
        self.assertEqual(
            authority_guard.GUARDED_OPERATIONS, intent_fixture.intents.OPERATIONS
        )
        for operation in sorted(intent_fixture.intents.OPERATIONS):
            payload = intent_fixture.consumed(operation)
            release_receipt_payloads.validate(payload)
            changed = copy.deepcopy(payload)
            changed.pop("authority_guard")
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(
                    contract.ReceiptValidationError, "keys mismatch"
                ):
                    release_receipt_payloads.validate(changed)

    def test_guard_rejects_stale_observation_wrong_head_and_consumer(self) -> None:
        service_payload = intent_fixture.consumed("GITHUB_RELEASE_PUBLISH")
        guard = copy.deepcopy(service_payload["authority_guard"])
        guard["observed_at"] = "2026-08-14T00:00:00Z"
        with self.assertRaisesRegex(authority_guard.AuthorityGuardError, "time window"):
            authority_guard.validate(guard)

        receipts = chain_fixture.successful_chain()
        consumption = next(
            envelope
            for envelope in receipts
            if envelope["payload"]["kind"] == "MUTATION_INTENT_CONSUMED"
            and envelope["payload"]["operation"] == "GITHUB_RELEASE_PUBLISH"
        )
        changed_guard = copy.deepcopy(consumption["payload"]["authority_guard"])
        changed_guard["activated_authority_head_record_id"] = receipt_fixture.digest(
            "another authority head"
        )
        with self.assertRaisesRegex(
            inventory.ServiceInventoryError, "activated-service"
        ):
            inventory.bind_authority_guard(
                changed_guard,
                inventory.compile_inventory(authority_fixture.authority_inventory()),
                head_record_id=authority_fixture.authority_head_record_id(),
                head_record_sha256=authority_fixture.authority_head_sha256(),
            )

        gha_payload = intent_fixture.consumed("PYPI_FILE_UPLOAD_SET")
        gha_guard = copy.deepcopy(gha_payload["authority_guard"])
        gha_guard["github_consumer"]["run_id"] += 1
        with self.assertRaisesRegex(authority_guard.AuthorityGuardError, "binding"):
            authority_guard.bind_to_consumption(
                gha_guard, gha_payload, receipt_fixture._producer(gha_payload)
            )

    def test_effect_dispatch_and_private_outcome_freshness_matrix(self) -> None:
        receipts = chain_fixture.successful_chain()
        for operation in (
            "ATTESTATION_CREATE",
            "GITHUB_DRAFT_ASSET_UPLOAD",
            "PYPI_FILE_UPLOAD_SET",
        ):
            index = next(
                i
                for i, envelope in enumerate(receipts)
                if envelope["payload"]["kind"] == "MUTATION_INTENT_CONSUMED"
                and envelope["payload"]["operation"] == operation
            )
            prefix = copy.deepcopy(receipts[: index + 1])
            expiry = _parse(prefix[-1]["payload"]["authority_guard_expires_at"])
            prefix[-1] = _with_timestamps(prefix[-1], expiry + timedelta(seconds=1))
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(
                    contract.ReceiptValidationError, "expired before consumption"
                ):
                    verify_chain(prefix)

        for operation in (
            "ATTESTATION_CREATE",
            "GITHUB_DRAFT_ASSET_UPLOAD",
        ):
            outcome_index = _outcome_index(receipts, operation)
            prefix = copy.deepcopy(receipts[: outcome_index + 1])
            expiry = _parse(prefix[-1]["payload"]["authority_guard_expires_at"])
            prefix[-1] = _with_timestamps(prefix[-1], expiry + timedelta(seconds=1))
            with (
                self.subTest(outcome_operation=operation),
                self.assertRaisesRegex(
                    contract.ReceiptValidationError,
                    "outside the consumed authority guard",
                ),
            ):
                verify_chain(prefix)

    def test_github_action_outcome_may_finish_late_only_on_same_fence(self) -> None:
        receipts = chain_fixture.successful_chain()
        for operation in authority_guard.GITHUB_ACTION_OPERATIONS:
            outcome_index = _outcome_index(receipts, operation)
            prefix = copy.deepcopy(receipts[: outcome_index + 1])
            expiry = _parse(prefix[-1]["payload"]["authority_guard_expires_at"])
            # The consumed receipt is the durable one-shot dispatch reservation.
            # Provider requery may finish later, but only under the same active
            # attempt, lease, and fence; it never grants a second dispatch.
            prefix[-1] = _with_timestamps(prefix[-1], expiry + timedelta(seconds=30))
            state = verify_chain(prefix)
            self.assertFalse(state.intent_ledger.has_ambiguous_consumption())

            wrong_fence = copy.deepcopy(prefix)
            wrong_fence[-1] = _with_fence(
                wrong_fence[-1], wrong_fence[-1]["lease"]["fencing_token"] + 1
            )
            with (
                self.subTest(operation=operation),
                self.assertRaisesRegex(
                    contract.ReceiptValidationError, "active lease/fence mismatch"
                ),
            ):
                verify_chain(wrong_fence)


def _parse(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _format(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _with_timestamps(envelope: dict, observed: datetime) -> dict:
    return build(
        stream=envelope["stream"],
        scope=envelope["scope"],
        attempt=envelope["attempt"],
        lease=envelope.get("lease"),
        producer=envelope["producer"],
        committer=envelope["committer"],
        timestamps={
            "observed_at": _format(observed),
            "committed_at": _format(observed + timedelta(seconds=1)),
        },
        payload=envelope["payload"],
    )


def _with_fence(envelope: dict, fencing_token: int) -> dict:
    lease = {**envelope["lease"], "fencing_token": fencing_token}
    return build(
        stream=envelope["stream"],
        scope=envelope["scope"],
        attempt=envelope["attempt"],
        lease=lease,
        producer=envelope["producer"],
        committer=envelope["committer"],
        timestamps=envelope["timestamps"],
        payload=envelope["payload"],
    )


def _outcome_index(receipts: list[dict], operation: str) -> int:
    return next(
        index
        for index, envelope in enumerate(receipts)
        if outcome_bindings.operation(envelope["payload"]) == operation
    )


if __name__ == "__main__":
    unittest.main()
