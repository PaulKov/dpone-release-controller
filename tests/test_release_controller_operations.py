"""Commit-A operation order and closed action codec tests."""

from __future__ import annotations

import copy
from dataclasses import replace
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.evidence import release_controller_operations as operations
from tools.evidence.release_controller_operation_contract import (
    LEDGER_TX,
    LOCAL_VERIFY,
    READ,
)
from tools.evidence.release_controller_operation_vectors import encoded
from tools.evidence.release_controller_operation_vectors import happy_path
from tools.evidence import release_controller_routes
from tools.evidence import release_controller_operation_static as static_operations
from tools.evidence.release_controller_service_roles import role_for_selector
from tests.release_receipt_chain_fixtures import successful_chain

FIXTURE = Path("tests/fixtures/release-controller-operation-profile-v2.json")


class ReleaseControllerOperationTests(unittest.TestCase):
    def test_operation_source_modules_stay_bounded(self) -> None:
        modules = sorted(
            Path("tools/evidence").glob("release_controller_operation*.py")
        )
        self.assertGreaterEqual(len(modules), 10)
        for module in modules:
            with self.subTest(module=module.name):
                self.assertLessEqual(
                    len(module.read_text(encoding="utf-8").splitlines()),
                    400,
                    f"split {module.name} before adding more authority",
                )

    def test_all_release_evidence_modules_stay_bounded(self) -> None:
        modules = sorted(Path("tools/evidence").glob("release_*.py"))
        self.assertGreaterEqual(len(modules), 100)
        for module in modules:
            source = module.read_text(encoding="utf-8")
            lines = source.splitlines()
            nonblank = sum(bool(line.strip()) for line in lines)
            with self.subTest(module=module.name, metric="lines"):
                self.assertLessEqual(len(lines), 400)
            with self.subTest(module=module.name, metric="nonblank"):
                self.assertLessEqual(nonblank, 350)

    def test_exact_107_receipt_path_ends_at_internal_closed(self) -> None:
        expected = happy_path()
        complete_chain = successful_chain()
        closed_index = next(
            index
            for index, envelope in enumerate(complete_chain)
            if envelope["payload"]["kind"] == "CLOSED"
        )
        observed = [
            (
                release_controller_routes.selector_for(envelope["payload"]),
                envelope["payload"]["state"],
            )
            for envelope in complete_chain[: closed_index + 1]
        ]
        self.assertEqual(len(expected), 107)
        self.assertEqual(
            [(row["selector"], row["state"]) for row in expected],
            observed,
        )
        draft_assets = [
            row
            for row in expected
            if row["selector"] == "DRAFT_TRANSITION:ASSET_UPLOADED"
        ]
        self.assertEqual(len(draft_assets), 17)
        self.assertEqual(len({row["subject_selector"] for row in draft_assets}), 17)
        pypi_integrity = [
            row
            for row in expected
            if row["selector"] == "PYPI_FILE_TRANSITION:INTEGRITY_VERIFIED"
        ]
        self.assertEqual(len(pypi_integrity), 8)
        self.assertEqual(pypi_integrity[-1]["state"], "PYPI_VERIFIED")

    def test_candidate_sequence_and_action_codec_are_exact(self) -> None:
        self.assertEqual(FIXTURE.read_bytes(), encoded())
        profile = operations.CANDIDATE_IMPORT
        self.assertEqual(
            tuple(call.phase for call in profile.ordered_calls),
            (
                "CANDIDATE_SOURCE_STREAM",
                "CANDIDATE_DEEP_VERIFY",
                "CANDIDATE_ADMIT",
            ),
        )
        self.assertEqual(
            tuple(call.effect for call in profile.ordered_calls),
            (READ, LOCAL_VERIFY, LEDGER_TX),
        )
        self.assertEqual(
            profile.ordered_calls[-1].receipt_kinds,
            ("CANDIDATE_HANDOFF",),
        )
        (codec,) = operations.ACTION_CODECS_BY_OPERATION[profile.operation_id]
        self.assertEqual(codec.output_names, ())
        self.assertEqual(codec.output_authority, "NONE")
        names = tuple(value.name for value in codec.inputs)
        self.assertNotIn("broker_url", names)
        self.assertNotIn("body", names)
        self.assertEqual(
            profile.ordered_calls[-1].path,
            "/v1/releases/candidate/admit",
        )
        self.assertTrue(
            all(call.path != "/v1/receipts/append" for call in profile.ordered_calls)
        )

    def test_rematerialization_and_sentinel_are_explicit_while_closure_is_held(
        self,
    ) -> None:
        draft = operations.DRAFT_STAGE.ordered_calls
        pypi = operations.PYPI_PUBLISH.ordered_calls
        sentinel = operations.LEASE_SENTINEL.ordered_calls
        self.assertEqual(tuple(call.phase for call in draft), ("DRAFT_ADVANCE",))
        self.assertEqual(pypi[0].phase, "CANDIDATE_REMATERIALIZE_STREAM")
        self.assertEqual(pypi[1].phase, "PYPI_EXACT_UPLOAD_SET_VERIFY")
        machine = operations.DRAFT_STAGE.durable_state_machine
        assert machine is not None
        self.assertEqual(len(machine.cycles), 19)
        self.assertEqual(machine.max_provider_mutations_per_advance, 1)
        self.assertTrue(machine.no_transaction_across_network)
        self.assertTrue(machine.durable_checkpoint_after_each_substep)
        self.assertEqual(machine.terminal_verification.state, "DRAFT_VERIFIED")
        self.assertEqual(draft[-1].cardinality, "UNTIL_TERMINAL")
        self.assertEqual(operations.PYPI_OBSERVE.environment, "release-attest")
        self.assertNotIn("DRAFT_OUTCOME_ADMIT", tuple(call.phase for call in draft))
        self.assertNotIn("PYPI_OUTCOME_ADMIT", tuple(call.phase for call in pypi))
        self.assertTrue(
            {
                "closure-artifact-upload",
                "closure-artifact-verify",
                "runtime-closure",
            }.isdisjoint(operations.OPERATION_BY_ID)
        )
        self.assertEqual(sentinel[0].cardinality, "WHILE_LEASE_ACTIVE")
        self.assertEqual(sentinel[0].interval_seconds, 45)
        self.assertEqual(operations.LEASE_SENTINEL.absolute_timeout_seconds, 21_600)

    def test_draft_cycles_bind_transport_reconcile_and_terminal_verification(
        self,
    ) -> None:
        machine = operations.DRAFT_STAGE.durable_state_machine
        assert machine is not None
        self.assertEqual(
            tuple(cycle.cycle_id for cycle in machine.cycles),
            (
                "draft-create",
                *(f"draft-asset-{index:02d}" for index in range(17)),
                "draft-update",
            ),
        )
        for cycle in machine.cycles:
            with self.subTest(cycle=cycle.cycle_id):
                self.assertEqual(
                    cycle.next_cycle_gate, "PRIOR_OUTCOME_DURABLY_COMMITTED"
                )
                self.assertIn("PROVIDER_RESULT_CLASSIFY", cycle.ordered_substeps)
                self.assertEqual(
                    cycle.byte_source_authority,
                    "BROKER_RESOLVED_ADMITTED_CANDIDATE_BYTES",
                )
                self.assertIn(
                    "INTERNAL_PINNED_CANDIDATE_SOURCE_STREAM",
                    cycle.ordered_substeps,
                )
                self.assertIn("SAFE_EXACT_MEMBER_EXTRACTION", cycle.ordered_substeps)
        self.assertEqual(
            machine.candidate_source.private_rpc,
            "candidate-reader:read-admitted-candidate-v1",
        )
        self.assertNotIn(
            "cycle_transport_sha256",
            tuple(
                value.name
                for codec in operations.ACTION_CODECS_BY_OPERATION["draft-stage"]
                for value in codec.inputs
            ),
        )
        self.assertEqual(
            machine.terminal_verification.ordered_substeps,
            (
                "READ_ONLY_RELEASE_REQUERY",
                "READ_ONLY_EXACT_17_ASSET_REQUERY",
                "TAG_BODY_DRAFT_TRUE_INVENTORY_CROSS_BIND",
                "VERIFIED_OUTCOME_DURABLE_COMMIT",
            ),
        )
        branches = {
            branch.classification: branch for branch in machine.recovery_branches
        }
        self.assertFalse(
            branches["TIMEOUT_OR_UNKNOWN_AFTER_EFFECT"].provider_mutation_allowed
        )
        self.assertEqual(
            branches["TIMEOUT_OR_UNKNOWN_AFTER_EFFECT"].next_action,
            "READ_ONLY_PROVIDER_REQUERY",
        )
        self.assertEqual(branches["PROVIDER_CONFLICT"].terminal_status, "HOLD")
        self.assertTrue(
            branches["PROVIDER_CONCLUSIVELY_ABSENT"].requires_new_linked_intent
        )
        self.assertEqual(
            branches["PROVIDER_CONCLUSIVELY_ABSENT"].max_retry_intents_per_subject,
            1,
        )
        self.assertIn(
            "absence_observation_sha256",
            branches["PROVIDER_CONCLUSIVELY_ABSENT"].retry_authority_link_fields,
        )
        self.assertEqual(
            machine.replay_policy,
            "DUPLICATE_JTI_OR_REQUEST_CANNOT_ADVANCE_STATE",
        )

    def test_external_action_pins_are_closed_and_public_closure_is_absent(self) -> None:
        publish = operations.PYPI_PUBLISH.ordered_calls
        pypa = next(call for call in publish if call.method == "ACTION")
        self.assertEqual(pypa.path, operations.PYPI_ACTION)
        held = {
            "closed-check-intent",
            "closed-check-project",
            "closed-check-verify",
            "closure-artifact-upload",
            "closure-artifact-verify",
            "runtime-closure",
        }
        self.assertTrue(held.isdisjoint(operations.ACTION_CODECS_BY_OPERATION))

    def test_server_requeries_commit_one_atomic_fenced_batch_after_provider_io(
        self,
    ) -> None:
        for profile in operations.OPERATIONS:
            calls = tuple(
                call
                for call in profile.ordered_calls
                if call.effect == "SERVER_REQUERY_LEDGER_TX"
            )
            self.assertEqual(
                tuple(plan.phase for plan in profile.server_transactions),
                tuple(call.phase for call in calls),
            )
            for call, plan in zip(calls, profile.server_transactions, strict=True):
                with self.subTest(operation=profile.operation_id, phase=call.phase):
                    self.assertFalse(plan.provider_io_inside_transaction)
                    self.assertEqual(plan.durable_commit_count, 1)
                    self.assertEqual(
                        plan.atomic_receipt_selectors, call.receipt_selectors
                    )
                    self.assertEqual(
                        tuple(
                            selector for selector, _role in plan.receipt_producer_roles
                        ),
                        call.receipt_selectors,
                    )
                    self.assertTrue(plan.pre_transaction_reads)
        self.assertTrue(
            release_controller_routes.HELD_PUBLIC_CLOSURE_SELECTORS.isdisjoint(
                {
                    selector
                    for profile in operations.OPERATIONS
                    for plan in profile.server_transactions
                    for selector in plan.atomic_receipt_selectors
                }
            )
        )

    def test_server_transaction_roles_equal_real_receipt_producer_roles(self) -> None:
        expected_by_selector = {
            selector: role
            for profile in operations.OPERATIONS
            for plan in profile.server_transactions
            for selector, role in plan.receipt_producer_roles
        }
        self.assertTrue(expected_by_selector)
        for selector, role in expected_by_selector.items():
            with self.subTest(selector=selector):
                self.assertEqual(role, role_for_selector(selector))

        observed = 0
        for envelope in successful_chain():
            selector = release_controller_routes.selector_for(envelope["payload"])
            if selector not in expected_by_selector:
                continue
            observed += 1
            with self.subTest(
                selector=selector, sequence=envelope["stream"]["sequence"]
            ):
                self.assertEqual(
                    envelope["producer"]["kind"], "trusted_controller_service"
                )
                self.assertEqual(
                    envelope["producer"]["service_role"],
                    expected_by_selector[selector],
                )
        self.assertGreater(observed, 0)

    def test_order_path_audience_effect_and_codec_drift_fail_closed(self) -> None:
        base = operations.CANDIDATE_IMPORT
        cases = {
            "reordered": tuple(reversed(base.ordered_calls)),
            "local-network": (
                base.ordered_calls[0],
                copy.copy(base.ordered_calls[1]),
                base.ordered_calls[2],
            ),
        }
        local = cases["local-network"][1]
        object.__setattr__(local, "audience", "forged-audience")
        for name, calls in cases.items():
            profile = copy.copy(base)
            object.__setattr__(profile, "ordered_calls", calls)
            with (
                self.subTest(name=name),
                patch.object(operations, "CANDIDATE_IMPORT", profile),
                patch.object(operations, "OPERATIONS", (profile,)),
                self.assertRaises(operations.OperationProfileError),
            ):
                operations.validate()

    def test_new_route_cannot_be_silently_blessed_by_generation(self) -> None:
        forged = replace(
            release_controller_routes.ROUTES[0],
            selector="FORGED_NEW_AUTHORITY",
            job_name="forged-job",
        )
        with (
            patch.object(
                release_controller_routes,
                "ROUTES",
                (*release_controller_routes.ROUTES, forged),
            ),
            self.assertRaisesRegex(RuntimeError, "explicit operation table/route"),
        ):
            static_operations._profiles()


if __name__ == "__main__":
    unittest.main()
