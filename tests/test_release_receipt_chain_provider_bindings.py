"""Stateful and adversarial tests for the receipt-v2 release stream."""

from __future__ import annotations

import copy
import unittest
from typing import Any

from tests import release_receipt_fixtures as base
from tests import release_receipt_publish_fixtures as publish
from tests.release_receipt_chain_fixtures import (
    gate_decision_chain,
    successful_chain,
)
from tests.release_receipt_fixtures import envelope_for
from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_intents as intents
from tools.evidence import release_receipt_inventory as inventory
from tools.evidence.release_receipt_envelope_v2 import verify

from tests.release_receipt_chain_test_support import (
    _index,
    _prior_consumption,
    _rebuilt,
    _rechain,
    verify_chain,
)


class ReleaseReceiptChainProviderBindingTests(unittest.TestCase):
    def test_gate_request_decision_and_intent_share_one_exact_binding(self) -> None:
        receipts = gate_decision_chain("APPROVE")
        approved = _index(receipts, "PYPI_GATE_APPROVED")
        replacements: dict[str, Any] = {
            "candidate_id": base.digest("different candidate"),
            "gate_request_id": base.digest("different gate request"),
            "lease_id": base.digest("different lease"),
            "fencing_token": 4,
            "tag": "v0.74.1",
            "ref": "refs/tags/v0.74.1",
            "deployment_id": 18_000_002,
            "environment_name": "pypi-other",
            "environment_id": 18_405_660_891,
            "protection_rule_id": 7_000_000_002,
            "gate_app_id": 9_000_002,
            "gate_installation_id": 10_000_002,
            "app_slug": "dpone-release-controller-pypi-gate-other",
            "controller_repository_id": 1_305_993_854,
            "controller_workflow_id": 316_322_128,
            "controller_workflow_sha": "d" * 40,
            "controller_run_id": 123_456_790,
            "controller_run_attempt": 3,
            "expected_file_count": 7,
            "expected_file_inventory_sha256": base.digest("different files"),
            "gate_request_provider_observation_sha256": base.digest(
                "different request observation"
            ),
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(receipts)
                changed[approved]["payload"][field] = replacement
                with self.assertRaises(contract.ReceiptValidationError):
                    verify_chain(_rechain(changed))

        intent_index = next(
            index
            for index, receipt in enumerate(receipts)
            if receipt["payload"].get("operation") == "PYPI_DEPLOYMENT_APPROVE"
            and receipt["payload"]["kind"] == "MUTATION_INTENT"
        )
        changed = copy.deepcopy(receipts)
        subject = changed[intent_index]["payload"]["subject"]
        subject["controller_workflow_sha"] = "d" * 40
        changed[intent_index]["payload"]["subject_identity_sha256"] = (
            intents.subject_identity_sha256("PYPI_DEPLOYMENT_APPROVE", subject)
        )
        with self.assertRaisesRegex(
            contract.ReceiptValidationError, "gate decision intent subject"
        ):
            verify_chain(_rechain(changed))

    def test_every_github_job_is_pinned_to_workflow_and_run_per_attempt(self) -> None:
        receipts = successful_chain()
        job_index = next(
            index
            for index, envelope in enumerate(receipts)
            if envelope["producer"]["kind"] == "github_actions_job"
            and "lease" in envelope
        )
        changed = copy.deepcopy(receipts)
        changed[job_index]["producer"]["workflow_sha"] = "d" * 40
        with self.assertRaisesRegex(
            contract.ReceiptValidationError, "workflow authority"
        ):
            verify_chain(_rechain(changed))

        changed = copy.deepcopy(receipts)
        changed[job_index]["producer"]["run_id"] += 1
        with self.assertRaisesRegex(
            contract.ReceiptValidationError,
            "canonical controller attempt|run/attempt",
        ):
            verify_chain(_rechain(changed))

    def test_candidate_inventories_drive_pypi_draft_and_immutable_release(self) -> None:
        receipts = successful_chain()
        pending = _index(receipts, "PYPI_FILE_TRANSITION", "PENDING_UPLOAD")
        changed = copy.deepcopy(receipts)
        changed[pending]["payload"]["size_bytes"] += 1
        with self.assertRaisesRegex(contract.ReceiptValidationError, "PyPI size"):
            verify_chain(_rechain(changed))

        immutable = _index(receipts, "GITHUB_RELEASE_TRANSITION", "IMMUTABLE_VERIFIED")
        changed = copy.deepcopy(receipts)
        changed[immutable]["payload"]["assets_sha256"] = "sha256:" + "d" * 64
        with self.assertRaisesRegex(
            contract.ReceiptValidationError, "GitHub asset inventory"
        ):
            verify_chain(_rechain(changed))

    def test_governance_projection_cannot_drift_between_a_b_and_c(self) -> None:
        receipts = successful_chain()
        governance_b = next(
            index
            for index, receipt in enumerate(receipts)
            if receipt["payload"].get("label") == "B"
        )
        changed = copy.deepcopy(receipts)
        changed[governance_b]["payload"]["tag_ruleset_version"] += 1
        with self.assertRaisesRegex(contract.ReceiptValidationError, "governance"):
            verify_chain(_rechain(changed))

    def test_internal_closed_has_no_follow_on_public_projection_receipt(self) -> None:
        receipts = successful_chain()
        self.assertEqual(receipts[-1]["payload"]["kind"], "CLOSED")
        self.assertFalse(
            {
                "CLOSURE_ARTIFACT_VERIFIED",
                "CLOSED_CHECK_TRANSITION",
            }.intersection(envelope["payload"]["kind"] for envelope in receipts)
        )
        self.assertEqual(
            verify_chain(receipts, require_terminal=True).phase, "TERMINAL"
        )

    def test_each_pypi_file_has_a_closed_order_and_monotonic_verified_count(
        self,
    ) -> None:
        receipts = successful_chain()
        pending = _index(receipts, "PYPI_FILE_TRANSITION", "PENDING_UPLOAD")
        sealed = _index(receipts, "PYPI_FILE_TRANSITION", "SEALED_FOR_UPLOAD")
        changed = copy.deepcopy(receipts)
        changed[pending], changed[sealed] = changed[sealed], changed[pending]
        with self.assertRaisesRegex(contract.ReceiptValidationError, "per-file"):
            verify_chain(_rechain(changed))

        changed = copy.deepcopy(receipts)
        verified = _index(receipts, "PYPI_FILE_TRANSITION", "INTEGRITY_VERIFIED")
        changed[verified]["payload"]["verified_file_count"] = 2
        with self.assertRaisesRegex(contract.ReceiptValidationError, "verified count"):
            verify_chain(_rechain(changed))

    def test_pypi_upload_requires_exact_consumed_candidate_set_and_provider_time(
        self,
    ) -> None:
        receipts = successful_chain()
        observed = _index(receipts, "PYPI_UPLOAD_SET_OBSERVED")
        consumed = _prior_consumption(receipts, observed)

        changed = copy.deepcopy(receipts)
        del changed[consumed]
        with self.assertRaisesRegex(
            contract.ReceiptValidationError, "consumed mutation intent"
        ):
            verify_chain(_rechain(changed))

        changed = copy.deepcopy(receipts)
        upload_intent = next(
            envelope
            for envelope in changed
            if envelope["payload"].get("operation") == "PYPI_FILE_UPLOAD_SET"
            and envelope["payload"]["kind"] == "MUTATION_INTENT"
        )
        subject = upload_intent["payload"]["subject"]
        subject["upload_file_inventory"][0]["sha256"] = base.digest(
            "forged upload bytes"
        )
        subject["upload_file_inventory_sha256"] = inventory.inventory_sha256(
            inventory.DISTRIBUTION_SCHEMA,
            subject["upload_file_inventory"],
        )
        upload_intent["payload"]["subject_identity_sha256"] = (
            intents.subject_identity_sha256("PYPI_FILE_UPLOAD_SET", subject)
        )
        with self.assertRaisesRegex(
            contract.ReceiptValidationError, "upload candidate file"
        ):
            verify_chain(_rechain(changed))

        changed = copy.deepcopy(receipts)
        changed[observed]["payload"]["observed_at"] = "2026-08-15T00:05:59Z"
        with self.assertRaisesRegex(
            contract.ReceiptValidationError, "historical event timestamp"
        ):
            verify_chain(_rechain(changed))

        with self.assertRaisesRegex(contract.ReceiptValidationError, "transition"):
            envelope_for(publish.pypi("UPLOAD_ACCEPTED"))

    def test_job_label_and_unpinned_service_roles_are_rejected(self) -> None:
        envelope = envelope_for(publish.closed())
        envelope["producer"]["job_name"] = "lease"
        with self.assertRaisesRegex(contract.ReceiptValidationError, "job profile"):
            verify(_rebuilt(envelope))

        hygiene = next(
            receipt
            for receipt in successful_chain()
            if receipt["payload"]["kind"] == "TENANT_HYGIENE_VERIFIED"
        )
        changed = copy.deepcopy(hygiene)
        changed["producer"] = {
            "kind": "trusted_controller_service",
            "service_role": "tenant_hygiene_scanner",
            "service_authority_role": "tenant_scanner",
            "service_identity": "service:unfrozen-scanner",
            "service_version_id": "v1",
            "deployment_observation_sha256": "sha256:" + "1" * 64,
            "github_app_id": 1,
            "installation_id": 2,
            "workload_identity": "scanner",
            "request_id": "request-01HXDPONE",
            "provider_observation_sha256": "sha256:" + "2" * 64,
            "provider_api_version": "2026-03-10",
        }
        with self.assertRaisesRegex(contract.ReceiptValidationError, "service role"):
            verify(_rebuilt(changed))
