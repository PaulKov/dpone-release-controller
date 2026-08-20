"""Adversarial tests for the closed receipt-envelope v2 contract."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path


from tests import release_receipt_fixtures as base
from tests import release_receipt_intent_fixtures as intent_fixture
from tests import release_receipt_publish_fixtures as publish
from tests import release_receipt_gate_fixtures as gate
from tests.release_receipt_fixtures import (
    all_payloads,
    envelope_for,
)
from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_authority_guard as authority_guard
from tools.evidence import release_receipt_intents as intents
from tools.evidence.release_receipt_envelope_v2 import (
    decode,
    encode,
    payload_sha256,
    receipt_id,
    verify,
)

GOLDEN_PATH = Path("tests/fixtures/release-receipt-v2-golden.json")
SCHEMA_PATH = Path("docs/schemas/release/release-receipt-envelope-v2.schema.json")


class ReleaseReceiptV2PayloadTests(unittest.TestCase):
    def test_pypi_integrity_binds_repository_api_bytes_sigstore_and_rekor(self) -> None:
        envelope = envelope_for(publish.pypi("INTEGRITY_VERIFIED", verified_count=8))
        integrity = envelope["payload"]["integrity"]
        mutations = {
            "repository_identity": "https://github.com/PaulKov/dpone",
            "api_path": "/integrity/dpone/latest/file/provenance",
            "file_url": "https://example.test/dpone.whl",
            "subject_sha256": "sha256:" + "f" * 64,
            "cryptographically_verified": False,
            "verification_result": "PARSED",
            "rekor_log_index": True,
        }
        for key, value in mutations.items():
            with self.subTest(key=key):
                changed = copy.deepcopy(envelope)
                changed["payload"]["integrity"][key] = value
                _reseal(changed)
                with self.assertRaises(contract.ReceiptValidationError):
                    verify(changed)
        self.assertEqual(
            integrity["repository_identity"],
            "https://github.com/PaulKov/dpone-release-controller",
        )

    def test_pypi_receipts_enforce_file_and_aggregate_policy_limits(self) -> None:
        oversized_file = base._distributions()
        oversized_file[0]["size_bytes"] = 100_000_001
        aggregate_overflow = base._distributions()
        for record, size in zip(aggregate_overflow, [67_108_865, *([67_108_864] * 7)]):
            record["size_bytes"] = size

        for name, files in (
            ("file", oversized_file),
            ("aggregate", aggregate_overflow),
        ):
            for payload in (
                intent_fixture.intent("PYPI_FILE_UPLOAD_SET", upload_files=files),
                publish.upload_set(upload_files=files),
            ):
                with self.subTest(name=name, kind=payload["kind"]):
                    with self.assertRaisesRegex(
                        contract.ReceiptValidationError,
                        "file limit" if name == "file" else "aggregate limit",
                    ):
                        envelope_for(payload)

    def test_public_closure_payload_prototypes_are_not_active_receipts(self) -> None:
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

    def test_public_closure_mutations_have_no_intent_or_guard_authority(self) -> None:
        forbidden = {
            "GITHUB_CLOSED_CHECK_PROJECT",
            "GITHUB_CLOSURE_ARTIFACT_UPLOAD",
        }
        self.assertTrue(forbidden.isdisjoint(intents.OPERATIONS))
        self.assertTrue(forbidden.isdisjoint(authority_guard.GUARDED_OPERATIONS))

    def test_pypi_gate_consumes_one_intent_and_reconciles_ambiguity(self) -> None:
        approved = envelope_for(gate.approved())
        self.assertEqual(approved["payload"]["intent_state"], "CONSUMED")
        for owner, key, value in (
            ("payload", "intent_state", "UNCONSUMED"),
            ("producer", "service_role", "tenant_hygiene_scanner"),
            ("producer", "github_app_id", 9_000_002),
        ):
            changed = copy.deepcopy(approved)
            changed[owner][key] = value
            _reseal(changed)
            with self.assertRaises(contract.ReceiptValidationError):
                verify(changed)

    def test_job_oidc_and_committer_version_are_not_aliasable(self) -> None:
        envelope = envelope_for(publish.closed())
        for path, value in (
            (("producer", "actor_id"), True),
            (("producer", "audience"), "dpone-release-controller-pypi"),
            (("producer", "job_name"), "arbitrary"),
            (("committer", "worker_version_id"), "worker-v2"),
        ):
            with self.subTest(path=path):
                changed = copy.deepcopy(envelope)
                changed[path[0]][path[1]] = value
                _reseal(changed)
                with self.assertRaises(contract.ReceiptValidationError):
                    verify(changed)

    def test_receipt_numbers_are_ecmascript_safe_integers(self) -> None:
        envelope = envelope_for(publish.closed())
        for value in (True, 1.0, contract.MAX_SAFE_INTEGER + 1):
            with self.subTest(value=value):
                changed = copy.deepcopy(envelope)
                changed["producer"]["run_id"] = value
                with self.assertRaises(contract.ReceiptValidationError):
                    _reseal(changed)
                    verify(changed)

    def test_incident_hold_release_requires_maintainer_action(self) -> None:
        envelope = envelope_for(publish.hold_released())
        changed = copy.deepcopy(envelope)
        changed["producer"] = envelope_for(publish.hold())["producer"]
        _reseal(changed)
        with self.assertRaisesRegex(
            contract.ReceiptValidationError,
            "not produced by a workflow job|forbidden|no trusted service role",
        ):
            verify(changed)

    def test_abandoned_lease_release_requires_exact_internal_orchestrator(self) -> None:
        payload = base._lease_released_abandoned()
        envelope = envelope_for(payload)
        self.assertEqual(envelope["producer"]["service_role"], "lease_orchestrator")
        verify(envelope)

        changed = copy.deepcopy(envelope)
        changed["producer"] = envelope_for(base._lease_released())["producer"]
        _reseal(changed)
        with self.assertRaisesRegex(
            contract.ReceiptValidationError,
            "forbidden|service role|not produced by a workflow job",
        ):
            verify(changed)

    def test_every_trusted_service_role_rejects_cross_selector_relabeling(self) -> None:
        service_envelopes = {
            envelope["producer"]["service_role"]: envelope
            for payload in all_payloads()
            if (envelope := envelope_for(payload))["producer"]["kind"]
            == "trusted_controller_service"
        }
        roles = tuple(sorted(service_envelopes))
        self.assertGreaterEqual(len(roles), 10)
        for index, role in enumerate(roles):
            changed = copy.deepcopy(service_envelopes[role])
            changed["producer"]["service_role"] = roles[(index + 1) % len(roles)]
            _reseal(changed)
            with (
                self.subTest(role=role),
                self.assertRaisesRegex(
                    contract.ReceiptValidationError, "service role/payload mismatch"
                ),
            ):
                verify(changed)

    def test_digest_tampering_duplicate_keys_and_noncanonical_bytes_fail(self) -> None:
        envelope = envelope_for(publish.closed())
        changed = copy.deepcopy(envelope)
        changed["payload_sha256"] = "sha256:" + "0" * 64
        changed["receipt_id"] = receipt_id(
            {key: value for key, value in changed.items() if key != "receipt_id"}
        )
        with self.assertRaisesRegex(contract.ReceiptValidationError, "payload_sha256"):
            verify(changed)
        with self.assertRaisesRegex(contract.ReceiptValidationError, "canonical"):
            decode(encode(envelope) + b"\n")
        duplicate = b'{"schema":1,"schema":2}'
        with self.assertRaisesRegex(contract.ReceiptValidationError, "duplicate"):
            decode(duplicate)

    def test_every_historical_timestamp_precedes_the_durable_receipt(self) -> None:
        payload_timestamp_fields = {
            key for payload in all_payloads() for key in payload if key.endswith("_at")
        }
        self.assertEqual(
            payload_timestamp_fields,
            contract.HISTORICAL_EVENT_TIMESTAMP_FIELDS
            | contract.FUTURE_EVENT_TIMESTAMP_FIELDS,
        )
        timestamps = {
            "observed_at": "2026-08-15T00:00:00Z",
            "committed_at": "2026-08-15T00:00:01Z",
        }
        for key in contract.HISTORICAL_EVENT_TIMESTAMP_FIELDS:
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(
                    contract.ReceiptValidationError, "historical event timestamp"
                ),
            ):
                contract.require_historical_event_timestamps(
                    {key: "2026-08-15T00:00:02Z"}, timestamps
                )
        for key in contract.FUTURE_EVENT_TIMESTAMP_FIELDS:
            with self.subTest(key=key):
                contract.require_historical_event_timestamps(
                    {key: "2099-01-01T00:00:00Z"}, timestamps
                )

        envelope = envelope_for(gate.requested())
        envelope["payload"]["requested_at"] = "2099-01-01T00:00:00Z"
        _reseal(envelope)
        with self.assertRaisesRegex(
            contract.ReceiptValidationError, "historical event timestamp"
        ):
            verify(envelope)


def _reseal(envelope: dict) -> None:
    envelope["payload_sha256"] = payload_sha256(envelope["payload"])
    body = {key: value for key, value in envelope.items() if key != "receipt_id"}
    envelope["receipt_id"] = receipt_id(body)
