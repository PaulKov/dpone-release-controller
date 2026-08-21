"""Adversarial tests for the closed receipt-envelope v2 contract."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator

from scripts.canonicalize_release_receipt_schema import canonical_schema_bytes
from tests import release_receipt_chain_fixtures as chain_fixture
from tests import release_receipt_publish_fixtures as publish
from tests.release_receipt_fixtures import (
    CANDIDATE_ID,
    LEASE_ID,
    RELEASE_ID,
    all_payloads,
    envelope_for,
)
from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_broker_record_envelope as broker_envelope
from tools.evidence import release_receipt_reference_vectors as reference_vectors
from tools.evidence import release_receipt_schema_registry as schema_registry
from tools.evidence.release_receipt_envelope_v2 import (
    decode,
    encode,
    payload_sha256,
    receipt_id,
    verify,
)
from tools.evidence.release_receipt_vectors import golden_document

GOLDEN_PATH = Path("tests/fixtures/release-receipt-v2-golden.json")
SCHEMA_PATH = Path("docs/schemas/release/release-receipt-envelope-v2.schema.json")


class ReleaseReceiptV2EnvelopeTests(unittest.TestCase):
    def test_checked_schema_is_current_and_accepts_every_closed_branch(self) -> None:
        expected = canonical_schema_bytes()
        self.assertEqual(expected, schema_registry.schema_bytes())
        self.assertEqual(SCHEMA_PATH.read_bytes(), expected)
        schema = json.loads(expected)
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        for payload in all_payloads():
            with self.subTest(kind=payload["kind"]):
                validator.validate(envelope_for(payload))

    def test_every_closed_payload_branch_round_trips_canonical_bytes(self) -> None:
        payloads = all_payloads()
        observed = set()
        for payload in payloads:
            with self.subTest(kind=payload["kind"], state=payload["state"]):
                envelope = envelope_for(payload)
                encoded = encode(envelope)
                self.assertEqual(decode(encoded), envelope)
                self.assertEqual(envelope["receipt_type"], payload["kind"])
                observed.add(payload["kind"])
        self.assertEqual(observed, set(contract.PAYLOAD_KINDS))

    def test_genesis_receipt_is_bounded_by_the_shared_broker_envelope_cap(self) -> None:
        genesis = chain_fixture.successful_chain()[0]
        encoded = encode(genesis)
        self.assertLessEqual(len(encoded), broker_envelope.MAX_BROKER_RECORD_BYTES)

        oversized = copy.deepcopy(genesis)
        oversized["padding"] = "x" * broker_envelope.MAX_BROKER_RECORD_BYTES
        with self.assertRaisesRegex(
            contract.ReceiptValidationError, "exceeds the byte contract"
        ):
            verify(oversized)

    def test_receipt_decoder_rejects_oversize_before_json_allocation(self) -> None:
        oversized = b"{" + b"x" * broker_envelope.MAX_BROKER_RECORD_BYTES
        self.assertEqual(len(oversized), broker_envelope.MAX_BROKER_RECORD_BYTES + 1)
        with mock.patch.object(
            json,
            "loads",
            side_effect=AssertionError("JSON parser must not be called"),
        ):
            with self.assertRaisesRegex(
                contract.ReceiptValidationError, "1..65536 bytes"
            ):
                decode(oversized)

    def test_domain_separated_golden_request_ids_are_stable(self) -> None:
        document = golden_document()
        envelope = document["positive"]["envelope"]
        self.assertEqual(envelope, reference_vectors.positive_envelope())
        self.assertEqual(
            envelope["payload_sha256"],
            "sha256:fcc83af875038be56f080370e4ece056c2be14acd8609aa1c6f850d9f9ff53cb",
        )
        self.assertEqual(
            envelope["receipt_id"],
            "sha256:865f8228c2fef3f5086c7f38ba43d6375ed3f328d9ea0bd4130ab4aa4ba01bc3",
        )
        self.assertEqual(json.loads(GOLDEN_PATH.read_text()), document)

    def test_receipt_type_must_equal_uppercase_payload_kind(self) -> None:
        envelope = envelope_for(all_payloads()[0])
        envelope["receipt_type"] = "request_enqueued"
        _reseal(envelope)
        with self.assertRaisesRegex(contract.ReceiptValidationError, "schema/type"):
            verify(envelope)

    def test_lease_is_forbidden_pre_acquisition_and_required_after(self) -> None:
        pre_lease = envelope_for(all_payloads()[0])
        pre_lease["lease"] = {"lease_id": LEASE_ID, "fencing_token": 3}
        _reseal(pre_lease)
        with self.assertRaises(contract.ReceiptValidationError):
            verify(pre_lease)

        acquired = envelope_for(
            next(p for p in all_payloads() if p["kind"] == "LEASE_ACQUIRED")
        )
        del acquired["lease"]
        _reseal(acquired)
        with self.assertRaises(contract.ReceiptValidationError):
            verify(acquired)

    def test_governance_a_forbids_lease_while_b_and_c_require_it(self) -> None:
        governance = [p for p in all_payloads() if p["kind"] == "GOVERNANCE_SNAPSHOT"]
        self.assertNotIn("lease", envelope_for(governance[0]))
        self.assertIn("lease", envelope_for(governance[1]))
        self.assertIn("lease", envelope_for(governance[2]))

    def test_scope_has_one_exact_identity_and_cross_binds_payload(self) -> None:
        candidate = envelope_for(
            next(p for p in all_payloads() if p["kind"] == "CANDIDATE_HANDOFF")
        )
        self.assertEqual(
            candidate["scope"], {"kind": "candidate", "candidate_id": CANDIDATE_ID}
        )
        candidate["scope"]["candidate_id"] = RELEASE_ID
        _reseal(candidate)
        with self.assertRaisesRegex(contract.ReceiptValidationError, "scope identity"):
            verify(candidate)

    def test_root_attempt_and_lease_reject_null_zero_bool_and_extensions(self) -> None:
        envelope = envelope_for(publish.authorized())
        mutations = (
            ("attempt", "attempt_id", None),
            ("attempt", "queue_entry_id", "GENESIS"),
            ("lease", "fencing_token", True),
            ("lease", "lease_id", None),
        )
        for owner, key, value in mutations:
            with self.subTest(owner=owner, key=key):
                changed = copy.deepcopy(envelope)
                changed[owner][key] = value
                _reseal(changed)
                with self.assertRaises(contract.ReceiptValidationError):
                    verify(changed)
        changed = copy.deepcopy(envelope)
        changed["attempt"]["alias"] = changed["attempt"]["attempt_id"]
        _reseal(changed)
        with self.assertRaisesRegex(contract.ReceiptValidationError, "keys mismatch"):
            verify(changed)

    def test_only_closed_can_claim_pass_go(self) -> None:
        payload = publish.authorized()
        payload["status"] = "PASS"
        payload["decision"] = "GO"
        with self.assertRaisesRegex(contract.ReceiptValidationError, "reserved"):
            envelope_for(payload)
        closed = envelope_for(publish.closed())
        self.assertEqual(
            (closed["payload"]["status"], closed["payload"]["decision"]), ("PASS", "GO")
        )


def _reseal(envelope: dict) -> None:
    envelope["payload_sha256"] = payload_sha256(envelope["payload"])
    body = {key: value for key, value in envelope.items() if key != "receipt_id"}
    envelope["receipt_id"] = receipt_id(body)
