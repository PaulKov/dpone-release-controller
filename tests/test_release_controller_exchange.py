"""Typed candidate-admit request/response codec adversarial tests."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tests import release_receipt_fixtures as receipt_fixtures
from tests.release_candidate_handoff_test_support import write_candidate
from tests.test_release_candidate_provider import (
    FROZEN_CLOCK,
    FROZEN_NOW,
    MemorySource,
    _binding,
    _observation,
    _zip_tree,
)
from tools.evidence import release_controller_exchange as exchange
from tools.evidence import release_identity
from tools.evidence.release_candidate_handoff import import_provider_candidate
from tools.evidence.release_canonical import canonical_json_bytes
from tools.evidence.release_receipt_envelope_v2 import build, encode


class ReleaseControllerExchangeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        workspace = Path(temporary.name)
        producer = workspace / "producer"
        producer.mkdir()
        write_candidate(producer)
        raw_zip = _zip_tree(producer)
        self.imported = import_provider_candidate(
            MemorySource(raw_zip),
            _observation(raw_zip),
            _binding(raw_zip),
            workspace / "candidate",
            clock=FROZEN_CLOCK,
        )
        self.request_bytes = exchange.candidate_admit_request_bytes(self.imported)
        self.request = exchange.parse_candidate_admit_request(
            self.request_bytes, now=FROZEN_NOW
        )

    def test_request_contains_only_selectors_observation_and_typed_evidence(
        self,
    ) -> None:
        raw = json.loads(self.request_bytes)
        self.assertEqual(
            set(raw),
            {
                "candidate",
                "evidence",
                "provider_observation",
                "release_identity_id",
                "schema",
                "schema_version",
            },
        )
        forbidden = {
            "attempt_id",
            "committer",
            "fencing_token",
            "lease_id",
            "producer",
            "receipt_id",
            "state",
            "timestamps",
        }
        self.assertFalse(forbidden.intersection(raw))
        self.assertFalse(forbidden.intersection(raw["evidence"]))
        self.assertEqual(
            self.request.receipt_payload,
            self.imported.receipt_payload(),
        )

    def test_broker_authored_response_and_head_hint_are_cross_bound(self) -> None:
        receipt = _receipt(self.request)
        response = _response(receipt)
        verified = exchange.parse_candidate_admit_response(
            canonical_json_bytes(response), expected=self.request
        )
        self.assertEqual(verified.receipt, receipt)
        self.assertEqual(verified.head.receipt_id, receipt["receipt_id"])

    def test_selector_observation_evidence_and_generic_authority_fail_closed(
        self,
    ) -> None:
        mutations = {
            "generic-authority": lambda value: value.update(lease_id="forged"),
            "selector": lambda value: value["candidate"].update(
                candidate_artifact_id=value["candidate"]["candidate_artifact_id"] + 1
            ),
            "observation": lambda value: value["provider_observation"].update(
                head_sha="f" * 40
            ),
            "candidate-id": lambda value: value["evidence"].update(
                candidate_id="sha256:" + ("f" * 64)
            ),
            "raw-zip": lambda value: value["evidence"].update(
                candidate_artifact_raw_zip_sha256="sha256:" + ("e" * 64)
            ),
            "payload-kind": lambda value: value["evidence"].update(
                kind="CANDIDATE_HANDOFF"
            ),
        }
        for name, mutate in mutations.items():
            raw = json.loads(self.request_bytes)
            mutate(raw)
            with (
                self.subTest(name=name),
                self.assertRaises(exchange.ControllerExchangeError),
            ):
                exchange.parse_candidate_admit_request(
                    canonical_json_bytes(raw), now=FROZEN_NOW
                )

    def test_noncanonical_duplicate_and_stale_request_fail_closed(self) -> None:
        noncanonical = json.dumps(json.loads(self.request_bytes), indent=2).encode()
        duplicate = self.request_bytes.replace(
            b'{"candidate":',
            b'{"schema_version":1,"candidate":',
            1,
        )
        for name, data in (("noncanonical", noncanonical), ("duplicate", duplicate)):
            with (
                self.subTest(name=name),
                self.assertRaises(exchange.ControllerExchangeError),
            ):
                exchange.parse_candidate_admit_request(data, now=FROZEN_NOW)

    def test_response_evidence_and_head_substitution_fail_closed(self) -> None:
        substituted_payload = copy.deepcopy(dict(self.request.receipt_payload))
        substituted_payload["candidate_manifest_sha256"] = "sha256:" + ("f" * 64)
        substituted = _response(_receipt(self.request, payload=substituted_payload))
        head = _response(_receipt(self.request))
        head["head"]["sequence"] += 1
        for name, value in (("evidence", substituted), ("head", head)):
            with (
                self.subTest(name=name),
                self.assertRaises(exchange.ControllerExchangeError),
            ):
                exchange.parse_candidate_admit_response(
                    canonical_json_bytes(value), expected=self.request
                )

    def test_error_response_is_sanitized_and_request_bound(self) -> None:
        error = canonical_json_bytes(
            {
                "error": {
                    "code": "LEDGER_CONFLICT",
                    "request_id": "request-01HXDPONE",
                    "retryable": False,
                },
                "schema": exchange.ERROR_SCHEMA,
                "schema_version": 1,
            }
        )
        parsed = exchange.parse_error_response(
            error, expected_request_id="request-01HXDPONE"
        )
        self.assertEqual(parsed.code, "LEDGER_CONFLICT")
        self.assertFalse(parsed.retryable)


def _receipt(
    request: exchange.CandidateAdmitRequest,
    *,
    payload: dict | None = None,
) -> dict:
    selected = dict(payload or request.receipt_payload)
    observation = request.provider_observation
    authority_id = release_identity.release_authority_id(
        release_identity_id=request.release_identity_id,
        tag_object_sha=observation["tag_object_sha"],
        peeled_commit_sha=request.candidate["expected_peeled_commit_sha"],
        policy_sha256=observation["policy_sha256"],
    )
    return build(
        stream={
            "release_identity_id": request.release_identity_id,
            "release_authority_id": authority_id,
            "sequence": 0,
            "previous": "GENESIS",
        },
        scope={"kind": "candidate", "candidate_id": selected["candidate_id"]},
        attempt={
            "attempt_id": receipt_fixtures.ATTEMPT_ID,
            "queue_entry_id": receipt_fixtures.QUEUE_ID,
        },
        producer=receipt_fixtures._producer(selected),
        committer=receipt_fixtures._committer(),
        timestamps=receipt_fixtures._timestamps_for(selected),
        payload=selected,
    )


def _response(receipt: dict) -> dict:
    receipt_bytes = encode(receipt)
    return {
        "head": {
            "phase": "CANDIDATE_HANDOFF",
            "receipt_id": receipt["receipt_id"],
            "receipt_sha256": "sha256:" + hashlib.sha256(receipt_bytes).hexdigest(),
            "sequence": receipt["stream"]["sequence"],
        },
        "receipt": receipt,
        "schema": exchange.CANDIDATE_ADMIT_RESPONSE_SCHEMA,
        "schema_version": 1,
    }


if __name__ == "__main__":
    unittest.main()
