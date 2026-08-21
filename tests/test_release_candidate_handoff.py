"""Adversarial tests for the closed release-candidate handoff."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from tools.evidence import release_candidate_codec as candidate_codec
from tools.evidence import release_receipt_inventory
from tools.evidence.release_candidate_handoff import (
    CandidateHandoffError,
    SUPPLEMENTAL_UNSIGNED_MEMBERS,
    verify_candidate_artifact,
)
from tests.release_candidate_handoff_test_support import (
    ARTIFACT_DIGEST,
    ARTIFACT_ID,
    PRODUCER_GOLDEN,
    PRODUCER_SCHEMA,
    RUN_ATTEMPT,
    RUN_ID,
    TAG,
    _binding,
    _seal_manifest,
    write_candidate,
    _write_json,
)


class CandidateHandoffContractTests(unittest.TestCase):
    def test_mirrored_producer_schema_and_golden_bytes_are_exact(self) -> None:
        self.assertEqual(
            hashlib.sha256(PRODUCER_SCHEMA.read_bytes()).hexdigest(),
            "b4245cfadeab72fc104e5723a3188169ac0c6a705d190e00140ea0e1d10103c3",
        )
        self.assertEqual(
            hashlib.sha256(PRODUCER_GOLDEN.read_bytes()).hexdigest(),
            "ea2974c03c496c2152064405ad630edb1fd126f6b6c7431c66d1af1aa0614e1a",
        )
        manifest = candidate_codec.parse_manifest(
            candidate_codec.load_unique_json(PRODUCER_GOLDEN.read_bytes(), "golden")
        )
        self.assertEqual(manifest.release, TAG)
        self.assertEqual(len(manifest.members), 24)
        self.assertEqual(
            manifest.supplemental_unsigned_members, SUPPLEMENTAL_UNSIGNED_MEMBERS
        )

    def test_exact_producer_fixture_binds_outer_provider_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_candidate(root)

            verified = verify_candidate_artifact(root, _binding())

        self.assertEqual(verified.binding.artifact_id, ARTIFACT_ID)
        self.assertEqual(verified.manifest.release, TAG)
        self.assertEqual(len(verified.manifest.distributions), 8)
        self.assertEqual(len(verified.manifest.members), 24)
        distributions = [
            {
                "project": record.package,
                "version": record.version,
                "filename": record.filename,
                "size_bytes": record.size_bytes,
                "sha256": record.sha256,
            }
            for record in verified.manifest.distributions
        ]
        self.assertEqual(
            verified.receipt_payload(),
            {
                "kind": "CANDIDATE_HANDOFF",
                "state": "CANDIDATE_HANDOFF",
                "candidate_id": verified.manifest.candidate_id,
                "candidate_inventory_sha256": (
                    verified.manifest.candidate_inventory_sha256
                ),
                "candidate_run_id": RUN_ID,
                "candidate_run_attempt": RUN_ATTEMPT,
                "candidate_artifact_id": ARTIFACT_ID,
                "candidate_artifact_digest": ARTIFACT_DIGEST,
                "candidate_manifest_sha256": verified.manifest.manifest_sha256,
                "file_count": 25,
                "total_bytes": verified.total_bytes,
                "distribution_inventory": distributions,
                "distribution_inventory_sha256": (
                    release_receipt_inventory.inventory_sha256(
                        release_receipt_inventory.DISTRIBUTION_SCHEMA,
                        distributions,
                    )
                ),
            },
        )

    def test_outer_artifact_fields_are_forbidden_inside_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = write_candidate(root)
            manifest["artifact_id"] = ARTIFACT_ID
            _write_json(root / "candidate-handoff-v2.json", manifest)

            with self.assertRaisesRegex(CandidateHandoffError, "unexpected"):
                verify_candidate_artifact(root, _binding())

    def test_supplemental_unsigned_classification_is_exact_and_ordered(self) -> None:
        mutations = {
            "missing": lambda values: values[:-1],
            "reordered": lambda values: list(reversed(values)),
            "authority_alias": lambda values: [
                *values[:-1],
                "evidence/supply-chain/signed-supply-chain-attestation.json",
            ],
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = write_candidate(root)
                manifest["supplemental_unsigned_members"] = mutate(
                    list(SUPPLEMENTAL_UNSIGNED_MEMBERS)
                )
                _seal_manifest(root, manifest)

                with self.assertRaisesRegex(
                    CandidateHandoffError,
                    "supplemental unsigned member classification mismatch",
                ):
                    verify_candidate_artifact(root, _binding())
