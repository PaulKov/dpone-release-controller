"""Cross-language release identity contract tests."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.evidence import release_identity as identity
from tools.evidence import release_identity_vectors as vectors
from tools.evidence.release_canonical import sha256_id

FIXTURE = Path(__file__).parent / "fixtures" / "release-identity-v2-golden.json"


class ReleaseIdentityTests(unittest.TestCase):
    def test_checked_in_fixture_is_exact_canonical_python_output(self) -> None:
        expected = vectors.fixture_bytes()
        self.assertEqual(FIXTURE.read_bytes(), expected)

    def test_every_shared_positive_vector_is_self_consistent(self) -> None:
        raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
        for name in ("release", "authority", "candidate", "attempt"):
            vector = raw[name]
            with self.subTest(positive=name):
                self.assertEqual(
                    vector["id"],
                    sha256_id(vector["domain"], vector["payload"]),
                )

    def test_noncanonical_attempt_inputs_are_rejected_without_bool_aliases(
        self,
    ) -> None:
        authority_id = "sha256:" + ("a" * 64)
        for run_id, run_attempt in (
            (True, 1),
            (1, True),
            (0, 1),
            (1, 0),
            (identity.MAX_SAFE_INTEGER + 1, 1),
            (1, identity.MAX_SAFE_INTEGER + 1),
        ):
            with self.subTest(run_id=run_id, run_attempt=run_attempt):
                with self.assertRaises(identity.ReleaseIdentityError):
                    identity.attempt_id(
                        release_authority_id=authority_id,
                        controller_workflow_id=316_322_127,
                        controller_run_id=run_id,
                        controller_run_attempt=run_attempt,
                    )
        with self.assertRaises(identity.ReleaseIdentityError):
            identity.attempt_id(
                release_authority_id=authority_id,
                controller_workflow_id=identity.MAX_SAFE_INTEGER + 1,
                controller_run_id=1,
                controller_run_attempt=1,
            )

    def test_release_and_digest_syntax_are_strict(self) -> None:
        with self.assertRaises(identity.ReleaseIdentityError):
            identity.release_identity_id("v0.74.0-rc.1")
        with self.assertRaises(identity.ReleaseIdentityError):
            identity.candidate_id(
                release_authority_id="a" * 64,
                candidate_inventory_sha256="sha256:" + ("b" * 64),
            )


if __name__ == "__main__":
    unittest.main()
