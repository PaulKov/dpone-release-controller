"""Adversarial tests for verified GitHub attestation output."""

from __future__ import annotations

import json
import subprocess
import unittest
from unittest.mock import patch

from tests.public_authenticity_test_support import (
    PublicAuthenticityFixtureMixin,
)
from tools.public_authenticity.verifier import (
    PublicAuthenticityError,
    verify_public_archive_authenticity,
)


class PublicAuthenticityOutputTests(PublicAuthenticityFixtureMixin, unittest.TestCase):
    def test_normalizes_python_integer_limit_failure(self) -> None:
        output = b"[" + (b"9" * 5_000) + b"]"
        with patch(
            "tools.public_authenticity.verifier.run_bounded_process",
            return_value=subprocess.CompletedProcess((), 0, output, b""),
        ):
            with self.assertRaisesRegex(
                PublicAuthenticityError, "PUBLIC_AUTH_VERIFIER_OUTPUT_INVALID"
            ):
                verify_public_archive_authenticity(
                    artifact=self.artifact,
                    bundle=self.bundle,
                    gh_binary=self.gh,
                    policy=self.policy,
                    trusted_root=self.trusted_root,
                )

    def test_rejects_incomplete_verified_evidence(self) -> None:
        cases = (
            (
                lambda result: result["signature"].clear(),
                "PUBLIC_AUTH_VERIFIER_SIGNATURE_MISSING",
            ),
            (
                lambda result: result.__setitem__(
                    "verifiedTimestamps", [{"type": "TimestampAuthority"}]
                ),
                "PUBLIC_AUTH_VERIFIER_TLOG_MISSING",
            ),
            (
                lambda result: result["statement"]["subject"][0]["digest"].update(
                    sha256="c" * 64
                ),
                "PUBLIC_AUTH_VERIFIER_SUBJECT_INVALID",
            ),
            (
                lambda result: result["verifiedIdentity"]["issuer"].update(
                    regexp="invalid"
                ),
                "PUBLIC_AUTH_VERIFIER_POLICY_SHAPE_INVALID",
            ),
            (
                lambda result: result["verifiedIdentity"][
                    "subjectAlternativeName"
                ].update(subjectAlternativeName="https://identity.invalid"),
                "PUBLIC_AUTH_VERIFIER_IDENTITY_MISMATCH",
            ),
            (
                lambda result: result["signature"]["certificate"].update(
                    issuer="https://issuer.invalid"
                ),
                "PUBLIC_AUTH_VERIFIER_CERTIFICATE_CLAIM_MISMATCH",
            ),
            (
                lambda result: result["signature"]["certificate"].update(
                    sourceRepositoryDigest="c" * 40
                ),
                "PUBLIC_AUTH_VERIFIER_CERTIFICATE_CLAIM_MISMATCH",
            ),
        )
        for mutate, code in cases:
            with self.subTest(code=code):
                document = json.loads(self._success_output())
                mutate(document[0]["verificationResult"])
                output = json.dumps(document, separators=(",", ":")).encode()
                with patch(
                    "tools.public_authenticity.verifier.run_bounded_process",
                    return_value=subprocess.CompletedProcess((), 0, output, b""),
                ):
                    with self.assertRaisesRegex(PublicAuthenticityError, code):
                        verify_public_archive_authenticity(
                            artifact=self.artifact,
                            bundle=self.bundle,
                            gh_binary=self.gh,
                            policy=self.policy,
                            trusted_root=self.trusted_root,
                        )


if __name__ == "__main__":
    unittest.main()
