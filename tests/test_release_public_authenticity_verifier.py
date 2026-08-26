"""Tests for the dormant offline public-authenticity boundary."""

from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tests.public_authenticity_test_support import (
    PublicAuthenticityFixtureMixin,
)
from tools.public_authenticity.verifier import (
    PublicAuthenticityError,
    canonical_observation_bytes,
    verify_public_archive_authenticity,
)


class PublicAuthenticityVerifierTests(
    PublicAuthenticityFixtureMixin, unittest.TestCase
):
    def test_builds_the_exact_offline_verification_command(self) -> None:
        calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

        def runner(
            command: tuple[str, ...], **kwargs: Any
        ) -> subprocess.CompletedProcess[bytes]:
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, self._success_output(), b"")

        with patch(
            "tools.public_authenticity.verifier.run_bounded_process",
            side_effect=runner,
        ):
            observation = verify_public_archive_authenticity(
                artifact=self.artifact,
                bundle=self.bundle,
                gh_binary=self.gh,
                policy=self.policy,
                trusted_root=self.trusted_root,
            )

        self.assertEqual(len(calls), 1)
        command, options = calls[0]
        self.assertEqual(Path(command[0]).name, "gh")
        staged_artifact = command[3]
        staged_bundle = command[command.index("--bundle") + 1]
        staged_root = command[command.index("--custom-trusted-root") + 1]
        self.assertEqual(
            command,
            (
                command[0],
                "attestation",
                "verify",
                staged_artifact,
                "--repo",
                "PaulKov/dpone-release-controller",
                "--hostname",
                "github.com",
                "--bundle",
                staged_bundle,
                "--custom-trusted-root",
                staged_root,
                "--predicate-type",
                "https://slsa.dev/provenance/v1",
                "--digest-alg",
                "sha256",
                "--cert-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                "--cert-identity",
                "https://github.com/PaulKov/dpone-release-controller/"
                ".github/workflows/release-controller.yml@refs/tags/v1.2.3",
                "--signer-digest",
                "a" * 40,
                "--source-digest",
                "b" * 40,
                "--source-ref",
                "refs/tags/v1.2.3",
                "--deny-self-hosted-runners",
                "--format",
                "json",
            ),
        )
        self.assertEqual(
            set(options["env"]),
            {
                "GH_CONFIG_DIR",
                "GH_NO_UPDATE_NOTIFIER",
                "GH_PROMPT_DISABLED",
                "HOME",
                "LANG",
                "LC_ALL",
                "NO_COLOR",
                "TMPDIR",
            },
        )
        self.assertEqual(options["timeout_seconds"], 120)
        self.assertEqual(options["max_stdout_bytes"], 8_388_608)
        self.assertEqual(options["max_stderr_bytes"], 1_048_576)
        document = json.loads(canonical_observation_bytes(observation))
        self.assertEqual(
            document["schema"], "dpone.release-public-authenticity-observation.v1"
        )
        self.assertEqual(
            document["artifact_sha256"],
            f"sha256:{hashlib.sha256(b'public-archive').hexdigest()}",
        )

    def test_rejects_verifier_binary_drift_before_runner_access(self) -> None:
        policy = replace(self.policy, gh_binary_sha256="c" * 64)
        with patch("tools.public_authenticity.verifier.run_bounded_process") as runner:
            with self.assertRaisesRegex(
                PublicAuthenticityError, "PUBLIC_AUTH_VERIFIER_DIGEST_MISMATCH"
            ):
                verify_public_archive_authenticity(
                    artifact=self.artifact,
                    bundle=self.bundle,
                    gh_binary=self.gh,
                    policy=policy,
                    trusted_root=self.trusted_root,
                )
            runner.assert_not_called()

    def test_rejects_every_a0_input_digest_drift_before_execution(self) -> None:
        for field, code in (
            ("artifact_sha256", "PUBLIC_AUTH_ARTIFACT_DIGEST_MISMATCH"),
            ("bundle_sha256", "PUBLIC_AUTH_BUNDLE_DIGEST_MISMATCH"),
            ("trusted_root_sha256", "PUBLIC_AUTH_TRUSTED_ROOT_DIGEST_MISMATCH"),
        ):
            with self.subTest(field=field):
                with patch(
                    "tools.public_authenticity.verifier.run_bounded_process"
                ) as runner:
                    with self.assertRaisesRegex(PublicAuthenticityError, code):
                        verify_public_archive_authenticity(
                            artifact=self.artifact,
                            bundle=self.bundle,
                            gh_binary=self.gh,
                            policy=replace(self.policy, **{field: "c" * 64}),
                            trusted_root=self.trusted_root,
                        )
                    runner.assert_not_called()

    def test_rejects_every_symlinked_input_before_runner_access(self) -> None:
        for field, source, label in (
            ("artifact", self.artifact, "ARTIFACT"),
            ("bundle", self.bundle, "BUNDLE"),
            ("trusted_root", self.trusted_root, "TRUSTED_ROOT"),
            ("gh_binary", self.gh, "VERIFIER"),
        ):
            with self.subTest(field=field):
                link = self.root / f"{field}-link"
                link.symlink_to(source)
                arguments = {
                    "artifact": self.artifact,
                    "bundle": self.bundle,
                    "gh_binary": self.gh,
                    "policy": self.policy,
                    "trusted_root": self.trusted_root,
                }
                arguments[field] = link
                with patch(
                    "tools.public_authenticity.verifier.run_bounded_process"
                ) as runner:
                    with self.assertRaisesRegex(
                        PublicAuthenticityError,
                        f"PUBLIC_AUTH_{label}_(?:TYPE_INVALID|UNAVAILABLE)",
                    ):
                        verify_public_archive_authenticity(**arguments)
                    runner.assert_not_called()

    def test_rejects_empty_input_and_nonexecutable_verifier(self) -> None:
        empty_bundle = self._write("empty-bundle.jsonl", b"")
        with self.assertRaisesRegex(
            PublicAuthenticityError, "PUBLIC_AUTH_BUNDLE_SIZE_INVALID"
        ):
            verify_public_archive_authenticity(
                artifact=self.artifact,
                bundle=empty_bundle,
                gh_binary=self.gh,
                policy=self.policy,
                trusted_root=self.trusted_root,
            )
        self.gh.chmod(0o600)
        with self.assertRaisesRegex(
            PublicAuthenticityError, "PUBLIC_AUTH_VERIFIER_NOT_EXECUTABLE"
        ):
            verify_public_archive_authenticity(
                artifact=self.artifact,
                bundle=self.bundle,
                gh_binary=self.gh,
                policy=self.policy,
                trusted_root=self.trusted_root,
            )

    def test_rejects_relative_paths_before_runner_access(self) -> None:
        with self.assertRaisesRegex(
            PublicAuthenticityError, "PUBLIC_AUTH_ARTIFACT_PATH_INVALID"
        ):
            verify_public_archive_authenticity(
                artifact=Path("closure.zip"),
                bundle=self.bundle,
                gh_binary=self.gh,
                policy=self.policy,
                trusted_root=self.trusted_root,
            )

    def test_rejects_noncanonical_semver_ref_before_runner_access(self) -> None:
        with patch("tools.public_authenticity.verifier.run_bounded_process") as runner:
            with self.assertRaisesRegex(
                PublicAuthenticityError, "PUBLIC_AUTH_SOURCE_REF_INVALID"
            ):
                verify_public_archive_authenticity(
                    artifact=self.artifact,
                    bundle=self.bundle,
                    gh_binary=self.gh,
                    policy=replace(self.policy, source_ref="refs/tags/v01.2.3"),
                    trusted_root=self.trusted_root,
                )
            runner.assert_not_called()

    def test_rejects_unverified_or_ambiguous_output(self) -> None:
        for output, code in (
            (b"[]", "PUBLIC_AUTH_VERIFIER_RESULT_COUNT_INVALID"),
            (b"[{},{}]", "PUBLIC_AUTH_VERIFIER_RESULT_COUNT_INVALID"),
            (b"[{}]", "PUBLIC_AUTH_VERIFIER_RESULT_SHAPE_INVALID"),
        ):
            with self.subTest(code=code):
                with self.assertRaisesRegex(PublicAuthenticityError, code):
                    with patch(
                        "tools.public_authenticity.verifier.run_bounded_process",
                        return_value=subprocess.CompletedProcess((), 0, output, b""),
                    ):
                        verify_public_archive_authenticity(
                            artifact=self.artifact,
                            bundle=self.bundle,
                            gh_binary=self.gh,
                            policy=self.policy,
                            trusted_root=self.trusted_root,
                        )

    def test_rejects_nonzero_verifier_exit(self) -> None:
        with self.assertRaisesRegex(
            PublicAuthenticityError, "PUBLIC_AUTH_VERIFICATION_FAILED"
        ):
            with patch(
                "tools.public_authenticity.verifier.run_bounded_process",
                return_value=subprocess.CompletedProcess((), 1, b"", b"x"),
            ):
                verify_public_archive_authenticity(
                    artifact=self.artifact,
                    bundle=self.bundle,
                    gh_binary=self.gh,
                    policy=self.policy,
                    trusted_root=self.trusted_root,
                )

    def test_executes_only_private_snapshots(self) -> None:
        def runner(
            command: tuple[str, ...], **_kwargs: Any
        ) -> subprocess.CompletedProcess[bytes]:
            self.artifact.write_bytes(b"changed-after-snapshot")
            staged_artifact = Path(command[3])
            self.assertNotEqual(staged_artifact, self.artifact)
            self.assertEqual(staged_artifact.read_bytes(), b"public-archive")
            self.assertEqual(Path(command[0]).read_bytes(), b"pinned-gh-binary")
            return subprocess.CompletedProcess(command, 0, self._success_output(), b"")

        with patch(
            "tools.public_authenticity.verifier.run_bounded_process",
            side_effect=runner,
        ):
            observation = verify_public_archive_authenticity(
                artifact=self.artifact,
                bundle=self.bundle,
                gh_binary=self.gh,
                policy=self.policy,
                trusted_root=self.trusted_root,
            )
        self.assertEqual(
            observation.artifact_sha256,
            f"sha256:{hashlib.sha256(b'public-archive').hexdigest()}",
        )


if __name__ == "__main__":
    unittest.main()
