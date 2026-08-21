"""Unit tests for the fail-closed controller preflight contract."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "controller_preflight.py"
SPEC = importlib.util.spec_from_file_location("controller_preflight", MODULE_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - test bootstrap invariant
    raise RuntimeError(f"cannot import {MODULE_PATH}")
preflight = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = preflight
SPEC.loader.exec_module(preflight)


class ControllerPreflightTests(unittest.TestCase):
    """Exercise input normalization and the independent activation bindings."""

    def setUp(self) -> None:
        self.policy_path = ROOT / "config" / "release-controller-activation.json"

    def test_checked_in_policy_is_quarantined(self) -> None:
        policy = preflight.load_activation_policy(self.policy_path)

        self.assertEqual(policy.state, "quarantined")
        self.assertEqual(policy.policy_version, 1)
        self.assertFalse(policy.live_mutation_enabled)
        self.assertIsNone(policy.activation_marker_sha256)

    def test_dry_run_normalizes_empty_tag_without_enabling_live(self) -> None:
        inputs, live_enabled = preflight.evaluate_environment(
            self.policy_path,
            self._environment(),
        )

        self.assertEqual(inputs.tag, "v0.0.0-quarantine.12345")
        self.assertEqual(inputs.ttl_seconds, 900)
        self.assertFalse(live_enabled)

    def test_checked_in_policy_rejects_live_mode(self) -> None:
        with self.assertRaisesRegex(preflight.PreflightError, "active policy v2"):
            preflight.evaluate_environment(
                self.policy_path,
                self._environment(
                    INPUT_MODE="live",
                    INPUT_TAG="v0.74.0",
                    CONTROLLER_ACTIVATION_MARKER="present-but-not-authorized",
                    CONTROLLER_ACTIVATION_COMMIT_SHA="a" * 40,
                ),
            )

    def test_live_mode_requires_explicit_tag_before_policy_evaluation(self) -> None:
        with self.assertRaisesRegex(preflight.PreflightError, "explicit canonical tag"):
            preflight.evaluate_environment(
                self.policy_path,
                self._environment(INPUT_MODE="live", INPUT_TAG=""),
            )

    def test_active_policy_requires_marker_and_exact_commit_binding(self) -> None:
        marker = "reviewed-marker"
        policy_path = self._write_policy(
            state="active",
            policy_version=2,
            enabled=True,
            marker_digest="sha256:" + hashlib.sha256(marker.encode()).hexdigest(),
        )
        environment = self._environment(
            INPUT_MODE="live",
            INPUT_TAG="v0.74.0",
            CONTROLLER_ACTIVATION_MARKER=marker,
            CONTROLLER_ACTIVATION_COMMIT_SHA="b" * 40,
        )

        with self.assertRaisesRegex(preflight.PreflightError, "commit binding"):
            preflight.evaluate_environment(policy_path, environment)

        environment["CONTROLLER_ACTIVATION_COMMIT_SHA"] = "a" * 40
        _inputs, live_enabled = preflight.evaluate_environment(policy_path, environment)
        self.assertTrue(live_enabled)

    def test_active_policy_rejects_wrong_marker(self) -> None:
        policy_path = self._write_policy(
            state="active",
            policy_version=2,
            enabled=True,
            marker_digest="sha256:" + hashlib.sha256(b"expected").hexdigest(),
        )
        with self.assertRaisesRegex(preflight.PreflightError, "marker does not match"):
            preflight.evaluate_environment(
                policy_path,
                self._environment(
                    INPUT_MODE="live",
                    INPUT_TAG="v0.74.0",
                    CONTROLLER_ACTIVATION_MARKER="wrong",
                    CONTROLLER_ACTIVATION_COMMIT_SHA="a" * 40,
                ),
            )

    def test_workflow_identity_is_exact_and_ref_confined(self) -> None:
        drift_cases = {
            "GITHUB_REPOSITORY": "fork/dpone-release-controller",
            "GITHUB_REPOSITORY_ID": "1",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/historical-live-workflow",
            "GITHUB_WORKFLOW_REF": (
                f"{preflight.CONTROLLER_REPOSITORY}/{preflight.WORKFLOW_PATH}"
                "@refs/heads/historical-live-workflow"
            ),
            "GITHUB_SHA": "not-a-commit",
        }
        for key, value in drift_cases.items():
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(preflight.PreflightError, key),
            ):
                preflight.evaluate_environment(
                    self.policy_path,
                    self._environment(**{key: value}),
                )

    def test_rejects_shell_payloads_and_noncanonical_values(self) -> None:
        invalid_cases = (
            {"mode": "live; echo pwned", "tag": "v0.74.0", "ttl_seconds": "900"},
            {"mode": "dry-run", "tag": "$(touch pwned)", "ttl_seconds": "900"},
            {"mode": "dry-run", "tag": "v01.74.0", "ttl_seconds": "900"},
            {"mode": "dry-run", "tag": "v0.74.0+build", "ttl_seconds": "900"},
            {"mode": "dry-run", "tag": "v0.74.0", "ttl_seconds": "900; true"},
            {"mode": "dry-run", "tag": "v0.74.0", "ttl_seconds": "٠٩٠"},
        )
        for case in invalid_cases:
            with self.subTest(case=case), self.assertRaises(preflight.PreflightError):
                preflight.validate_inputs(run_id="12345", **case)

    def test_ttl_boundaries_are_explicit(self) -> None:
        for accepted in ("60", "3600"):
            with self.subTest(accepted=accepted):
                result = preflight.validate_inputs(
                    mode="dry-run", tag="v0.74.0", ttl_seconds=accepted, run_id="1"
                )
                self.assertEqual(result.ttl_seconds, int(accepted))
        for rejected in ("59", "3601"):
            with (
                self.subTest(rejected=rejected),
                self.assertRaises(preflight.PreflightError),
            ):
                preflight.validate_inputs(
                    mode="dry-run", tag="v0.74.0", ttl_seconds=rejected, run_id="1"
                )

    def test_policy_rejects_unknown_fields_and_inconsistent_state(self) -> None:
        raw = self._policy_mapping(
            state="quarantined", policy_version=1, enabled=False, marker_digest=None
        )
        raw["unexpected"] = True
        with self.assertRaisesRegex(preflight.PreflightError, "keys mismatch"):
            preflight.ActivationPolicy.from_mapping(raw)

        raw.pop("unexpected")
        raw["live_mutation_enabled"] = True
        with self.assertRaisesRegex(preflight.PreflightError, "quarantined policy"):
            preflight.ActivationPolicy.from_mapping(raw)

    def test_policy_rejects_duplicate_json_keys(self) -> None:
        policy_path = self._write_policy(
            state="quarantined",
            policy_version=1,
            enabled=False,
            marker_digest=None,
        )
        policy_path.write_text(
            policy_path.read_text(encoding="utf-8").replace(
                '"reason": "test fixture"',
                '"reason": "first", "reason": "second"',
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(preflight.PreflightError, "duplicate JSON"):
            preflight.load_activation_policy(policy_path)

    def test_receipt_names_the_controlled_mutation_boundary(self) -> None:
        receipt = preflight._dry_run_receipt(
            self.policy_path,
            self._environment(INPUT_TAG="v0.74.0"),
        )

        self.assertFalse(receipt["controlled_release_provider_mutation_executed"])
        self.assertNotIn("external_mutation_executed", receipt)
        self.assertEqual(receipt["controller_ref"], preflight.CONTROLLER_REF)

    @staticmethod
    def _environment(**overrides: str) -> dict[str, str]:
        environment = {
            "INPUT_MODE": "dry-run",
            "INPUT_TAG": "",
            "INPUT_TTL_SECONDS": "900",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_REPOSITORY": preflight.CONTROLLER_REPOSITORY,
            "GITHUB_REPOSITORY_ID": str(preflight.CONTROLLER_REPOSITORY_ID),
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": preflight.CONTROLLER_REF,
            "GITHUB_WORKFLOW_REF": preflight.EXPECTED_WORKFLOW_REF,
        }
        environment.update(overrides)
        return environment

    def _write_policy(
        self,
        *,
        state: str,
        policy_version: int,
        enabled: bool,
        marker_digest: str | None,
    ) -> Path:
        directory = Path(tempfile.mkdtemp(prefix="controller-preflight-test-"))
        self.addCleanup(directory.rmdir)
        self.addCleanup(lambda: (directory / "policy.json").unlink(missing_ok=True))
        path = directory / "policy.json"
        path.write_text(
            json.dumps(
                self._policy_mapping(
                    state=state,
                    policy_version=policy_version,
                    enabled=enabled,
                    marker_digest=marker_digest,
                )
            ),
            encoding="utf-8",
        )
        return path

    @staticmethod
    def _policy_mapping(
        *,
        state: str,
        policy_version: int,
        enabled: bool,
        marker_digest: str | None,
    ) -> dict[str, Any]:
        return {
            "schema": preflight.POLICY_SCHEMA,
            "state": state,
            "policy_version": policy_version,
            "live_mutation_enabled": enabled,
            "target_repository": preflight.TARGET_REPOSITORY,
            "target_repository_id": preflight.TARGET_REPOSITORY_ID,
            "workflow_path": preflight.WORKFLOW_PATH,
            "activation_marker_sha256": marker_digest,
            "reason": "test fixture",
        }


if __name__ == "__main__":
    unittest.main()
