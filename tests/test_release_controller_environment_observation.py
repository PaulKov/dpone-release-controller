"""Adversarial normalized A0 controller-environment tests."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from tests.release_controller_environment_fixtures import observation
from tools.evidence.release_canonical import MAX_SAFE_INTEGER, canonical_json_bytes
from tools.evidence.release_controller_environment_observation import (
    EnvironmentObservationError,
    verify,
)
from tools.evidence.release_controller_provider_profile import REQUIRED_PROVIDER_PROFILE
from tools.evidence.release_controller_provider_vectors import encoded as profile_bytes

FIXTURE = Path("tests/fixtures/release-controller-environments-a0-v1.json")
PROFILE_FIXTURE = Path(
    "tests/fixtures/release-controller-required-provider-profile-v1.json"
)
CONFIG = Path("config/release-controller-v2.json")
NOW = datetime(2026, 8, 15, 0, 0, 30, tzinfo=timezone.utc)


class EnvironmentObservationTests(unittest.TestCase):
    def test_checked_fixture_is_current_and_valid(self) -> None:
        value = observation()
        self.assertEqual(FIXTURE.read_bytes(), canonical_json_bytes(value))
        _verify(value)

    def test_checked_static_profile_has_no_live_provider_ids(self) -> None:
        self.assertEqual(PROFILE_FIXTURE.read_bytes(), profile_bytes())
        config = json.loads(CONFIG.read_text())
        self.assertEqual(config["required_provider_profile"], REQUIRED_PROVIDER_PROFILE)
        encoded_profile = json.dumps(REQUIRED_PROVIDER_PROFILE)
        for forbidden in ('"app_id"', '"installation_id"', '"environment_id"'):
            self.assertNotIn(forbidden, encoded_profile)

    def test_tag_policy_is_exact_and_environment_ids_are_unique(self) -> None:
        cases = []
        protected = observation()
        protected["controller_environments"]["pypi"]["deployment_branch_policy"] = {
            "protected_branches": True,
            "custom_branch_policies": False,
        }
        cases.append(protected)
        wildcard = observation()
        wildcard["controller_environments"]["pypi"]["deployment_policies"][0][
            "name"
        ] = "v*"
        cases.append(wildcard)
        branch = observation()
        branch["controller_environments"]["pypi"]["deployment_policies"][0]["type"] = (
            "branch"
        )
        cases.append(branch)
        duplicate = observation()
        duplicate["controller_environments"]["github-release"]["environment_id"] = (
            duplicate["controller_environments"]["release-attest"]["environment_id"]
        )
        cases.append(duplicate)
        for value in cases:
            with (
                self.subTest(value=value),
                self.assertRaises(EnvironmentObservationError),
            ):
                _verify(value)

    def test_bypass_secrets_variables_and_extra_rules_fail_closed(self) -> None:
        mutations = (
            ("release-attest", "can_admins_bypass", True),
            ("release-attest", "secret_count", 1),
            ("github-release", "variable_count", 1),
            ("pypi", "protection_rule_count", 2),
        )
        for environment, key, value in mutations:
            changed = observation()
            changed["controller_environments"][environment][key] = value
            with self.subTest(key=key), self.assertRaises(EnvironmentObservationError):
                _verify(changed)
        extra = observation()
        extra["controller_environments"]["release-attest"]["protection_rules"].append(
            {"type": "wait_timer"}
        )
        with self.assertRaises(EnvironmentObservationError):
            _verify(extra)

    def test_gate_role_installation_and_activation_evidence_are_bound(self) -> None:
        for key, value in (
            ("app_id", 9_000_002),
            ("installation_id", 10_000_002),
            ("accepted_action", "approved"),
            ("enabled", False),
        ):
            changed = observation()
            changed["controller_environments"]["pypi"]["protection_rules"][0][key] = (
                value
            )
            with self.subTest(key=key), self.assertRaises(EnvironmentObservationError):
                _verify(changed)
        changed = observation()
        changed["controller_environments"]["pypi"]["activation_evidence"][
            "provider_observation_sha256"
        ] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(EnvironmentObservationError, "cross-bind"):
            _verify(changed)

    def test_stale_future_bool_and_non_safe_ids_are_rejected(self) -> None:
        cases = []
        for observed_at in (
            "2026-08-14T23:54:59Z",
            "2026-08-15T00:01:01Z",
        ):
            changed = observation()
            changed["observed_at"] = observed_at
            cases.append(changed)
        for value in (True, MAX_SAFE_INTEGER + 1):
            changed = observation()
            changed["controller_environments"]["pypi"]["environment_id"] = value
            cases.append(changed)
        for changed in cases:
            with (
                self.subTest(changed=changed),
                self.assertRaises(EnvironmentObservationError),
            ):
                _verify(changed)


def _verify(value: dict) -> None:
    verify(
        value,
        gate_app_id=9_000_001,
        gate_installation_id=10_000_001,
        now=NOW,
    )


if __name__ == "__main__":
    unittest.main()
