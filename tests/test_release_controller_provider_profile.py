"""Closed provider-profile tests for controller activation preflight."""

from __future__ import annotations

import json
import unittest

from tests.release_controller_preflight_fixtures import config, temporary_config
from tools.evidence.release_controller_preflight import (
    ProductionPreflightError,
    load_activation_contract,
)
from tools.evidence.release_controller_provider_profile import (
    REQUIRED_PROVIDER_PROFILE,
)


class ProviderProfileTests(unittest.TestCase):
    def test_checked_in_profile_matches_the_closed_source(self) -> None:
        observed = config()["required_provider_profile"]
        self.assertEqual(observed, REQUIRED_PROVIDER_PROFILE)
        self.assertEqual(len(observed["github_apps"]), 7)
        self.assertNotIn("app_id", json.dumps(observed))
        self.assertNotIn("installation_id", json.dumps(observed))
        self.assertEqual(
            observed["github_apps"]["pypi_deployment_gate"]["subscribed_events"],
            ["deployment_protection_rule"],
        )
        runtime_gate = observed["github_apps"]["runtime_deployment_gate"]
        self.assertEqual(runtime_gate["permissions"]["deployments"], "write")
        self.assertEqual(runtime_gate["subscription_action"], "requested")
        self.assertEqual(
            observed["target_runtime"]["environments"]["ghcr"]["protection_rule"][
                "app_role"
            ],
            "runtime_deployment_gate",
        )

    def test_required_provider_profile_cannot_be_weakened(self) -> None:
        mutations = (
            ("github_actions", "sha_pinning_required", False),
            ("github_apps", "pypi_deployment_gate", {}),
            ("github_apps", "runtime_deployment_gate", {}),
            ("trusted_controller", "environments", {}),
            ("target_runtime", "environments", {}),
        )
        for owner, key, value in mutations:
            changed = config()
            changed["required_provider_profile"][owner][key] = value
            with self.subTest(owner=owner, key=key), temporary_config(changed) as path:
                with self.assertRaisesRegex(
                    ProductionPreflightError, "required_provider_profile"
                ):
                    load_activation_contract(path)


if __name__ == "__main__":
    unittest.main()
