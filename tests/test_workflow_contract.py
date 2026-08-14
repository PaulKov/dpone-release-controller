"""Exact, dependency-free security contracts for controller workflows."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tests.restricted_yaml import RestrictedYamlError, parse_restricted_workflow
from tests.workflow_contract_fixtures import (
    EXPECTED_CI_WORKFLOW,
    EXPECTED_CONTROLLER_WORKFLOW,
    EXPECTED_WORKFLOW_FILENAMES,
)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIRECTORY = ROOT / ".github" / "workflows"
WORKFLOW = WORKFLOW_DIRECTORY / "controller-quarantine.yml"
CI_WORKFLOW = WORKFLOW_DIRECTORY / "ci.yml"
HISTORICAL_WORKFLOW = WORKFLOW_DIRECTORY / "release-controller.yml"
APP_MANIFEST = ROOT / "github-app-manifest.json"
APP_BOOTSTRAP = ROOT / "scripts" / "open-app-manifest.html"


class WorkflowContractTests(unittest.TestCase):
    """Reject semantic or structural drift from the reviewed workflow graph."""

    maxDiff = None

    def test_workflow_inventory_is_exact(self) -> None:
        actual = {
            path.name
            for path in WORKFLOW_DIRECTORY.iterdir()
            if path.is_file() and path.suffix in {".yml", ".yaml"}
        }

        self.assertEqual(actual, EXPECTED_WORKFLOW_FILENAMES)

    def test_controller_workflow_matches_exact_semantic_contract(self) -> None:
        parsed = parse_restricted_workflow(WORKFLOW.read_text(encoding="utf-8"))

        self.assertEqual(parsed, EXPECTED_CONTROLLER_WORKFLOW)

    def test_ci_workflow_matches_exact_semantic_contract(self) -> None:
        parsed = parse_restricted_workflow(CI_WORKFLOW.read_text(encoding="utf-8"))

        self.assertEqual(parsed, EXPECTED_CI_WORKFLOW)

    def test_restricted_parser_rejects_ambiguous_yaml_features(self) -> None:
        invalid_documents = {
            "duplicate key": "name: first\nname: second\n",
            "tab indentation": "name: test\njobs:\n\tbuild: value\n",
            "anchor": "name: &shared controller\n",
            "alias": "name: *shared\n",
            "merge key": "base: controller\nchild:\n  <<: *base\n",
            "folded block": "run: >\n  echo unsupported\n",
        }

        for feature, document in invalid_documents.items():
            with self.subTest(feature=feature):
                with self.assertRaises(RestrictedYamlError):
                    parse_restricted_workflow(document)

    def test_extra_step_cannot_match_controller_contract(self) -> None:
        original = WORKFLOW.read_text(encoding="utf-8")
        mutated = original.replace(
            "      - name: Upload quarantine receipt",
            (
                "      - name: Unexpected step\n"
                "        run: echo unsafe\n"
                "      - name: Upload quarantine receipt"
            ),
            1,
        )

        self.assertNotEqual(mutated, original)
        self.assertNotEqual(
            parse_restricted_workflow(mutated),
            EXPECTED_CONTROLLER_WORKFLOW,
        )

    def test_historical_live_workflow_identity_is_removed(self) -> None:
        self.assertFalse(HISTORICAL_WORKFLOW.exists())

    def test_installation_scaffold_is_exactly_read_only(self) -> None:
        manifest = json.loads(APP_MANIFEST.read_text(encoding="utf-8"))

        self.assertEqual(
            manifest["default_permissions"],
            {
                "metadata": "read",
                "contents": "read",
                "actions": "read",
                "checks": "read",
                "statuses": "read",
            },
        )

    def test_one_click_app_bootstrap_is_inert(self) -> None:
        bootstrap = APP_BOOTSTRAP.read_text(encoding="utf-8").lower()

        for forbidden in ("<form", "<script", "settings/apps/new"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, bootstrap)


if __name__ == "__main__":
    unittest.main()
