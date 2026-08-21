"""Security invariants for the emergency controller quarantine."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIRECTORY = ROOT / ".github" / "workflows"
CI_WORKFLOW = WORKFLOW_DIRECTORY / "ci.yml"
QUARANTINE_WORKFLOW = WORKFLOW_DIRECTORY / "controller-quarantine.yml"
LEGACY_WORKFLOW = WORKFLOW_DIRECTORY / "release-controller.yml"
EVIDENCE_DIRECTORY = ROOT / "tools" / "evidence"
CLI_PATH = EVIDENCE_DIRECTORY / "release_evidence_cli.py"
APP_MANIFEST = ROOT / "github-app-manifest.json"
APP_BOOTSTRAP = ROOT / "scripts" / "open-app-manifest.html"
EVIDENCE_PROTOTYPE = ROOT / "evidence-store.example.json"
SCAFFOLD_STAMP = ROOT / ".scaffold-stamp"

EXPECTED_WORKFLOWS = frozenset({"ci.yml", "controller-quarantine.yml"})
EXPECTED_ACTIONS = frozenset(
    {
        "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
    }
)
FORBIDDEN_WORKFLOW_TEXT = (
    "workflow_dispatch",
    "pull_request_target",
    "schedule:",
    "secrets.",
    "id-token:",
    "attestations:",
    "contents: write",
    "actions: write",
    "administration: write",
    "packages: write",
    "B2_APPLICATION_KEY",
    "DPONE_RELEASE_APP",
    "create-github-app-token",
    "attest-build-provenance",
    "upload-artifact",
)


def load_tombstone() -> object:
    """Load the one retained CLI without importing a package graph."""

    spec = importlib.util.spec_from_file_location("retired_release_cli", CLI_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {CLI_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WorkflowQuarantineTests(unittest.TestCase):
    """Prove that the checked-in Actions graph has no release authority."""

    def test_workflow_inventory_is_exact_and_legacy_writer_is_removed(self) -> None:
        actual = {
            path.name
            for path in WORKFLOW_DIRECTORY.iterdir()
            if path.is_file() and path.suffix in {".yml", ".yaml"}
        }

        self.assertEqual(actual, EXPECTED_WORKFLOWS)
        self.assertFalse(LEGACY_WORKFLOW.exists())

    def test_workflows_have_no_dispatch_secret_or_write_authority(self) -> None:
        actions: set[str] = set()
        for workflow in (CI_WORKFLOW, QUARANTINE_WORKFLOW):
            text = workflow.read_text(encoding="utf-8")
            with self.subTest(workflow=workflow.name):
                self.assertIn("permissions: {}", text)
                for forbidden in FORBIDDEN_WORKFLOW_TEXT:
                    self.assertNotIn(forbidden, text)
                actions.update(re.findall(r"uses:\s*([^\s#]+)", text))

        self.assertEqual(actions, EXPECTED_ACTIONS)
        for action in actions:
            with self.subTest(action=action):
                self.assertRegex(action, r"@[0-9a-f]{40}$")

    def test_quarantine_marker_is_master_push_only_and_executes_no_source(self) -> None:
        text = QUARANTINE_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("  push:\n    branches:\n      - master\n", text)
        self.assertNotIn("uses:", text)
        self.assertNotIn("actions/checkout", text)
        self.assertIn("QUARANTINED:", text)

    def test_ci_checkout_does_not_persist_credentials(self) -> None:
        text = CI_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("contents: read", text)
        self.assertIn("persist-credentials: false", text)


class LegacyWriterRemovalTests(unittest.TestCase):
    """Prove that current source cannot load the retired writer graph."""

    def test_only_the_fail_closed_tombstone_remains(self) -> None:
        actual = {
            path.name
            for path in EVIDENCE_DIRECTORY.iterdir()
            if path.is_file() and path.suffix == ".py"
        }

        self.assertEqual(actual, {"release_evidence_cli.py"})

    def test_every_non_help_invocation_fails_closed(self) -> None:
        cli = load_tombstone()
        invocations = (
            [],
            ["acquire-lease"],
            ["stage-draft-live", "--tag", "v0.74.0"],
            ["--allow-dormant-bootstrap-mutations", "acquire-lease"],
        )

        for arguments in invocations:
            stderr = io.StringIO()
            with (
                self.subTest(arguments=arguments),
                contextlib.redirect_stderr(stderr),
                self.assertRaises(SystemExit) as raised,
            ):
                cli.main(list(arguments))

            self.assertEqual(raised.exception.code, 2)
            self.assertIn("PERMANENTLY QUARANTINED", stderr.getvalue())

    def test_help_is_read_only_and_explains_the_retirement(self) -> None:
        cli = load_tombstone()
        stdout = io.StringIO()

        with (
            contextlib.redirect_stdout(stdout),
            self.assertRaises(SystemExit) as raised,
        ):
            cli.main(["--help"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("Permanent tombstone", stdout.getvalue())
        self.assertIn("implementation has been removed", stdout.getvalue())

    def test_tombstone_has_no_provider_or_process_imports(self) -> None:
        text = CLI_PATH.read_text(encoding="utf-8")

        for forbidden in (
            "import os",
            "import subprocess",
            "import urllib",
            "import http",
            "import requests",
            "import boto",
            "import pathlib",
            "importlib",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)


class BootstrapQuarantineTests(unittest.TestCase):
    """Reject a return of broad App installation authority."""

    def test_app_manifest_is_metadata_read_only(self) -> None:
        manifest = json.loads(APP_MANIFEST.read_text(encoding="utf-8"))

        self.assertEqual(manifest["default_events"], [])
        self.assertFalse(manifest["hook_attributes"]["active"])
        self.assertEqual(manifest["default_permissions"], {"metadata": "read"})

    def test_one_click_app_bootstrap_is_removed(self) -> None:
        self.assertFalse(APP_BOOTSTRAP.exists())

    def test_bootstrap_and_evidence_store_prototypes_are_removed(self) -> None:
        self.assertFalse(EVIDENCE_PROTOTYPE.exists())
        self.assertFalse(SCAFFOLD_STAMP.exists())

    def test_documentation_distinguishes_code_from_provider_quarantine(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        inventory = (ROOT / "docs" / "live-inventory.md").read_text(encoding="utf-8")

        self.assertIn("provides no proof that provider-side authority", readme)
        self.assertIn("UNVERIFIED PROVIDER STATE", inventory)
        self.assertIn("separate RFC and separately reviewed PR", readme)


if __name__ == "__main__":
    unittest.main()
