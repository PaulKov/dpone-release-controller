"""Security invariants for the emergency controller quarantine."""

from __future__ import annotations

import ast
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
        "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
        "astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78",
    }
)
RETIRED_PROVIDER_MODULES = frozenset(
    {
        "release_attest_draft.py",
        "release_authorize.py",
        "release_draft_inventory.py",
        "release_evidence_cli_observe.py",
        "release_evidence_cli_support.py",
        "release_evidence_store_b2.py",
        "release_github_api.py",
        "release_governance_snapshot.py",
        "release_immutable_inventory.py",
        "release_lease_service.py",
        "release_public_bundle.py",
        "release_pypi_inventory.py",
        "release_receipt_envelope.py",
        "release_stage_draft.py",
        "release_stream_service.py",
        "release_trusted_publisher_inventory.py",
    }
)
FORBIDDEN_PROVIDER_IMPORTS = frozenset(
    {
        "boto3",
        "http.client",
        "requests",
        "socket",
        "subprocess",
        "urllib.error",
        "urllib.request",
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
EXPECTED_EMERGENCY_QUARANTINE_JOB = """  emergency-quarantine:
    name: Validate emergency quarantine
    if: ${{ always() }}
    needs:
      - contract
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - name: Require the complete quarantine contract matrix
        env:
          CONTRACT_RESULT: ${{ needs.contract.result }}
        run: |
          set -euo pipefail
          test "${CONTRACT_RESULT}" = "success"
"""


def exact_workflow_job(text: str, job_id: str) -> str:
    """Return one top-level job block, rejecting plain or quoted duplicate IDs."""

    lines = text.splitlines(keepends=True)
    escaped_job_id = re.escape(job_id)
    job_id_declaration = re.compile(
        rf"^  (?:{escaped_job_id}|'(?:{escaped_job_id})'|\"(?:{escaped_job_id})\")"
        r"\s*:[^\n]*(?:\n)?$"
    )
    starts = [
        index for index, line in enumerate(lines) if job_id_declaration.fullmatch(line)
    ]
    if len(starts) != 1:
        raise AssertionError(
            f"expected exactly one active {job_id!r} job, found {len(starts)}"
        )

    start = starts[0]
    end = len(lines)
    top_level_job = re.compile(
        r"^  (?:[A-Za-z0-9_-]+|'[A-Za-z0-9_-]+'|\"[A-Za-z0-9_-]+\")"
        r"\s*:[^\n]*(?:\n)?$"
    )
    for index in range(start + 1, len(lines)):
        if top_level_job.fullmatch(lines[index]):
            end = index
            break
    return "".join(lines[start:end])


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

    def test_required_quarantine_check_is_one_exact_active_job(self) -> None:
        """Prevent comments, duplicate job IDs, skips, or partial needs from spoofing it."""

        text = CI_WORKFLOW.read_text(encoding="utf-8")

        self.assertEqual(
            exact_workflow_job(text, "emergency-quarantine"),
            EXPECTED_EMERGENCY_QUARANTINE_JOB,
        )
        self.assertEqual(
            text.splitlines().count("    name: Validate emergency quarantine"),
            1,
        )

    def test_required_check_extractor_rejects_comments_and_duplicate_job_ids(
        self,
    ) -> None:
        """Ignore comments and reject common active aliases of the protected job ID."""

        commented = EXPECTED_EMERGENCY_QUARANTINE_JOB.replace(
            "  emergency-quarantine:\n",
            "  # emergency-quarantine:\n",
            1,
        )
        with self.assertRaisesRegex(AssertionError, "found 0"):
            exact_workflow_job(commented, "emergency-quarantine")

        duplicate_declarations = (
            "  emergency-quarantine: # duplicate\n",
            "  emergency-quarantine:   \n",
            "  'emergency-quarantine': {}\n",
            '  "emergency-quarantine" : {}\n',
        )
        for declaration in duplicate_declarations:
            with (
                self.subTest(declaration=declaration.rstrip()),
                self.assertRaisesRegex(AssertionError, "found 2"),
            ):
                exact_workflow_job(
                    EXPECTED_EMERGENCY_QUARANTINE_JOB + declaration,
                    "emergency-quarantine",
                )


class LegacyWriterRemovalTests(unittest.TestCase):
    """Prove that current source cannot load the retired writer graph."""

    def test_retired_provider_graph_stays_removed(self) -> None:
        actual = {
            path.name
            for path in EVIDENCE_DIRECTORY.iterdir()
            if path.is_file() and path.suffix == ".py"
        }

        self.assertIn("release_evidence_cli.py", actual)
        self.assertTrue(RETIRED_PROVIDER_MODULES.isdisjoint(actual))

    def test_dormant_model_has_no_provider_or_process_imports(self) -> None:
        violations: list[str] = []
        for path in sorted(EVIDENCE_DIRECTORY.glob("release_*.py")):
            if path == CLI_PATH:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                imported: set[str] = set()
                if isinstance(node, ast.Import):
                    imported.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module is not None:
                    imported.add(node.module)
                    imported.update(
                        f"{node.module}.{alias.name}" for alias in node.names
                    )
                for name in imported:
                    if any(
                        name == forbidden or name.startswith(f"{forbidden}.")
                        for forbidden in FORBIDDEN_PROVIDER_IMPORTS
                    ):
                        violations.append(f"{path.name}:{node.lineno}:{name}")
        self.assertEqual(violations, [])

    def test_dormant_model_dependency_graph_is_closed_and_acyclic(self) -> None:
        modules = {
            path.stem: path
            for path in EVIDENCE_DIRECTORY.glob("release_*.py")
            if path != CLI_PATH
        }
        dependencies: dict[str, set[str]] = {name: set() for name in modules}
        missing: list[str] = []
        for name, path in modules.items():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                imported: tuple[str, ...] = ()
                if isinstance(node, ast.Import):
                    imported = tuple(
                        alias.name.rsplit(".", 1)[-1]
                        for alias in node.names
                        if alias.name.startswith("tools.evidence.release_")
                    )
                elif isinstance(node, ast.ImportFrom):
                    if node.module == "tools.evidence":
                        imported = tuple(
                            alias.name
                            for alias in node.names
                            if alias.name.startswith("release_")
                        )
                    elif node.module and node.module.startswith(
                        "tools.evidence.release_"
                    ):
                        imported = (node.module.rsplit(".", 1)[-1],)
                for dependency in imported:
                    if dependency == "release_evidence_cli":
                        missing.append(f"{name}->{dependency}")
                    elif dependency.startswith("release_"):
                        if dependency not in modules:
                            missing.append(f"{name}->{dependency}")
                        else:
                            dependencies[name].add(dependency)
        self.assertEqual(missing, [])

        temporary: set[str] = set()
        complete: set[str] = set()

        def visit(name: str) -> None:
            if name in complete:
                return
            if name in temporary:
                self.fail(f"cyclic dormant-model dependency at {name}")
            temporary.add(name)
            for dependency in sorted(dependencies[name]):
                visit(dependency)
            temporary.remove(name)
            complete.add(name)

        for name in sorted(modules):
            visit(name)

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
