"""Structural security contract for the OIDC-only PyPI publisher."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


WORKFLOW = (
    Path(__file__).resolve().parents[1] / ".github" / "workflows" / "pypi-release.yml"
)
PUBLISHER_CONTRACT = (
    Path(__file__).resolve().parents[1] / "config" / "oidc-pypi-publisher.json"
)


class PyPIReleaseWorkflowTests(unittest.TestCase):
    """Ensure the publisher stays tag-bound, artifact-only, and tokenless."""

    def test_publisher_contract_is_exact(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")

        required = (
            "workflow_dispatch:",
            "ref: refs/tags/v${{ inputs.version }}",
            "repository: PaulKov/dpone",
            "environment: pypi",
            "id-token: write",
            "pypa/gh-action-pypi-publish@cef221092ed1bacb1cc03d23a2d87d1d172e277b",
            "packages-dir: dist/",
            "packages/apache-airflow-providers-dpone",
            "apache_airflow_providers_dpone",
            "persist-credentials: false",
            "skip-existing",
        )
        for fragment in required[:-1]:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)
        self.assertNotIn(required[-1], text)

    def test_only_publish_job_can_mint_an_oidc_token(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")

        self.assertEqual(text.count("id-token: write"), 1)
        publish = text.split("  publish:\n", maxsplit=1)[1]
        self.assertIn("id-token: write", publish)
        self.assertNotIn("actions/checkout", publish)
        self.assertNotIn("secrets.", text)
        self.assertNotIn("PYPI_TOKEN", text)

    def test_public_verification_is_artifact_bound_and_tokenless(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")

        verification = text.split("  verify-published:\n", maxsplit=1)[1]
        self.assertIn("- publish", verification)
        self.assertIn("permissions: {}", verification)
        self.assertIn(
            "dpone-pypi-manifest-${{ needs.build.outputs.version }}", verification
        )
        self.assertIn("https://pypi.org/pypi/{project}/{version}/json", verification)
        self.assertIn('item["digests"]["sha256"]', verification)
        self.assertIn("for attempt in range(1, 11)", verification)
        self.assertNotIn("id-token: write", verification)
        self.assertNotIn("actions/checkout", verification)

    def test_checked_in_publisher_contract_matches_the_live_workflow(self) -> None:
        contract = json.loads(PUBLISHER_CONTRACT.read_text(encoding="utf-8"))

        self.assertEqual(contract["schema"], "dpone.oidc-pypi-publisher.v1")
        self.assertEqual(contract["state"], "active")
        self.assertEqual(
            contract["workflow_path"], ".github/workflows/pypi-release.yml"
        )
        self.assertEqual(contract["environment"], "pypi")
        self.assertEqual(contract["target_repository"], "PaulKov/dpone")
        self.assertEqual(
            contract["projects"],
            [
                "dpone",
                "dpone-native-accel",
                "dpone-airflow-pack",
                "apache-airflow-providers-dpone",
            ],
        )


if __name__ == "__main__":
    unittest.main()
