"""Fail-closed tests for the unfrozen public closure projection."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import generate_release_closure_contracts as closure_generator
from scripts.generate_release_closure_contracts import (
    FORBIDDEN_OUTPUTS,
    FORBIDDEN_SCHEMA_IDS,
    check_quarantine,
    generated_files,
)
from tools.evidence import release_closed_marker
from tools.evidence import release_closure_archive
from tools.evidence import release_closure_bundle
from tools.evidence import release_closure_documents
from tools.evidence import release_closure_inventory
from tools.evidence import release_closure_types
from tools.evidence import release_controller_operations
from tools.evidence import release_controller_routes
from tools.evidence import release_public_closure_hold as hold

ROOT = Path(__file__).resolve().parents[1]
HOLD_MODULES = (
    "release_closed_marker.py",
    "release_closure_archive.py",
    "release_closure_bundle.py",
    "release_closure_documents.py",
    "release_closure_inventory.py",
    "release_closure_types.py",
    "release_runtime_closure.py",
    "release_runtime_closure_authority.py",
    "release_runtime_closure_contract.py",
    "release_runtime_closure_observation.py",
    "release_runtime_closure_provider.py",
)
PUBLIC_BOUNDARY_MODULES = tuple(
    sorted(
        {
            *HOLD_MODULES,
            "release_controller_schema_registry.py",
            *(
                path.name
                for pattern in (
                    "release_controller_activation*.py",
                    "release_controller_wire*.py",
                )
                for path in (ROOT / "tools/evidence").glob(pattern)
            ),
        }
    )
)
FORBIDDEN_IMPORT_PREFIXES = (
    "tools.evidence.release_private_",
    "tools.evidence.release_receipt_",
)
PRIVATE_CANARIES = (
    "cloudflare_account_id",
    "installation_id",
    "oidc_jti_sha256",
    "provider_job_observation_sha256",
)


class PublicClosureHoldTests(unittest.TestCase):
    def test_config_is_an_exact_non_overridable_hold(self) -> None:
        raw = json.loads((ROOT / "config/release-controller-v2.json").read_bytes())
        self.assertEqual(
            raw["closure_projection"],
            {
                "status": hold.STATUS,
                "reason_code": hold.REASON_CODE,
                "public_projection_enabled": False,
                "runtime_gate_enabled": False,
            },
        )
        self.assertEqual(hold.contract().status, "HOLD")
        self.assertFalse(hold.contract().public_projection_enabled)

    def test_every_legacy_public_entrypoint_fails_before_reading_input(self) -> None:
        calls = (
            release_closed_marker.build,
            release_closed_marker.verify,
            release_closed_marker.decode_summary,
            release_closure_archive.build,
            release_closure_archive.verify,
            release_closure_bundle.build,
            release_closure_bundle.verify,
            release_closure_bundle.verify_zip,
            release_closure_bundle.zip_bytes,
            release_closure_documents.build,
            release_closure_documents.verify,
            release_closure_inventory.digest,
            release_closure_inventory.validate,
        )
        canary = {
            name: f"SECRET-{index}" for index, name in enumerate(PRIVATE_CANARIES)
        }
        for call in calls:
            with (
                self.subTest(call=call),
                self.assertRaisesRegex(
                    hold.PublicClosureContractHoldError,
                    hold.REASON_CODE,
                ),
            ):
                call(canary)

    def test_public_modules_never_import_private_or_receipt_contracts(self) -> None:
        source_root = ROOT / "tools/evidence"
        for name in PUBLIC_BOUNDARY_MODULES:
            path = source_root / name
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            imports = _imports(tree)
            with self.subTest(module=name):
                self.assertFalse(
                    tuple(
                        imported
                        for imported in imports
                        if imported.startswith(FORBIDDEN_IMPORT_PREFIXES)
                    )
                )

    def test_public_sources_contain_no_private_provider_canary_fields(self) -> None:
        source_root = ROOT / "tools/evidence"
        combined = "\n".join(
            (source_root / name).read_text(encoding="utf-8") for name in HOLD_MODULES
        )
        for canary in PRIVATE_CANARIES:
            with self.subTest(canary=canary):
                self.assertNotIn(canary, combined)

    def test_no_public_closure_operation_or_route_is_registered(self) -> None:
        held_operations = {
            "closed-check-intent",
            "closed-check-project",
            "closed-check-verify",
            "closure-artifact-upload",
            "closure-artifact-verify",
            "runtime-closure",
        }
        self.assertTrue(
            held_operations.isdisjoint(release_controller_operations.OPERATION_BY_ID)
        )
        self.assertTrue(
            release_controller_routes.HELD_PUBLIC_CLOSURE_SELECTORS.isdisjoint(
                release_controller_routes.ROUTE_BY_SELECTOR
            )
        )

    def test_legacy_generated_public_artifacts_are_absent(self) -> None:
        self.assertEqual(generated_files(), {})
        self.assertEqual(check_quarantine(), ())
        self.assertTrue(FORBIDDEN_OUTPUTS)
        for relative in FORBIDDEN_OUTPUTS:
            with self.subTest(path=relative):
                self.assertFalse((ROOT / relative).exists())

    def test_retired_release_evidence_schema_path_and_id_are_quarantined(self) -> None:
        retired_path = Path("docs/schemas/release/release-evidence-v2.schema.json")
        retired_id = (
            "https://paulkov.github.io/dpone-release-controller/schemas/release/"
            "release-evidence-v2.schema.json"
        )
        self.assertIn(retired_path, FORBIDDEN_OUTPUTS)
        self.assertEqual(FORBIDDEN_SCHEMA_IDS, (retired_id,))

        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            alias = temporary_root / "docs/schemas/alias.json"
            alias.parent.mkdir(parents=True)
            alias.write_text(json.dumps({"$id": retired_id}), encoding="utf-8")
            with patch.object(closure_generator, "ROOT", temporary_root):
                self.assertEqual(
                    check_quarantine(),
                    (Path("docs/schemas/alias.json"),),
                )

    def test_public_type_aliases_are_hold_only(self) -> None:
        self.assertIs(
            release_closure_types.ClosureBundleError,
            hold.PublicClosureContractHoldError,
        )
        self.assertIs(release_closure_types.ClosureExpectation, hold.PublicClosureHold)


def _imports(tree: ast.AST) -> tuple[str, ...]:
    result: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            result.extend(f"{node.module}.{alias.name}" for alias in node.names)
    return tuple(result)


if __name__ == "__main__":
    unittest.main()
