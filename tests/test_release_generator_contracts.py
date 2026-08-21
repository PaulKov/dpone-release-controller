"""Fail-closed CLI, inventory, and atomic-write tests for contract producers."""

from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import canonicalize_release_receipt_schema as receipt_schema_canonicalizer
from scripts import generate_release_controller_action_contract as action_generator
from scripts import generate_release_controller_vectors as vector_generator
from scripts import generate_release_controller_wire_contracts as wire_generator
from scripts import release_generator_support as support
from tools.evidence import release_receipt_schema_registry
from tools.evidence import release_receipt_vectors as receipt_vector_generator

ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github/workflows/ci.yml"

GENERATORS = (
    action_generator.main,
    vector_generator.main,
    wire_generator.main,
    receipt_vector_generator.main,
)

CANONICALIZERS = (receipt_schema_canonicalizer.main,)


class ReleaseGeneratorCliTests(unittest.TestCase):
    def test_ci_keeps_generators_and_schema_canonicalizer_in_drift_gate(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("for producer in scripts/generate_*.py", workflow)
        self.assertIn(
            "python -B scripts/canonicalize_release_receipt_schema.py --check",
            workflow,
        )
        self.assertNotIn("generate_release_receipt_schema.py", workflow)

    def test_every_mutating_generator_requires_one_explicit_mode(self) -> None:
        for main in GENERATORS:
            with (
                self.subTest(generator=main.__module__, arguments=()),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                main([])
            self.assertEqual(raised.exception.code, 2)

            with (
                self.subTest(
                    generator=main.__module__,
                    arguments=("--check", "--write"),
                ),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                main(["--check", "--write"])
            self.assertEqual(raised.exception.code, 2)

    def test_every_canonicalizer_requires_one_explicit_mode(self) -> None:
        for main in CANONICALIZERS:
            with (
                self.subTest(canonicalizer=main.__module__, arguments=()),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                main([])
            self.assertEqual(raised.exception.code, 2)

            with (
                self.subTest(
                    canonicalizer=main.__module__,
                    arguments=("--check", "--write"),
                ),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                main(["--check", "--write"])
            self.assertEqual(raised.exception.code, 2)

    def test_wire_check_rejects_an_exact_root_extra(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = root / "expected.json"
            expected.write_bytes(b"expected\n")
            extra = root / "orphan.json"
            extra.write_bytes(b"orphan\n")
            with (
                patch.object(
                    wire_generator,
                    "generated_files",
                    return_value={expected: b"expected\n"},
                ),
                patch.object(
                    wire_generator,
                    "managed_roots",
                    return_value=(support.ManagedRoot(root),),
                ),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(wire_generator.generate(check=True), 1)

    def test_receipt_vector_check_rejects_a_namespace_extra(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = root / "release-receipt-v2-golden.json"
            expected.write_bytes(b"expected\n")
            extra = root / "release-receipt-retired-golden.json"
            extra.write_bytes(b"retired\n")
            with (
                patch.object(
                    receipt_vector_generator,
                    "generated_files",
                    return_value={expected: b"expected\n"},
                ),
                patch.object(
                    receipt_vector_generator,
                    "managed_roots",
                    return_value=(
                        support.ManagedRoot(
                            root,
                            receipt_vector_generator.MANAGED_PATTERNS,
                        ),
                    ),
                ),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(receipt_vector_generator.generate(check=True), 1)


class ReleaseGeneratorInventoryTests(unittest.TestCase):
    def test_receipt_schema_canonicalizer_rewrites_only_valid_source(self) -> None:
        document = release_receipt_schema_registry.document()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = release_receipt_schema_registry.SOURCE.relative_to(
                release_receipt_schema_registry.REPOSITORY_ROOT
            )
            output = root / relative
            output.parent.mkdir(parents=True)
            output.write_text(
                json.dumps(document, separators=(",", ":")),
                encoding="utf-8",
            )

            with (
                patch.object(release_receipt_schema_registry, "SOURCE", output),
                patch.object(
                    release_receipt_schema_registry,
                    "REPOSITORY_ROOT",
                    root,
                ),
                patch.object(receipt_schema_canonicalizer, "OUTPUT", output),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(receipt_schema_canonicalizer.reconcile(check=True), 1)
                self.assertEqual(receipt_schema_canonicalizer.reconcile(check=False), 0)
                self.assertEqual(
                    output.read_bytes(),
                    release_receipt_schema_registry.schema_bytes(),
                )

    def test_shared_root_ignores_other_namespaces_but_rejects_owned_extra(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = root / "release-controller-action-bundle-v1.schema.json"
            expected.write_bytes(b"expected\n")
            unrelated = root / "release-receipt-envelope-v2.schema.json"
            unrelated.write_bytes(b"unrelated\n")
            owned_extra = root / "release-controller-action-bundle-v0.schema.json"
            owned_extra.write_bytes(b"retired\n")

            drift = support.inventory_drift(
                (expected,),
                (
                    support.ManagedRoot(
                        root,
                        ("release-controller-action-bundle-*.schema.json",),
                    ),
                ),
            )
            self.assertEqual(drift.missing, ())
            self.assertEqual(drift.extra, (owned_extra,))

    def test_write_refuses_extras_without_changing_or_deleting_any_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = root / "expected.json"
            expected.write_bytes(b"old\n")
            extra = root / "orphan.json"
            extra.write_bytes(b"orphan\n")

            with redirect_stderr(io.StringIO()):
                result = support.reconcile_generated_files(
                    {expected: b"new\n"},
                    (support.ManagedRoot(root),),
                    check=False,
                    label="test inventory",
                )

            self.assertEqual(result, 1)
            self.assertEqual(expected.read_bytes(), b"old\n")
            self.assertEqual(extra.read_bytes(), b"orphan\n")


class ReleaseGeneratorAtomicWriteTests(unittest.TestCase):
    def test_atomic_write_replaces_bytes_and_leaves_no_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "generated.json"
            path.write_bytes(b"old\n")

            support.atomic_write(path, b"new\n")

            self.assertEqual(path.read_bytes(), b"new\n")
            self.assertEqual(tuple(path.parent.glob(f".{path.name}.*")), ())

    def test_replace_failure_preserves_old_bytes_and_cleans_temporary_file(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "generated.json"
            path.write_bytes(b"old\n")

            with (
                patch.object(support.os, "replace", side_effect=OSError("blocked")),
                self.assertRaisesRegex(OSError, "blocked"),
            ):
                support.atomic_write(path, b"new\n")

            self.assertEqual(path.read_bytes(), b"old\n")
            self.assertEqual(tuple(path.parent.glob(f".{path.name}.*")), ())


if __name__ == "__main__":
    unittest.main()
