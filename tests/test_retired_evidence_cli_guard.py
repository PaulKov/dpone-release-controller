"""Fail-closed tests for the retired evidence mutation CLI entry point."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
CLI_PATH = ROOT / "tools" / "evidence" / "release_evidence_cli.py"


def _load_cli_module() -> object:
    """Load only the guarded entry point, without its dormant runtime graph."""

    spec = importlib.util.spec_from_file_location(
        "dpone_test_retired_evidence_cli",
        CLI_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {CLI_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RetiredEvidenceCliGuardTests(unittest.TestCase):
    """Prove accidental invocations stop before legacy mutation code loads."""

    def setUp(self) -> None:
        self.cli = _load_cli_module()

    def test_missing_acknowledgement_stops_before_runtime_load(self) -> None:
        runtime_loader = Mock()
        stderr = io.StringIO()

        with (
            patch.object(self.cli, "_load_runtime_modules", runtime_loader),
            contextlib.redirect_stderr(stderr),
            self.assertRaises(SystemExit) as raised,
        ):
            self.cli.main(self._acquire_arguments())

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("DORMANT / NOT AN OPERATOR INTERFACE", stderr.getvalue())
        self.assertIn(
            "--allow-dormant-bootstrap-mutations is required",
            stderr.getvalue(),
        )
        runtime_loader.assert_not_called()

    def test_help_is_non_mutating_and_explains_status(self) -> None:
        runtime_loader = Mock()
        stdout = io.StringIO()

        with (
            patch.object(self.cli, "_load_runtime_modules", runtime_loader),
            contextlib.redirect_stdout(stdout),
            self.assertRaises(SystemExit) as raised,
        ):
            self.cli.main(["--help"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("DORMANT / NOT AN OPERATOR INTERFACE", stdout.getvalue())
        self.assertIn("--allow-dormant-bootstrap-mutations", stdout.getvalue())
        runtime_loader.assert_not_called()

    def test_explicit_acknowledgement_preserves_existing_dispatch(self) -> None:
        store = object()
        release_ids = object()
        producer = object()
        runner = Mock(return_value=17)
        support = self._support_runtime(store, release_ids, producer, runner)
        observe = self._observe_runtime()
        runtime_loader = Mock(return_value=(support, observe))

        with patch.object(self.cli, "_load_runtime_modules", runtime_loader):
            result = self.cli.main(
                [
                    "--allow-dormant-bootstrap-mutations",
                    *self._acquire_arguments(),
                    "--dry-memory",
                ]
            )

        self.assertEqual(result, 17)
        runtime_loader.assert_called_once_with()
        support.build_store.assert_called_once()
        support.release_ids.assert_called_once()
        support.producer.assert_called_once_with(default_job="admit-and-lease")
        runner.assert_called_once()
        args = runner.call_args.args[2]
        self.assertTrue(args.allow_dormant_bootstrap_mutations)
        self.assertTrue(args.dry_memory)

    @staticmethod
    def _acquire_arguments() -> list[str]:
        return [
            "acquire-lease",
            "--tag",
            "v0.74.0",
            "--repository-id",
            "1255975556",
        ]

    @staticmethod
    def _support_runtime(
        store: object,
        release_ids: object,
        producer: object,
        acquire_runner: Mock,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            build_store=Mock(return_value=store),
            release_ids=Mock(return_value=release_ids),
            producer=Mock(return_value=producer),
            run_acquire_lease=acquire_runner,
            run_capture_snapshot_a=Mock(),
            run_attest_draft_dry_run=Mock(),
            run_stage_draft_live=Mock(),
            run_authorize_publication=Mock(),
            run_release_lease=Mock(),
        )

    @staticmethod
    def _observe_runtime() -> SimpleNamespace:
        return SimpleNamespace(
            run_pypi_inventory_observe=Mock(),
            run_immutable_inventory_observe=Mock(),
            run_trusted_publisher_inventory_observe=Mock(),
            run_draft_inventory_observe=Mock(),
        )


if __name__ == "__main__":
    unittest.main()
