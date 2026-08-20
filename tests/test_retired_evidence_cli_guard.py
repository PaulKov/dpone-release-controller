"""Fail-closed tests for the permanently quarantined legacy CLI."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

CLI_PATH = (
    Path(__file__).resolve().parents[1] / "tools/evidence/release_evidence_cli.py"
)


def _load_cli_module() -> object:
    spec = importlib.util.spec_from_file_location("retired_release_cli", CLI_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {CLI_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RetiredEvidenceCliGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cli = _load_cli_module()

    def test_every_invocation_stops_before_runtime_load(self) -> None:
        runtime_loader = Mock()
        for arguments in (
            [],
            ["acquire-lease"],
            ["--allow-dormant-bootstrap-mutations"],
        ):
            with (
                self.subTest(arguments=arguments),
                patch.object(self.cli, "_load_runtime_modules", runtime_loader),
                contextlib.redirect_stderr(io.StringIO()) as stderr,
                self.assertRaises(SystemExit) as raised,
            ):
                self.cli.main(arguments)
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("PERMANENTLY QUARANTINED", stderr.getvalue())
        runtime_loader.assert_not_called()

    def test_help_is_read_only_and_explains_broker_replacement(self) -> None:
        stdout = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            self.assertRaises(SystemExit) as raised,
        ):
            self.cli.main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("PERMANENTLY QUARANTINED", stdout.getvalue())
        self.assertIn("broker v2", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
