"""Tests for bounded execution used by public-authenticity verification."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tools.public_authenticity.process import (
    BoundedProcessError,
    _kill_process_group,
    run_bounded_process,
)


class BoundedProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.environment = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_returns_bounded_stdout_and_stderr(self) -> None:
        result = run_bounded_process(
            (
                sys.executable,
                "-c",
                "import sys;sys.stdout.write('ok');sys.stderr.write('note')",
            ),
            cwd=self.root,
            env=self.environment,
            max_stderr_bytes=16,
            max_stdout_bytes=16,
            timeout_seconds=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"ok")
        self.assertEqual(result.stderr, b"note")

    def test_rejects_output_over_the_cap(self) -> None:
        with self.assertRaisesRegex(BoundedProcessError, "OUTPUT_LIMIT_EXCEEDED"):
            run_bounded_process(
                (sys.executable, "-c", "print('x' * 4096)"),
                cwd=self.root,
                env=self.environment,
                max_stderr_bytes=16,
                max_stdout_bytes=16,
                timeout_seconds=5,
            )

    def test_kills_child_when_selector_registration_fails(self) -> None:
        selector = Mock()
        selector.register.side_effect = OSError("selector unavailable")
        process = Mock(stdout=Mock(), stderr=Mock())
        streams = (process.stdout, process.stderr)
        for descriptor, stream in enumerate(streams, start=10):
            stream.fileno.return_value = descriptor
            stream.closed = False
        with (
            patch(
                "tools.public_authenticity.process.selectors.DefaultSelector",
                return_value=selector,
            ),
            patch(
                "tools.public_authenticity.process.subprocess.Popen",
                return_value=process,
            ),
            patch(
                "tools.public_authenticity.process._kill_process_group"
            ) as kill_group,
        ):
            with self.assertRaisesRegex(BoundedProcessError, "EXECUTION_FAILED"):
                run_bounded_process(
                    (sys.executable, "-c", "pass"),
                    cwd=self.root,
                    env=self.environment,
                    max_stderr_bytes=16,
                    max_stdout_bytes=16,
                    timeout_seconds=5,
                )
        kill_group.assert_called_once_with(process)
        selector.close.assert_called_once_with()
        for stream in streams:
            stream.close.assert_called_once_with()

    def test_kills_a_timed_out_process_group(self) -> None:
        with self.assertRaisesRegex(BoundedProcessError, "TIMEOUT"):
            run_bounded_process(
                (sys.executable, "-c", "import time;time.sleep(5)"),
                cwd=self.root,
                env=self.environment,
                max_stderr_bytes=16,
                max_stdout_bytes=16,
                timeout_seconds=0.05,
            )

    def test_kills_descendants_after_the_group_leader_exits(self) -> None:
        process = Mock(pid=12345)
        process.poll.return_value = 0
        with patch("tools.public_authenticity.process.os.killpg") as kill_group:
            _kill_process_group(process)
        kill_group.assert_called_once_with(12345, 9)
        process.kill.assert_not_called()
        process.wait.assert_not_called()


if __name__ == "__main__":
    unittest.main()
