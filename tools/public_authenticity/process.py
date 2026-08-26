"""Bounded, non-interactive subprocess execution for authenticity adapters."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


class BoundedProcessError(RuntimeError):
    """Stable process-boundary failure without leaking child output."""


@dataclass(frozen=True, slots=True)
class BoundedProcessResult:
    """Bounded child result retained entirely in memory."""

    returncode: int
    stdout: bytes
    stderr: bytes


def run_bounded_process(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    max_stderr_bytes: int,
    max_stdout_bytes: int,
    timeout_seconds: float,
) -> BoundedProcessResult:
    """Run one absolute command with bounded output, time and inherited state."""
    try:
        selector = selectors.DefaultSelector()
    except OSError as error:
        raise BoundedProcessError("EXECUTION_FAILED") from error
    try:
        process = subprocess.Popen(
            tuple(command),
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        selector.close()
        raise BoundedProcessError("EXECUTION_FAILED") from error
    assert process.stdout is not None
    assert process.stderr is not None
    streams = {
        process.stdout: (bytearray(), max_stdout_bytes),
        process.stderr: (bytearray(), max_stderr_bytes),
    }
    deadline = time.monotonic() + timeout_seconds
    try:
        for stream in streams:
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BoundedProcessError("TIMEOUT")
            events = selector.select(remaining)
            if not events:
                raise BoundedProcessError("TIMEOUT")
            for key, _mask in events:
                stream = key.fileobj
                chunk = os.read(stream.fileno(), 65_536)
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                output, maximum = streams[stream]
                output.extend(chunk)
                if len(output) > maximum:
                    raise BoundedProcessError("OUTPUT_LIMIT_EXCEEDED")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BoundedProcessError("TIMEOUT")
        returncode = process.wait(timeout=remaining)
    except BoundedProcessError:
        _kill_process_group(process)
        raise
    except subprocess.TimeoutExpired as error:  # pragma: no cover
        _kill_process_group(process)
        raise BoundedProcessError("TIMEOUT") from error
    except (KeyError, OSError, ValueError) as error:  # pragma: no cover
        _kill_process_group(process)
        raise BoundedProcessError("EXECUTION_FAILED") from error
    finally:
        selector.close()
        for stream in streams:
            if not stream.closed:
                stream.close()
    return BoundedProcessResult(
        returncode=returncode,
        stdout=bytes(streams[process.stdout][0]),
        stderr=bytes(streams[process.stderr][0]),
    )


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        if process.poll() is None:
            process.kill()
    if process.poll() is None:
        process.wait()
