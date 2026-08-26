"""Produce isolated-install evidence from a verified historical ZIP artifact."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Sequence
from pathlib import Path


class IsolatedInstallFailure(RuntimeError):
    """Raised when the verifier cannot prove an isolated package installation."""


def create_isolated_install_evidence(
    artifact_zip: Path, verified_archives: Sequence[object], transcript_path: Path
) -> dict[str, object]:
    """Install ZIP wheels in a temporary venv and record its transcript."""

    transcript_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dpone-retro-install-") as temporary:
        root = Path(temporary)
        wheels = _extract_verified_wheels(
            artifact_zip, verified_archives, root / "wheels"
        )
        venv = root / "venv"
        commands = (
            (sys.executable, "-m", "venv", str(venv)),
            (
                _venv_executable(venv, "pip"),
                "install",
                "--disable-pip-version-check",
                "--no-input",
                *map(str, wheels),
            ),
            (_venv_executable(venv, "pip"), "check"),
            (_venv_executable(venv, "dpone"), "--help"),
        )
        transcript_parts = []
        failure: str | None = None
        for command in commands:
            output, returncode = _run(command)
            transcript_parts.append(output)
            if returncode:
                failure = f"isolated install command failed with exit code {returncode}"
                break
        transcript = "".join(transcript_parts)

    _write(transcript_path, transcript)
    if failure:
        raise IsolatedInstallFailure(failure)
    if (
        "No broken requirements found." not in transcript
        or "usage: dpone" not in transcript
    ):
        raise IsolatedInstallFailure("isolated install did not complete successfully")
    encoded = transcript.encode()
    return {
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "size": len(encoded),
        "transcript": transcript_path.name,
    }


def _extract_verified_wheels(
    artifact_zip: Path, verified_archives: Sequence[object], destination: Path
) -> tuple[Path, ...]:
    destination.mkdir()
    expected = _expected_wheels(verified_archives)
    with zipfile.ZipFile(artifact_zip) as archive:
        members = {member.filename: member for member in archive.infolist()}
        expected_names = {wheel[0] for wheel in expected}
        if len(members) != len(archive.infolist()) or expected_names - set(members):
            raise IsolatedInstallFailure(
                "artifact wheel inventory changed before install"
            )
        paths = []
        for name, expected_sha256, expected_size in expected:
            destination_path = destination / name
            digest = hashlib.sha256()
            size = 0
            with (
                archive.open(members[name]) as source,
                destination_path.open("wb") as target,
            ):
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
                    size += len(block)
                    target.write(block)
            if digest.hexdigest() != expected_sha256 or size != expected_size:
                raise IsolatedInstallFailure(
                    "artifact wheel bytes changed before install"
                )
            paths.append(destination_path)
    return tuple(paths)


def _expected_wheels(
    verified_archives: Sequence[object],
) -> tuple[tuple[str, str, int], ...]:
    wheels = []
    for archive in verified_archives:
        if not isinstance(archive, dict) or not str(
            archive.get("filename", "")
        ).endswith(".whl"):
            continue
        filename = archive.get("filename")
        sha256 = archive.get("sha256")
        size = archive.get("size")
        if (
            not isinstance(filename, str)
            or "/" in filename
            or not isinstance(sha256, str)
            or len(sha256) != 64
            or not isinstance(size, int)
            or size < 0
        ):
            raise IsolatedInstallFailure("verified wheel inventory is malformed")
        wheels.append((filename, sha256, size))
    if len(wheels) != 4 or len({wheel[0] for wheel in wheels}) != 4:
        raise IsolatedInstallFailure(
            "verified artifact does not contain exactly four wheels"
        )
    return tuple(sorted(wheels))


def _run(command: tuple[str, ...]) -> tuple[str, int]:
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    transcript = "$ " + " ".join(command) + "\n" + result.stdout + result.stderr
    return transcript, result.returncode


def _venv_executable(venv: Path, name: str) -> str:
    directory = "Scripts" if sys.platform == "win32" else "bin"
    suffix = ".exe" if sys.platform == "win32" else ""
    return str(venv / directory / f"{name}{suffix}")


def _write(path: Path, content: str) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)
