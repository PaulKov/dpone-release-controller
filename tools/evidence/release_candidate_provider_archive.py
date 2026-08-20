"""Safe extraction of one already-digest-verified provider artifact ZIP."""

from __future__ import annotations

import os
import stat
import zipfile
from pathlib import Path
from typing import Any

from tools.evidence import release_candidate_contract as contract

MAX_EXPANDED_BYTES = 805_306_368
MAX_ZIP_ENTRIES = 256
EXPECTED_FILE_COUNT = contract.EXPECTED_PROVIDER_FILE_COUNT


def validate_and_extract(raw_zip: Any, destination: Path) -> tuple[int, int]:
    """Validate the closed ZIP inventory and extract regular files only."""

    try:
        with zipfile.ZipFile(raw_zip, "r") as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                raise contract.CandidateHandoffError(
                    "provider ZIP has too many entries"
                )
            names: set[str] = set()
            members: list[tuple[zipfile.ZipInfo, str]] = []
            expanded = 0
            for info in infos:
                relative = contract.require_safe_path(
                    info.filename.rstrip("/"), "provider ZIP member"
                )
                if relative in names:
                    raise contract.CandidateHandoffError(
                        "provider ZIP contains duplicate names"
                    )
                names.add(relative)
                if info.flag_bits & 0x1:
                    raise contract.CandidateHandoffError(
                        "encrypted provider ZIP members are forbidden"
                    )
                mode = (info.external_attr >> 16) & 0xFFFF
                is_directory = info.is_dir()
                expected_types = (
                    {0, stat.S_IFDIR} if is_directory else {0, stat.S_IFREG}
                )
                if mode and stat.S_IFMT(mode) not in expected_types:
                    raise contract.CandidateHandoffError(
                        "non-regular provider ZIP member is forbidden"
                    )
                if is_directory:
                    continue
                if info.file_size <= 0 or info.file_size > contract.MAX_FILE_BYTES:
                    raise contract.CandidateHandoffError(
                        "provider ZIP member size is outside bounds"
                    )
                expanded += info.file_size
                if expanded > MAX_EXPANDED_BYTES:
                    raise contract.CandidateHandoffError(
                        "provider ZIP expanded size exceeds limit"
                    )
                members.append((info, relative))
            if len(members) != EXPECTED_FILE_COUNT:
                raise contract.CandidateHandoffError(
                    "provider ZIP must contain exactly 25 files"
                )
            for info, relative in members:
                _extract_regular(archive, info, destination, relative)
            return len(members), expanded
    except contract.CandidateHandoffError:
        raise
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        raise contract.CandidateHandoffError(
            f"invalid provider artifact ZIP: {exc}"
        ) from exc


def _extract_regular(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    destination: Path,
    relative: str,
) -> None:
    target = destination.joinpath(*Path(relative).parts)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(target, flags, 0o600)
    observed = 0
    try:
        with archive.open(info, "r") as source:
            while chunk := source.read(1024 * 1024):
                observed += len(chunk)
                if observed > info.file_size:
                    raise contract.CandidateHandoffError(
                        "provider ZIP member expanded beyond declaration"
                    )
                view = memoryview(chunk)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise contract.CandidateHandoffError(
                            "provider ZIP extraction made no progress"
                        )
                    view = view[written:]
        if observed != info.file_size:
            raise contract.CandidateHandoffError("provider ZIP member size mismatch")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
