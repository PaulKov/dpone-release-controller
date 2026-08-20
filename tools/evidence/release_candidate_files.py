"""No-follow extracted-tree and package archive verification."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Callable

from tools.evidence import release_candidate_archive_metadata as archive_metadata
from tools.evidence import release_candidate_contract as contract

MAX_ARCHIVE_ENTRIES = archive_metadata.MAX_ARCHIVE_ENTRIES
MAX_ARCHIVE_EXPANDED_BYTES = archive_metadata.MAX_ARCHIVE_EXPANDED_BYTES
MAX_METADATA_BYTES = archive_metadata.MAX_METADATA_BYTES


def require_root(root: Path) -> Path:
    """Require a present non-symlink directory without resolving it."""

    root = root.absolute()
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise contract.CandidateHandoffError(
            f"candidate root is not readable: {exc}"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise contract.CandidateHandoffError(
            "candidate root must be a non-symlink directory"
        )
    descriptor = open_directory_no_follow(root)
    os.close(descriptor)
    return root


def open_directory_no_follow(path: Path) -> int:
    """Open one trusted directory path without following its final component.

    The caller owns the directory's ancestry.  This deliberately does not walk
    from ``/``: on macOS the system-provided ``/var`` alias is a symlink to
    ``/private/var``.  Walking every component would reject secure temporary
    directories created by the operating system.  The final path identity is
    still checked with ``lstat``/``open(O_NOFOLLOW)``/``fstat``.
    """

    absolute = path.absolute()
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        before = absolute.lstat()
        descriptor = os.open(absolute, flags)
    except OSError as exc:
        raise contract.CandidateHandoffError(
            f"directory cannot be opened without following a link: {absolute}: {exc}"
        ) from exc
    try:
        after = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or not stat.S_ISDIR(after.st_mode)
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
        ):
            raise contract.CandidateHandoffError(
                f"directory identity changed while opening: {absolute}"
            )
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def enumerate_closed_members(root: Path) -> set[str]:
    """Return regular member paths and reject links, FIFOs and device nodes."""

    observed: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise contract.CandidateHandoffError(
                f"cannot inspect member {relative}: {exc}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise contract.CandidateHandoffError(
                f"symbolic links are forbidden: {relative}"
            )
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise contract.CandidateHandoffError(
                f"non-regular member is forbidden: {relative}"
            )
        observed.add(relative)
        if len(observed) > contract.MAX_MEMBER_COUNT:
            raise contract.CandidateHandoffError(
                "candidate artifact exceeds member count limit"
            )
    return observed


def read_regular(root: Path, relative: str) -> tuple[bytes, str]:
    """Read one bounded regular file with openat/no-follow semantics."""

    data = bytearray()
    size, digest = _stream_regular(root, relative, collector=data.extend)
    if len(data) != size:
        raise contract.CandidateHandoffError(
            f"file changed while collecting: {relative}"
        )
    return bytes(data), digest


def hash_regular(root: Path, relative: str) -> tuple[int, str]:
    """Hash one bounded regular file without retaining its bytes."""

    return _stream_regular(root, relative, collector=None)


def require_file_match(record: contract.FileRecord, size: int, digest: str) -> None:
    """Match one observed regular file to its manifest record."""

    if record.size_bytes != size:
        raise contract.CandidateHandoffError(
            f"member size mismatch for {record.path}: expected={record.size_bytes} actual={size}"
        )
    if record.sha256 != digest:
        raise contract.CandidateHandoffError(
            f"member digest mismatch for {record.path}"
        )


def verify_archive_metadata(
    data: bytes,
    distribution: contract.DistributionRecord,
    release: str,
) -> None:
    """Require package metadata to repeat the exact inventory Name/Version."""

    archive_metadata.verify(data, distribution, release)


def _stream_regular(
    root: Path,
    relative: str,
    *,
    collector: Callable[[bytes], None] | None,
) -> tuple[int, str]:
    relative = contract.require_safe_path(relative, "member path")
    path = root.joinpath(*PurePosixPath(relative).parts)
    try:
        before_open = path.lstat()
    except OSError as exc:
        raise contract.CandidateHandoffError(
            f"cannot lstat regular member {relative}: {exc}"
        ) from exc
    if not stat.S_ISREG(before_open.st_mode) or stat.S_ISLNK(before_open.st_mode):
        raise contract.CandidateHandoffError(
            f"required regular file is invalid: {relative}"
        )
    descriptor = _open_beneath(root, relative)
    try:
        before = os.fstat(descriptor)
        _require_stable_identity(before_open, before, relative)
        if before.st_size <= 0 or before.st_size > contract.MAX_FILE_BYTES:
            raise contract.CandidateHandoffError(
                f"file size outside allowed bounds: {relative}"
            )
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(
                descriptor, min(1024 * 1024, contract.MAX_FILE_BYTES - observed + 1)
            )
            if not chunk:
                break
            observed += len(chunk)
            if observed > contract.MAX_FILE_BYTES:
                raise contract.CandidateHandoffError(
                    f"file exceeds byte limit: {relative}"
                )
            digest.update(chunk)
            if collector is not None:
                collector(chunk)
        after = os.fstat(descriptor)
        _require_stable_identity(before, after, relative)
        if observed != before.st_size:
            raise contract.CandidateHandoffError(
                f"file changed while reading: {relative}"
            )
        return observed, "sha256:" + digest.hexdigest()
    except OSError as exc:
        raise contract.CandidateHandoffError(
            f"cannot read regular member {relative}: {exc}"
        ) from exc
    finally:
        os.close(descriptor)


def _open_beneath(root: Path, relative: str) -> int:
    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    parts = PurePosixPath(relative).parts
    current = -1
    try:
        current = os.open(root, directory_flags)
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=current)
            os.close(current)
            current = child
        return os.open(parts[-1], file_flags, dir_fd=current)
    except OSError as exc:
        raise contract.CandidateHandoffError(
            f"cannot open member without links {relative}: {exc}"
        ) from exc
    finally:
        if current >= 0:
            os.close(current)


def _require_stable_identity(
    before: os.stat_result,
    after: os.stat_result,
    path: str,
) -> None:
    def identity(item: os.stat_result) -> tuple[int, ...]:
        return (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )

    if not stat.S_ISREG(after.st_mode) or identity(before) != identity(after):
        raise contract.CandidateHandoffError(
            f"file identity changed while reading: {path}"
        )
