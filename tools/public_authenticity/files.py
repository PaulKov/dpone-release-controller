"""Private file snapshots and closed environment for authenticity adapters."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Mapping


class AuthenticityFileError(RuntimeError):
    """Stable file-boundary failure carrying an uppercase reason code."""


def closed_environment(snapshot_root: Path) -> Mapping[str, str]:
    """Return only non-secret process settings needed for deterministic output."""
    config_root = snapshot_root / "gh-config"
    home_root = snapshot_root / "home"
    try:
        config_root.mkdir(mode=0o700)
        home_root.mkdir(mode=0o700)
    except OSError as error:
        raise AuthenticityFileError("PUBLIC_AUTH_ENVIRONMENT_UNAVAILABLE") from error
    return {
        "GH_CONFIG_DIR": str(config_root),
        "GH_PROMPT_DISABLED": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "HOME": str(home_root),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "TMPDIR": str(snapshot_root),
    }


def snapshot_file(
    path: Path,
    destination: Path,
    maximum: int,
    label: str,
    *,
    executable: bool = False,
) -> tuple[Path, str]:
    """Copy one bounded regular file through a no-follow descriptor and hash it."""
    if not path.is_absolute():
        raise AuthenticityFileError(f"PUBLIC_AUTH_{label}_PATH_INVALID")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise AuthenticityFileError(f"PUBLIC_AUTH_{label}_NOFOLLOW_UNAVAILABLE")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise AuthenticityFileError(f"PUBLIC_AUTH_{label}_UNAVAILABLE") from error
    digest = hashlib.sha256()
    copied = 0
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise AuthenticityFileError(f"PUBLIC_AUTH_{label}_TYPE_INVALID")
            if metadata.st_size < 1 or metadata.st_size > maximum:
                raise AuthenticityFileError(f"PUBLIC_AUTH_{label}_SIZE_INVALID")
            if executable and metadata.st_mode & 0o111 == 0:
                raise AuthenticityFileError(f"PUBLIC_AUTH_{label}_NOT_EXECUTABLE")
            with destination.open("xb") as target:
                while chunk := source.read(1_048_576):
                    copied += len(chunk)
                    if copied > maximum:
                        raise AuthenticityFileError(f"PUBLIC_AUTH_{label}_SIZE_INVALID")
                    target.write(chunk)
                    digest.update(chunk)
                target.flush()
                os.fsync(target.fileno())
            final_metadata = os.fstat(source.fileno())
    except OSError as error:
        raise AuthenticityFileError(f"PUBLIC_AUTH_{label}_READ_FAILED") from error
    if copied != metadata.st_size or final_metadata.st_size != metadata.st_size:
        raise AuthenticityFileError(f"PUBLIC_AUTH_{label}_CHANGED_DURING_READ")
    try:
        destination.chmod(0o700 if executable else 0o600)
    except OSError as error:
        raise AuthenticityFileError(f"PUBLIC_AUTH_{label}_READ_FAILED") from error
    return destination, digest.hexdigest()
