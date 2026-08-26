"""Frozen PyPI distribution byte limits shared by import and publication.

PyPI rejects an individual wheel or source distribution larger than
100,000,000 bytes.  The release policy additionally limits the exact eight
distribution files to 512 MiB in aggregate.  Keeping these values in one
dependency-free module prevents candidate admission, mutation intents, and
provider receipts from drifting apart.
"""

from __future__ import annotations

from collections.abc import Iterable

MAX_PYPI_FILE_BYTES = 100_000_000
MAX_PYPI_TOTAL_BYTES = 512 * 1024 * 1024


class PyPISizeLimitError(ValueError):
    """A declared PyPI distribution set is outside the frozen policy."""


def require_file_size(value: int, name: str) -> int:
    """Return one positive byte size when it fits PyPI's exact file limit."""

    if type(value) is not int or value <= 0:
        raise PyPISizeLimitError(f"{name} must be a positive integer")
    if value > MAX_PYPI_FILE_BYTES:
        raise PyPISizeLimitError(
            f"{name} exceeds PyPI's {MAX_PYPI_FILE_BYTES}-byte file limit"
        )
    return value


def require_inventory_sizes(sizes: Iterable[int], name: str) -> int:
    """Return the aggregate size after enforcing per-file and total limits."""

    total = 0
    for index, size in enumerate(sizes):
        total += require_file_size(size, f"{name}[{index}]")
    if total > MAX_PYPI_TOTAL_BYTES:
        raise PyPISizeLimitError(
            f"{name} exceeds PyPI's {MAX_PYPI_TOTAL_BYTES}-byte aggregate limit"
        )
    return total
