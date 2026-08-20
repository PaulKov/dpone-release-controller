"""Quarantined direct lease writer; broker v2 is the sole lease authority."""

from __future__ import annotations

from typing import Any, Never

from tools.evidence.release_legacy_writer_guard import disabled


class LeaseConflictError(RuntimeError):
    """Retained only so dormant callers import without acquiring authority."""


def acquire_publication_lease(*args: Any, **kwargs: Any) -> Never:
    del args, kwargs
    return disabled("legacy direct lease acquire")


def release_publication_lease(*args: Any, **kwargs: Any) -> Never:
    del args, kwargs
    return disabled("legacy direct lease release")


def active_lease(*args: Any, **kwargs: Any) -> Never:
    del args, kwargs
    return disabled("legacy list-then-decide lease")


def parse_utc(*args: Any, **kwargs: Any) -> Never:
    del args, kwargs
    return disabled("legacy lease helper")
