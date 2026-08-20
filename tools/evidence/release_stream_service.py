"""Quarantined direct stream writer; broker v2 owns append and WORM CAS."""

from __future__ import annotations

from typing import Any, Never

from tools.evidence.release_legacy_writer_guard import disabled


class StreamPrerequisiteError(RuntimeError):
    """Retained only for import compatibility with dormant modules."""


def append_stream_receipt(*args: Any, **kwargs: Any) -> Never:
    del args, kwargs
    return disabled("legacy direct receipt append")
