"""Quarantined Actions-side B2 adapter.

WORM persistence is now an internal broker operation. Controller jobs never
receive B2 application keys and cannot list-then-put receipt state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Never

from tools.evidence.release_legacy_writer_guard import disabled


def object_key_for(*args: Any, **kwargs: Any) -> Never:
    del args, kwargs
    return disabled("legacy B2 receipt key")


class InMemoryEvidenceStore:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        disabled("legacy in-memory direct receipt store")


@dataclass(frozen=True, slots=True)
class B2Credentials:
    key_id: str
    application_key: str
    bucket_id: str
    bucket_name: str


class BackblazeB2EvidenceStore:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        disabled("Actions-side B2 credentials")
