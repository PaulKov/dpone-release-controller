"""Quarantined alias for the non-authoritative pre-broker envelope builder."""

from __future__ import annotations

from typing import Any, Never

from tools.evidence.release_legacy_writer_guard import disabled


def build_receipt_envelope(*args: Any, **kwargs: Any) -> Never:
    del args, kwargs
    return disabled("legacy receipt envelope builder")


def receipt_id_for(*args: Any, **kwargs: Any) -> Never:
    del args, kwargs
    return disabled("legacy undomained receipt identity")


def envelope_bytes(*args: Any, **kwargs: Any) -> Never:
    del args, kwargs
    return disabled("legacy receipt serialization")
