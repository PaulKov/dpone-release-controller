"""Fail-closed loading primitives for versioned release contract sources.

Files below ``contracts/`` are production-owned, language-neutral inputs.  They
must be parsed without duplicate-key or implicit-shape tolerance before any
generator projects them into public schemas or conformance fixtures.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = REPOSITORY_ROOT / "contracts"


class ContractSourceError(ValueError):
    """A checked contract source is missing, ambiguous, or malformed."""


def load_object(path: Path, *, label: str) -> dict[str, Any]:
    """Load one UTF-8 JSON object while rejecting duplicate member names."""

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ContractSourceError(f"{label} source is unavailable: {path}") from exc

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ContractSourceError(f"{label} has duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ContractSourceError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ContractSourceError(f"{label} must be a JSON object")
    return value


def pretty_json_bytes(value: Any) -> bytes:
    """Return the stable human-reviewable projection used by public schemas."""

    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
