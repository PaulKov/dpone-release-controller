"""Closed cross-language canonical JSON and domain-separated SHA-256 IDs."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_DEPTH = 32
MAX_NODES = 100_000
MAX_MAPPING_ENTRIES = 1_024
MAX_SEQUENCE_ITEMS = 4_096
MAX_KEY_BYTES = 128
MAX_STRING_BYTES = 1_048_576
MAX_CANONICAL_BYTES = 16_777_216


class CanonicalJsonError(ValueError):
    """A value is outside the deterministic Python/TypeScript JSON domain."""


def canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    """Encode the bounded JSON domain shared with the broker.

    Accepted values are ``null``, booleans, JS-safe integers, Unicode strings,
    arrays, and mappings with ASCII string keys. Floats and implementation-
    specific Python values are forbidden. ASCII keys make Python's key order
    byte-identical to the broker without an implicit UTF-16 ordering rule.
    """

    normalized = _normalize(payload, depth=0, budget=[MAX_NODES])
    if not isinstance(normalized, dict):
        raise CanonicalJsonError("canonical JSON root must be a mapping")
    encoded = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise CanonicalJsonError("canonical JSON exceeds the byte limit")
    return encoded


def sha256_hex(payload: Mapping[str, Any]) -> str:
    """Return the SHA-256 hex digest of closed canonical JSON bytes."""

    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def sha256_id(domain: str, payload: Mapping[str, Any]) -> str:
    """Return ``sha256:<hex>`` over an exact domain/payload wrapper."""

    if (
        not isinstance(domain, str)
        or not domain
        or not domain.isascii()
        or len(domain.encode("ascii")) > MAX_KEY_BYTES
    ):
        raise CanonicalJsonError("domain must be non-empty bounded ASCII")
    return f"sha256:{sha256_hex({'domain': domain, 'payload': payload})}"


def _normalize(value: Any, *, depth: int, budget: list[int]) -> Any:
    if depth > MAX_DEPTH:
        raise CanonicalJsonError("canonical JSON nesting exceeds the depth limit")
    budget[0] -= 1
    if budget[0] < 0:
        raise CanonicalJsonError("canonical JSON exceeds the node limit")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalJsonError("integer is outside the JS-safe range")
        return value
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise CanonicalJsonError("string contains a Unicode surrogate")
        if len(value.encode("utf-8")) > MAX_STRING_BYTES:
            raise CanonicalJsonError("string exceeds the UTF-8 byte limit")
        return value
    if isinstance(value, Mapping):
        if len(value) > MAX_MAPPING_ENTRIES:
            raise CanonicalJsonError("mapping exceeds the member limit")
        result: dict[str, Any] = {}
        for key, member in value.items():
            if (
                not isinstance(key, str)
                or not key
                or not key.isascii()
                or len(key.encode("ascii")) > MAX_KEY_BYTES
            ):
                raise CanonicalJsonError("mapping keys must be bounded non-empty ASCII")
            result[key] = _normalize(member, depth=depth + 1, budget=budget)
        return result
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray, memoryview)
    ):
        if len(value) > MAX_SEQUENCE_ITEMS:
            raise CanonicalJsonError("array exceeds the item limit")
        return [_normalize(member, depth=depth + 1, budget=budget) for member in value]
    raise CanonicalJsonError(f"unsupported canonical JSON type: {type(value).__name__}")
