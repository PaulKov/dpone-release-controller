"""Duplicate-safe JSON and canonical digest helpers for candidate documents."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from tools.evidence import release_candidate_contract as contract
from tools.evidence.release_canonical import CanonicalJsonError, canonical_json_bytes


def load_unique_json(data: bytes, name: str) -> Mapping[str, Any]:
    """Decode UTF-8 JSON while rejecting duplicate keys and non-object roots."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise contract.CandidateHandoffError(f"duplicate JSON key: {key!r}")
            result[key] = value
        return result

    try:
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise contract.CandidateHandoffError(f"invalid {name} JSON: {exc}") from exc
    return contract.require_mapping(raw, name)


def manifest_canonical_sha256(raw_without_digest: Mapping[str, Any]) -> str:
    """Return tagged SHA-256 of canonical manifest bytes without recursion."""

    if "manifest_sha256" in raw_without_digest:
        raise contract.CandidateHandoffError(
            "manifest digest input must omit manifest_sha256"
        )
    try:
        body = canonical_json_bytes(raw_without_digest)
    except CanonicalJsonError as exc:
        raise contract.CandidateHandoffError(
            f"manifest is outside the canonical JSON domain: {exc}"
        ) from exc
    return "sha256:" + hashlib.sha256(body).hexdigest()
