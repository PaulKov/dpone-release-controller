"""Canonical checked provider-profile vector for cross-repository parity."""

from __future__ import annotations

from typing import Any

from tools.evidence.release_canonical import canonical_json_bytes
from tools.evidence.release_controller_provider_profile import REQUIRED_PROVIDER_PROFILE

SCHEMA = "dpone.release-controller-required-provider-profile.v1"


def document() -> dict[str, Any]:
    """Return only non-live provider semantics; A0 owns all observed IDs."""

    return {
        "schema": SCHEMA,
        "schema_version": 1,
        "required_provider_profile": REQUIRED_PROVIDER_PROFILE,
    }


def encoded() -> bytes:
    """Return exact bytes mirrored by the target policy and broker tests."""

    return canonical_json_bytes(document())
