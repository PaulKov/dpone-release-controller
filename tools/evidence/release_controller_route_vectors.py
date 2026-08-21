"""Canonical cross-language fixture for controller broker routes."""

from __future__ import annotations

from typing import Any

from tools.evidence.release_canonical import canonical_json_bytes
from tools.evidence.release_controller_routes import ROUTES

SCHEMA = "dpone.release-controller-route-profile.v1"


def document() -> dict[str, Any]:
    """Return every route as a closed, selector-sorted JSON document."""

    return {
        "schema": SCHEMA,
        "schema_version": 1,
        "routes": [
            {
                "selector": route.selector,
                "requester_kind": route.requester_kind,
                "job_name": route.job_name,
                "environment": route.environment,
                "audience": route.audience,
                "method": route.method,
                "path": route.path,
                "receipt_type": route.receipt_type,
                "receipt_states": list(route.receipt_states),
            }
            for route in sorted(ROUTES, key=lambda value: value.selector)
        ],
    }


def encoded() -> bytes:
    """Return the exact bytes mirrored by the broker and target policy."""

    return canonical_json_bytes(document())
