"""Canonical static endpoint paths for controller operation selectors."""

from __future__ import annotations

import re

_SEGMENT_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z", re.ASCII)
_PATH_RE = re.compile(r"/[a-z0-9]+(?:[/-][a-z0-9]+)*\Z", re.ASCII)


class RoutePathError(ValueError):
    """A selector or generated path is not canonical lowercase ASCII."""


def kebab(value: str) -> str:
    """Convert one closed enum token to a canonical path segment."""

    segment = value.lower().replace("_", "-")
    if _SEGMENT_RE.fullmatch(segment) is None:
        raise RoutePathError(f"selector segment is not canonical: {value!r}")
    return segment


def operation_path(selector: str, job_name: str) -> str:
    """Return the single reviewed path for a selector-owning operation."""

    kind, separator, branch = selector.partition(":")
    kind_path = kebab(kind)
    branch_path = kebab(branch) if separator else None
    if selector == "ACTIVATION_PROOF":
        path = "/v1/activation/proof"
    elif selector == "CANDIDATE_SOURCE":
        path = "/v1/providers/github/candidate"
    elif selector == "CANDIDATE_HANDOFF":
        path = "/v1/releases/candidate/admit"
    elif selector == "TERMINAL_ASSERT":
        path = "/v1/releases/terminal/assert"
    elif kind == "LEASE_ACQUIRED":
        path = (
            "/v1/leases/recovery/acquire"
            if branch == "RECOVERY"
            else "/v1/leases/acquire"
        )
    elif kind == "LEASE_RENEWED":
        path = "/v1/leases/renew"
    elif kind == "LEASE_RELEASED":
        path = {
            "CANCELLED": "/v1/releases/cancel/finalize",
            "RECOVERY_REQUIRED": "/v1/releases/cancel/finalize",
            "ABANDONED": "/v1/internal/releases/recovery/hold/finalize",
        }[branch]
    elif job_name == "cancel":
        path = "/v1/releases/cancel/finalize"
    elif job_name == "pypi-prepare":
        path = "/v1/releases/pypi/prepare"
    elif job_name == "pypi-observe":
        path = "/v1/releases/pypi/admit"
    elif job_name == "recovery":
        path = "/v1/releases/recovery/observe"
    elif kind == "MUTATION_INTENT":
        assert branch_path is not None
        path = f"/v1/releases/intents/{branch_path}/issue"
    elif kind == "MUTATION_INTENT_CONSUMED":
        assert branch_path is not None
        path = f"/v1/releases/intents/{branch_path}/consume"
    else:
        suffix = f"/{branch_path}" if branch_path is not None else ""
        path = f"/v1/releases/events/{kind_path}{suffix}/admit"
    if _PATH_RE.fullmatch(path) is None:
        raise RoutePathError(f"operation path is not canonical: {path!r}")
    return path
