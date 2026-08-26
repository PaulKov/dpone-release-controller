"""Primitive types and fixed names for controller broker routes."""

from __future__ import annotations

from dataclasses import dataclass

from tools.evidence import release_controller_schema_ids as schema_ids

LEDGER = "dpone-release-controller-ledger-write"
CANDIDATE = "dpone-release-controller-candidate-read"
GOVERNANCE = "dpone-release-controller-governance-read"
ATTEST = "dpone-release-controller-attest"
PYPI = "dpone-release-controller-pypi"
GITHUB = "dpone-release-controller-github-release"
INTENT = "/v1/intents/issue"
SELECTOR_REQUEST_SCHEMA = schema_ids.SELECTOR_REQUEST
RECEIPT_PROJECTION_RESPONSE_SCHEMA = schema_ids.RECEIPT_PROJECTION


@dataclass(frozen=True, slots=True)
class RouteProfile:
    """One exact authenticated operation at the controller/broker boundary."""

    selector: str
    requester_kind: str
    job_name: str | None
    environment: str | None
    audience: str | None
    method: str
    path: str
    receipt_type: str | None
    receipt_states: tuple[str, ...]
