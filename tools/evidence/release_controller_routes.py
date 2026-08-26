"""Closed controller job, OIDC, and broker-route authority table.

The table is deliberately independent from workflow YAML. Receipt producers,
the broker, and the workflow AST verifier consume the same selectors so one
logical GitHub job can never authenticate under two environments.
"""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_payload_state_contract as state_contract
from tools.evidence.release_controller_route_contract import (
    ATTEST as ATTEST,
    CANDIDATE as CANDIDATE,
    GITHUB as GITHUB,
    GOVERNANCE as GOVERNANCE,
    INTENT as INTENT,
    LEDGER as LEDGER,
    PYPI as PYPI,
    RouteProfile,
)
from tools.evidence.release_controller_routes_admission import ADMISSION_ROUTES
from tools.evidence.release_controller_routes_publication import PUBLICATION_ROUTES
from tools.evidence.release_controller_routes_recovery import RECOVERY_ROUTES

HELD_PUBLIC_CLOSURE_SELECTORS = frozenset(
    {
        "CLOSED_CHECK_TRANSITION:PROJECTED",
        "CLOSED_CHECK_TRANSITION:VERIFIED",
        "CLOSURE_ARTIFACT_VERIFIED",
        "LEASE_RELEASED:CLOSED",
        "MUTATION_INTENT:GITHUB_CLOSED_CHECK_PROJECT",
        "MUTATION_INTENT:GITHUB_CLOSURE_ARTIFACT_UPLOAD",
        "MUTATION_INTENT_CONSUMED:GITHUB_CLOSED_CHECK_PROJECT",
        "MUTATION_INTENT_CONSUMED:GITHUB_CLOSURE_ARTIFACT_UPLOAD",
    }
)

ROUTES = (*ADMISSION_ROUTES, *PUBLICATION_ROUTES, *RECOVERY_ROUTES)
ROUTE_BY_SELECTOR = {route.selector: route for route in ROUTES}
if len(ROUTE_BY_SELECTOR) != len(ROUTES):
    raise RuntimeError("duplicate release controller route selector")

_ROUTE_STATES = {
    route.selector: route.receipt_states for route in ROUTES if route.receipt_type
}
_EXECUTABLE_STATES = dict(state_contract.STATES_BY_SELECTOR)
if _ROUTE_STATES != _EXECUTABLE_STATES:
    raise RuntimeError("controller route/payload selector state contract drift")


def selector_for(payload: Mapping[str, Any]) -> str:
    """Return the sole route discriminator for a closed receipt payload."""

    return state_contract.selector_for(payload)


def profile_for(payload: Mapping[str, Any]) -> RouteProfile:
    """Validate state parity and return one exact authenticated route."""

    selector = selector_for(payload)
    route = ROUTE_BY_SELECTOR.get(selector)
    if route is None or payload.get("state") not in route.receipt_states:
        raise contract.ReceiptValidationError("no exact controller route for payload")
    return route


def require_one_environment_per_job() -> None:
    """Reject ambiguous provider check labels across OIDC environments."""

    environments: dict[str, str] = {}
    for route in ROUTES:
        if route.requester_kind != "github_actions_job":
            continue
        assert route.job_name is not None and route.environment is not None
        previous = environments.setdefault(route.job_name, route.environment)
        if previous != route.environment:
            raise RuntimeError(f"job {route.job_name!r} crosses environments")


require_one_environment_per_job()
