"""Closed typed ledger endpoints derived from the authoritative route selectors.

The router consumes the generated ``BY_PATH`` table; it never parses a URL
back into a selector and never accepts an unknown slug.  Provider reads and
mutations remain separate operation phases.  These endpoints accept only the
selector-specific request schema and let the broker author the envelope.
"""

from __future__ import annotations

from dataclasses import dataclass

from tools.evidence import release_candidate_stream as candidate_stream
from tools.evidence import release_controller_activation_proof as activation_proof
from tools.evidence import release_controller_exchange as exchange
from tools.evidence import release_controller_schema_ids as schema_ids
from tools.evidence.release_controller_route_contract import (
    RECEIPT_PROJECTION_RESPONSE_SCHEMA,
    SELECTOR_REQUEST_SCHEMA,
)
from tools.evidence.release_controller_route_paths import kebab, operation_path
from tools.evidence.release_controller_routes import ROUTES


class TypedRouteError(ValueError):
    """A selector path is ambiguous, non-canonical, or not frozen."""


@dataclass(frozen=True, slots=True)
class TypedRoute:
    """One statically generated request/response validator binding."""

    selector: str
    path: str
    request_schema: str
    response_schema: str
    receipt_kind: str | None
    receipt_states: tuple[str, ...]
    job_name: str
    environment: str
    audience: str


def _parts(selector: str) -> tuple[str, str | None]:
    values = selector.split(":", 1)
    kind = values[0]
    branch = values[1] if len(values) == 2 else None
    kebab(kind)
    if branch is not None:
        kebab(branch)
    return kind, branch


def _schemas(selector: str, job_name: str) -> tuple[str, str]:
    if selector == "ACTIVATION_PROOF":
        return activation_proof.REQUEST_SCHEMA, activation_proof.RESPONSE_SCHEMA
    if selector == "CANDIDATE_SOURCE":
        return candidate_stream.REQUEST_SCHEMA, candidate_stream.RESPONSE_SCHEMA
    if selector == "CANDIDATE_HANDOFF":
        return (
            exchange.CANDIDATE_ADMIT_REQUEST_SCHEMA,
            exchange.CANDIDATE_ADMIT_RESPONSE_SCHEMA,
        )
    if selector == "TERMINAL_ASSERT":
        return SELECTOR_REQUEST_SCHEMA, schema_ids.TERMINAL_ASSERT_RESPONSE
    if job_name == "cancel":
        return SELECTOR_REQUEST_SCHEMA, schema_ids.CANCELLATION_OUTCOME_RESPONSE
    if job_name == "lease-renew":
        return schema_ids.LEASE_RENEW_REQUEST, schema_ids.LEASE_RENEW_RESPONSE
    if job_name == "recovery":
        return SELECTOR_REQUEST_SCHEMA, schema_ids.RECOVERY_DECISION_RESPONSE
    if job_name in {"pypi-observe", "pypi-recovery-observe"}:
        return SELECTOR_REQUEST_SCHEMA, schema_ids.PYPI_OUTCOME_RESPONSE
    if job_name == "pypi-prepare":
        return SELECTOR_REQUEST_SCHEMA, schema_ids.RECEIPT_BATCH_PROJECTION
    _parts(selector)
    return SELECTOR_REQUEST_SCHEMA, RECEIPT_PROJECTION_RESPONSE_SCHEMA


def _rows() -> tuple[TypedRoute, ...]:
    rows: list[TypedRoute] = []
    for route in ROUTES:
        if route.requester_kind != "github_actions_job":
            continue
        assert route.job_name and route.environment and route.audience
        request_schema, response_schema = _schemas(route.selector, route.job_name)
        path = operation_path(route.selector, route.job_name)
        rows.append(
            TypedRoute(
                selector=route.selector,
                path=path,
                request_schema=request_schema,
                response_schema=response_schema,
                receipt_kind=route.receipt_type,
                receipt_states=route.receipt_states,
                job_name=route.job_name,
                environment=route.environment,
                audience=route.audience,
            )
        )
    rows.sort(key=lambda row: row.selector.encode("ascii"))
    if len({row.selector for row in rows}) != len(rows):
        raise TypedRouteError("duplicate typed route selector")
    return tuple(rows)


ROUTES_BY_SELECTOR = {row.selector: row for row in _rows()}
BY_PATH = {
    path: tuple(row for row in ROUTES_BY_SELECTOR.values() if row.path == path)
    for path in sorted({row.path for row in ROUTES_BY_SELECTOR.values()})
}


def by_selector(selector: str) -> TypedRoute:
    """Return a frozen row; unknown selectors are never synthesized."""

    try:
        return ROUTES_BY_SELECTOR[selector]
    except KeyError as exc:
        raise TypedRouteError("unknown typed route selector") from exc


def by_path(path: str) -> tuple[TypedRoute, ...]:
    """Return the closed endpoint alternatives; unknown paths fail early."""

    try:
        return BY_PATH[path]
    except KeyError as exc:
        raise TypedRouteError("unknown typed route path") from exc
