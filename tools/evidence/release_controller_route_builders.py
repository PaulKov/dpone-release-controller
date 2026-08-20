"""Small constructors for the closed controller route tables."""

from __future__ import annotations

from tools.evidence.release_controller_route_contract import RouteProfile
from tools.evidence.release_controller_route_paths import operation_path


def job(
    selector: str,
    job_name: str,
    environment: str,
    audience: str,
    *states: str,
) -> RouteProfile:
    """Build one GitHub Actions route bound to an exact job and environment."""

    kind = selector.split(":", 1)[0]
    return RouteProfile(
        selector,
        "github_actions_job",
        job_name,
        environment,
        audience,
        "POST",
        operation_path(selector, job_name),
        kind,
        tuple(states),
    )


def service(selector: str, path: str, *states: str) -> RouteProfile:
    """Build one private trusted-service route."""

    return RouteProfile(
        selector,
        "trusted_controller_service",
        None,
        None,
        None,
        "POST",
        path,
        selector.split(":", 1)[0],
        tuple(states),
    )


def maintainer(selector: str, path: str, *states: str) -> RouteProfile:
    """Build one explicitly authenticated incident-maintainer route."""

    return RouteProfile(
        selector,
        "maintainer_incident_action",
        None,
        None,
        None,
        "POST",
        path,
        selector,
        tuple(states),
    )
