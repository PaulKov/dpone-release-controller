"""Recovery, closure, and one-use consumption route slice."""

from __future__ import annotations

from tools.evidence.release_controller_route_builders import job, maintainer, service
from tools.evidence.release_controller_route_contract import (
    ATTEST,
    GITHUB,
    LEDGER,
    PYPI,
)

RECOVERY_ROUTES = (
    job(
        "CANCELLATION",
        "cancel",
        "release-attest",
        LEDGER,
        "CANCELLED",
        "RECOVERY_REQUIRED",
    ),
    job(
        "RECOVERY_OBSERVATION",
        "recovery",
        "release-attest",
        LEDGER,
        "RECOVERY_RECONCILED",
    ),
    job(
        "RECOVERY_RESUMED",
        "recovery",
        "release-attest",
        LEDGER,
        "RECOVERY_RESUMED",
    ),
    job(
        "RECOVERY_CLOSED_EXACT",
        "recovery",
        "release-attest",
        LEDGER,
        "RECOVERY_CLOSED_EXACT",
    ),
    job("INCIDENT_HOLD", "recovery", "release-attest", LEDGER, "INCIDENT_HOLD"),
    maintainer(
        "INCIDENT_HOLD_RELEASED",
        "/v1/admin/incidents/hold-release",
        "RECOVERY_REQUIRED",
    ),
    job("CLOSED", "close", "release-attest", LEDGER, "CLOSED"),
    *(
        job(
            f"MUTATION_INTENT_CONSUMED:{operation}",
            job_name,
            environment,
            audience,
            "MUTATION_INTENT_CONSUMED",
        )
        for operation, job_name, environment, audience in (
            ("ATTESTATION_CREATE", "attest-create", "release-attest", ATTEST),
            ("GITHUB_RELEASE_PUBLISH", "github-publish", "github-release", GITHUB),
            ("PYPI_FILE_UPLOAD_SET", "pypi-publish", "pypi", PYPI),
        )
    ),
    service(
        "MUTATION_INTENT_CONSUMED:PYPI_DEPLOYMENT_APPROVE",
        "/v1/intents/consume",
        "MUTATION_INTENT_CONSUMED",
    ),
    service(
        "MUTATION_INTENT_CONSUMED:PYPI_DEPLOYMENT_REJECT",
        "/v1/intents/consume",
        "MUTATION_INTENT_CONSUMED",
    ),
)
