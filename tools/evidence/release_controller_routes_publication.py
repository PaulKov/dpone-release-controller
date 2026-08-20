"""Draft, PyPI, and GitHub publication route slice."""

from __future__ import annotations

from tools.evidence.release_controller_route_builders import job, service
from tools.evidence.release_controller_route_contract import (
    GOVERNANCE,
    INTENT,
    LEDGER,
)

PUBLICATION_ROUTES = (
    *(
        service(
            f"MUTATION_INTENT:{operation}",
            f"/v1/releases/intents/{operation.lower().replace('_', '-')}/issue",
            "MUTATION_INTENT_RECORDED",
        )
        for operation in (
            "GITHUB_DRAFT_CREATE",
            "GITHUB_DRAFT_ASSET_UPLOAD",
            "GITHUB_DRAFT_UPDATE",
        )
    ),
    service(
        "DRAFT_TRANSITION:CREATED",
        "/v1/internal/releases/draft/provider-outcome/created",
        "DRAFT_CREATED",
    ),
    service(
        "DRAFT_TRANSITION:ASSET_UPLOADED",
        "/v1/internal/releases/draft/provider-outcome/asset-uploaded",
        "DRAFT_STAGING",
    ),
    service(
        "DRAFT_TRANSITION:STAGED",
        "/v1/internal/releases/draft/provider-outcome/staged",
        "DRAFT_STAGED",
    ),
    service(
        "DRAFT_TRANSITION:VERIFIED",
        "/v1/internal/releases/draft/provider-outcome/verified",
        "DRAFT_VERIFIED",
    ),
    *(
        service(
            f"MUTATION_INTENT_CONSUMED:{operation}",
            f"/v1/releases/intents/{operation.lower().replace('_', '-')}/consume",
            "MUTATION_INTENT_CONSUMED",
        )
        for operation in (
            "GITHUB_DRAFT_CREATE",
            "GITHUB_DRAFT_ASSET_UPLOAD",
            "GITHUB_DRAFT_UPDATE",
        )
    ),
    job("AUTHORIZED", "authorize", "release-attest", LEDGER, "AUTHORIZED"),
    service(
        "MUTATION_INTENT:PYPI_DEPLOYMENT_APPROVE",
        INTENT,
        "MUTATION_INTENT_RECORDED",
    ),
    service(
        "MUTATION_INTENT:PYPI_DEPLOYMENT_REJECT",
        INTENT,
        "MUTATION_INTENT_RECORDED",
    ),
    *(
        service(kind, "/v1/providers/pypi/deployment-gate", *states)
        for kind, states in (
            ("PYPI_GATE_REQUESTED", ("PYPI_GATE_PENDING",)),
            ("PYPI_GATE_APPROVED", ("PYPI_GATE_APPROVED",)),
            ("PYPI_GATE_REJECTED", ("PYPI_GATE_REJECTED",)),
            (
                "PYPI_GATE_CALLBACK_AMBIGUOUS",
                ("PYPI_GATE_RECONCILIATION_REQUIRED",),
            ),
            (
                "PYPI_GATE_RECONCILED",
                (
                    "PYPI_GATE_PENDING",
                    "PYPI_GATE_APPROVED",
                    "PYPI_GATE_REJECTED",
                ),
            ),
        )
    ),
    *(
        job(
            f"PYPI_FILE_TRANSITION:{transition}",
            "pypi-prepare",
            "release-attest",
            LEDGER,
            "PYPI_PUBLISHING",
        )
        for transition in ("PENDING_UPLOAD", "SEALED_FOR_UPLOAD")
    ),
    job(
        "MUTATION_INTENT:PYPI_FILE_UPLOAD_SET",
        "pypi-prepare",
        "release-attest",
        LEDGER,
        "MUTATION_INTENT_RECORDED",
    ),
    job(
        "PYPI_UPLOAD_SET_OBSERVED",
        "pypi-observe",
        "release-attest",
        LEDGER,
        "PYPI_UPLOAD_SET_COMPLETE",
        "RECOVERY_REQUIRED",
    ),
    *(
        job(
            f"PYPI_FILE_TRANSITION:{transition}",
            "pypi-observe",
            "release-attest",
            LEDGER,
            *states,
        )
        for transition, states in (
            ("INTEGRITY_VERIFIED", ("PYPI_PARTIAL_EXACT", "PYPI_VERIFIED")),
            ("CONFLICT", ("PYPI_CONFLICT",)),
        )
    ),
    job(
        "PYPI_FILE_TRANSITION:ALREADY_PUBLISHED_EXACT",
        "pypi-recovery-observe",
        "release-attest",
        LEDGER,
        "PYPI_PARTIAL_EXACT",
        "PYPI_VERIFIED",
    ),
    job(
        "MUTATION_INTENT:GITHUB_RELEASE_PUBLISH",
        "github-publish-intent",
        "release-attest",
        LEDGER,
        "MUTATION_INTENT_RECORDED",
    ),
    job(
        "GITHUB_RELEASE_TRANSITION:PUBLISH_ACCEPTED",
        "github-publish-observe",
        "release-attest",
        GOVERNANCE,
        "GITHUB_RELEASE_PUBLISHING",
    ),
    job(
        "GITHUB_RELEASE_TRANSITION:IMMUTABLE_VERIFIED",
        "github-verify",
        "release-attest",
        GOVERNANCE,
        "GITHUB_IMMUTABLE_PUBLISHED",
    ),
)
