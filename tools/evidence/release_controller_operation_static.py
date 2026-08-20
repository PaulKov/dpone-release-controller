"""Closed explicit operation table for simple controller transitions.

Provider observations never round-trip through runner state.  A typed broker
endpoint delegates the fresh read to the pinned service and authors the
receipt in one server-side transaction.
"""

from dataclasses import dataclass

from tools.evidence import release_controller_routes as controller_routes
from tools.evidence import release_controller_typed_routes as typed_routes
from tools.evidence.release_controller_operation_contract import (
    LEDGER_TX,
    READ,
    SERVER_REQUERY_LEDGER_TX,
    OperationProfile,
)
from tools.evidence.release_controller_operation_factory import once, server_transaction


@dataclass(frozen=True, slots=True)
class StaticStep:
    """One explicit selector and optional server-side provider reader."""

    selector: str
    server_service_role: str | None = None
    additional_selectors: tuple[str, ...] = ()

    @property
    def selectors(self) -> tuple[str, ...]:
        """Return the exact outcomes owned by this one server transaction."""

        return (self.selector, *self.additional_selectors)


@dataclass(frozen=True, slots=True)
class StaticOperation:
    """One ordered workflow job; never synthesized from unknown routes."""

    job_name: str
    ordered_steps: tuple[StaticStep, ...]


TABLE = (
    StaticOperation(
        "admit", (StaticStep("ACTIVATION_PROOF"), StaticStep("REQUEST_ENQUEUED"))
    ),
    StaticOperation(
        "attest-verify",
        (StaticStep("ATTESTATION_VERIFIED", "attestation_reader"),),
    ),
    StaticOperation("authorize", (StaticStep("AUTHORIZED"),)),
    StaticOperation("bundle-verify", (StaticStep("PUBLIC_BUNDLE_VERIFIED"),)),
    StaticOperation(
        "cancel",
        (
            StaticStep(
                "CANCELLATION",
                "cancellation_observer",
                (
                    "LEASE_RELEASED:CANCELLED",
                    "LEASE_RELEASED:RECOVERY_REQUIRED",
                ),
            ),
        ),
    ),
    StaticOperation("close", (StaticStep("CLOSED"),)),
    StaticOperation(
        "github-publish-intent",
        (StaticStep("MUTATION_INTENT:GITHUB_RELEASE_PUBLISH"),),
    ),
    StaticOperation(
        "github-publish-observe",
        (
            StaticStep(
                "GITHUB_RELEASE_TRANSITION:PUBLISH_ACCEPTED",
                "github_governance_reader",
            ),
        ),
    ),
    StaticOperation(
        "github-verify",
        (
            StaticStep(
                "GITHUB_RELEASE_TRANSITION:IMMUTABLE_VERIFIED",
                "github_governance_reader",
            ),
        ),
    ),
    *(
        StaticOperation(
            f"governance-{label.lower()}",
            (
                StaticStep(
                    f"GOVERNANCE_SNAPSHOT:{label}",
                    "github_governance_reader",
                ),
            ),
        )
        for label in "ABC"
    ),
    StaticOperation(
        "pypi-recovery-observe",
        (StaticStep("PYPI_FILE_TRANSITION:ALREADY_PUBLISHED_EXACT", "pypi_reader"),),
    ),
    StaticOperation(
        "recovery",
        (
            StaticStep(
                "RECOVERY_OBSERVATION",
                "recovery_observer",
                (
                    "INCIDENT_HOLD",
                    "RECOVERY_CLOSED_EXACT",
                    "RECOVERY_RESUMED",
                ),
            ),
        ),
    ),
    StaticOperation(
        "tenant-hygiene",
        (StaticStep("TENANT_HYGIENE_VERIFIED", "tenant_scanner"),),
    ),
)

SPECIAL_JOB_NAMES = frozenset(
    {
        "attest-create",
        "candidate-import",
        "controller-complete",
        "github-publish",
        "lease-acquire",
        "lease-renew",
        "recovery-lease-acquire",
        "pypi-observe",
        "pypi-prepare",
        "pypi-publish",
    }
)

_PROVIDER_READS = {
    "ATTESTATION_VERIFIED": ("GITHUB_ATTESTATION_REQUERY",),
    "CANCELLATION": ("GITHUB_RELEASE_REQUERY", "PYPI_PROJECT_FILE_REQUERY"),
    "GITHUB_RELEASE_TRANSITION:PUBLISH_ACCEPTED": ("GITHUB_RELEASE_REQUERY",),
    "GITHUB_RELEASE_TRANSITION:IMMUTABLE_VERIFIED": (
        "GITHUB_RELEASE_AND_ASSET_REQUERY",
    ),
    "GOVERNANCE_SNAPSHOT:A": ("GITHUB_GOVERNANCE_REQUERY",),
    "GOVERNANCE_SNAPSHOT:B": ("GITHUB_GOVERNANCE_REQUERY",),
    "GOVERNANCE_SNAPSHOT:C": ("GITHUB_GOVERNANCE_REQUERY",),
    "PYPI_FILE_TRANSITION:ALREADY_PUBLISHED_EXACT": ("PYPI_PROJECT_FILE_REQUERY",),
    "RECOVERY_OBSERVATION": (
        "GITHUB_RELEASE_AND_ASSET_REQUERY",
        "PYPI_PROJECT_FILE_REQUERY",
    ),
    "TENANT_HYGIENE_VERIFIED": ("TENANT_SCANNER_RESULT_REQUERY",),
}


def _phase(step: StaticStep) -> str:
    suffix = "SERVER_REQUERY_AND_ADMIT" if step.server_service_role else "ADMIT"
    if step.additional_selectors:
        suffix = "SERVER_REQUERY_AND_BRANCH"
    return f"{step.selector.replace(':', '_')}_{suffix}"


def _profiles() -> tuple[OperationProfile, ...]:
    configured = {
        selector
        for item in TABLE
        for step in item.ordered_steps
        for selector in step.selectors
    }
    expected = {
        route.selector
        for route in controller_routes.ROUTES
        if route.requester_kind == "github_actions_job"
        and route.job_name not in SPECIAL_JOB_NAMES
    }
    if configured != expected:
        raise RuntimeError(
            "explicit operation table/route mismatch: "
            f"missing={sorted(expected - configured)}, "
            f"extra={sorted(configured - expected)}"
        )
    profiles: list[OperationProfile] = []
    for item in TABLE:
        calls = []
        for step in item.ordered_steps:
            route = controller_routes.ROUTE_BY_SELECTOR[step.selector]
            typed = typed_routes.by_selector(step.selector)
            selected_routes = tuple(
                controller_routes.ROUTE_BY_SELECTOR[selector]
                for selector in step.selectors
            )
            selected_typed = tuple(
                typed_routes.by_selector(selector) for selector in step.selectors
            )
            if any(
                candidate.job_name != route.job_name
                or candidate.environment != route.environment
                or candidate.audience != route.audience
                or candidate.method != route.method
                or candidate.path != route.path
                for candidate in selected_routes
            ) or any(
                candidate.path != typed.path
                or candidate.request_schema != typed.request_schema
                or candidate.response_schema != typed.response_schema
                for candidate in selected_typed
            ):
                raise RuntimeError("server branch route contract mismatch")
            effect = (
                SERVER_REQUERY_LEDGER_TX
                if step.server_service_role
                else (LEDGER_TX if route.receipt_type is not None else READ)
            )
            calls.append(
                once(
                    _phase(step),
                    route.method,
                    typed.path,
                    route.audience,
                    typed.request_schema,
                    typed.response_schema,
                    effect,
                    *tuple(
                        sorted(
                            {
                                candidate.receipt_type
                                for candidate in selected_routes
                                if candidate.receipt_type is not None
                            }
                        )
                    ),
                    receipt_selectors=(step.selectors if route.receipt_type else ()),
                    receipt_states=tuple(
                        sorted(
                            {
                                state
                                for candidate in selected_routes
                                for state in candidate.receipt_states
                            }
                        )
                    ),
                    authority_selectors=step.selectors,
                    server_service_role=step.server_service_role,
                )
            )
        first = controller_routes.ROUTE_BY_SELECTOR[item.ordered_steps[0].selector]
        if first.job_name != item.job_name or first.environment is None:
            raise RuntimeError("explicit operation identity mismatch")
        if any(
            controller_routes.ROUTE_BY_SELECTOR[selector].job_name != item.job_name
            for step in item.ordered_steps
            for selector in step.selectors
        ):
            raise RuntimeError("explicit operation crosses jobs")
        profiles.append(
            OperationProfile(
                item.job_name,
                item.job_name,
                first.environment,
                tuple(calls),
                900,
                server_transactions=tuple(
                    server_transaction(call, *_PROVIDER_READS[step.selector])
                    for step, call in zip(item.ordered_steps, calls, strict=True)
                    if step.server_service_role is not None
                ),
            )
        )
    return tuple(profiles)


OPERATIONS = _profiles()
