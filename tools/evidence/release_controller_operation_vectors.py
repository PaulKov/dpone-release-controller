"""Canonical cross-language Commit-A operation sequence vector."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from tools.evidence import release_controller_operations as operations
from tools.evidence import release_controller_routes as routes
from tools.evidence.release_canonical import canonical_json_bytes


def document() -> dict[str, Any]:
    """Return exact operations and separate workflow-facing action codecs."""

    operations.validate()
    return {
        "action_codecs": [asdict(codec) for codec in operations.ACTION_CODECS],
        "happy_path": happy_path(),
        "operations": [asdict(profile) for profile in operations.OPERATIONS],
        "schema": operations.SCHEMA,
        "schema_version": operations.SCHEMA_VERSION,
    }


def happy_path() -> list[dict[str, Any]]:
    """Return the exact 107-receipt sequence ending at private ledger CLOSED."""

    rows: list[tuple[str, str, str | None]] = [
        ("REQUEST_ENQUEUED", "QUEUED", None),
        ("GOVERNANCE_SNAPSHOT:A", "GOVERNANCE_A", None),
        ("CANDIDATE_HANDOFF", "CANDIDATE_HANDOFF", None),
        ("LEASE_ACQUIRED:PRIMARY", "LEASE_ACQUIRED", None),
        ("LEASE_RENEWED", "LEASE_RENEWED", None),
        ("TENANT_HYGIENE_VERIFIED", "TENANT_HYGIENE_VERIFIED", None),
        ("MUTATION_INTENT:ATTESTATION_CREATE", "MUTATION_INTENT_RECORDED", None),
        (
            "MUTATION_INTENT_CONSUMED:ATTESTATION_CREATE",
            "MUTATION_INTENT_CONSUMED",
            None,
        ),
        ("ATTESTATION_VERIFIED", "ATTESTED", None),
        ("PUBLIC_BUNDLE_VERIFIED", "PUBLIC_BUNDLE_VERIFIED", None),
    ]
    machine = operations.DRAFT_STAGE.durable_state_machine
    assert machine is not None
    for cycle in machine.cycles:
        rows.extend(
            (
                (cycle.intent_selector, "MUTATION_INTENT_RECORDED", cycle.subject),
                (cycle.consumed_selector, "MUTATION_INTENT_CONSUMED", cycle.subject),
                (cycle.outcome_selector, cycle.outcome_state, cycle.subject),
            )
        )
    rows.extend(
        (
            (
                machine.terminal_verification.selector,
                machine.terminal_verification.state,
                "candidate.release+exact-17-assets",
            ),
            ("GOVERNANCE_SNAPSHOT:B", "GOVERNANCE_B", None),
            ("AUTHORIZED", "AUTHORIZED", None),
            ("PYPI_GATE_REQUESTED", "PYPI_GATE_PENDING", None),
            (
                "MUTATION_INTENT:PYPI_DEPLOYMENT_APPROVE",
                "MUTATION_INTENT_RECORDED",
                None,
            ),
            (
                "MUTATION_INTENT_CONSUMED:PYPI_DEPLOYMENT_APPROVE",
                "MUTATION_INTENT_CONSUMED",
                None,
            ),
            ("PYPI_GATE_APPROVED", "PYPI_GATE_APPROVED", None),
        )
    )
    plan = operations.PYPI_PREPARE.publication_plan
    assert plan is not None
    for item in plan.files:
        for transition in item.prepare_transitions:
            rows.append(
                (
                    f"PYPI_FILE_TRANSITION:{transition}",
                    "PYPI_PUBLISHING",
                    item.inventory_selector,
                )
            )
    rows.extend(
        (
            (
                "MUTATION_INTENT:PYPI_FILE_UPLOAD_SET",
                "MUTATION_INTENT_RECORDED",
                "candidate.exact-eight-distributions",
            ),
            (
                "MUTATION_INTENT_CONSUMED:PYPI_FILE_UPLOAD_SET",
                "MUTATION_INTENT_CONSUMED",
                "candidate.exact-eight-distributions",
            ),
            (
                "PYPI_UPLOAD_SET_OBSERVED",
                "PYPI_UPLOAD_SET_COMPLETE",
                "candidate.exact-eight-distributions",
            ),
        )
    )
    for item in plan.files:
        rows.append(
            (
                "PYPI_FILE_TRANSITION:INTEGRITY_VERIFIED",
                "PYPI_VERIFIED" if item.ordinal == 8 else "PYPI_PARTIAL_EXACT",
                item.inventory_selector,
            )
        )
    rows.extend(
        (
            (
                "MUTATION_INTENT:GITHUB_RELEASE_PUBLISH",
                "MUTATION_INTENT_RECORDED",
                None,
            ),
            (
                "MUTATION_INTENT_CONSUMED:GITHUB_RELEASE_PUBLISH",
                "MUTATION_INTENT_CONSUMED",
                None,
            ),
            (
                "GITHUB_RELEASE_TRANSITION:PUBLISH_ACCEPTED",
                "GITHUB_RELEASE_PUBLISHING",
                None,
            ),
            (
                "GITHUB_RELEASE_TRANSITION:IMMUTABLE_VERIFIED",
                "GITHUB_IMMUTABLE_PUBLISHED",
                None,
            ),
            ("GOVERNANCE_SNAPSHOT:C", "GOVERNANCE_C", None),
            ("CLOSED", "CLOSED", None),
        )
    )
    if len(rows) != 107:
        raise RuntimeError("held operation sequence must contain 107 receipts")
    return [
        {
            "ordinal": ordinal,
            "producer_authority": _producer_authority(selector),
            "selector": selector,
            "state": state,
            "subject_selector": subject,
        }
        for ordinal, (selector, state, subject) in enumerate(rows, start=1)
    ]


def _producer_authority(selector: str) -> str:
    route = routes.ROUTE_BY_SELECTOR[selector]
    if route.requester_kind == "github_actions_job":
        return f"github_actions_job:{route.job_name}"
    if selector.startswith("MUTATION_INTENT:GITHUB_DRAFT_"):
        return "trusted_controller_service:draft_ledger_orchestrator"
    if selector.startswith("MUTATION_INTENT_CONSUMED:GITHUB_DRAFT_"):
        return "trusted_controller_service:github_draft_mutator"
    if selector.startswith("DRAFT_TRANSITION:"):
        return "trusted_controller_service:github_governance_reader"
    if route.requester_kind == "trusted_controller_service":
        return "trusted_controller_service:pypi_deployment_gate"
    return route.requester_kind


def encoded() -> bytes:
    """Return byte-identical canonical JSON for broker and AST mirrors."""

    return canonical_json_bytes(document())
