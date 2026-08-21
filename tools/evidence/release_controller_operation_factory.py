"""Shared closed constants and constructors for Commit-A operation contracts."""

from __future__ import annotations

import re

from tools.evidence.release_controller_operation_contract import (
    ActionCodec,
    ActionInput,
    OrderedCall,
    ServerTransactionPlan,
)
from tools.evidence.release_controller_service_roles import role_for_selector

SCHEMA = "dpone.release-controller-operation-profile.v2"
SCHEMA_VERSION = 2
BROKER_ACTION_REF = "PaulKov/dpone-release-controller/actions/broker-call@<A>"
LEASE_ACTION_REF = "PaulKov/dpone-release-controller/actions/lease-sentinel@<A>"
PYPI_ACTION_REF = "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33"
CANDIDATE_ADMIT_PATH = "/v1/releases/candidate/admit"
LOCAL_CANDIDATE_VERIFIER = "local:release-candidate-deep-verification"
PYPI_ACTION = PYPI_ACTION_REF
MATERIALIZATION_INPUTS = (
    "candidate_artifact_digest",
    "candidate_artifact_id",
    "candidate_run_attempt",
    "candidate_run_id",
    "expected_peeled_commit_sha",
    "operation",
    "tag",
)

TOKEN_RE = re.compile(r"[a-z][a-z0-9-]{1,63}\Z", re.ASCII)
PHASE_RE = re.compile(r"[A-Z][A-Z0-9_]{1,127}\Z", re.ASCII)
SCHEMA_RE = re.compile(r"dpone\.[a-z0-9.-]+\.v[1-9][0-9]*\Z", re.ASCII)
INPUT_RE = re.compile(r"[a-z][a-z0-9_-]{1,63}\Z", re.ASCII)
CARDINALITIES = frozenset(
    {"EXACT_COUNT", "ONCE", "UNTIL_TERMINAL", "WHILE_LEASE_ACTIVE"}
)
INPUT_TYPES = frozenset(
    {
        "BOOLEAN_LITERAL",
        "DIGEST",
        "GIT_SHA",
        "OPERATION_ID",
        "PACKAGE_DIRECTORY",
        "POSITIVE_INTEGER",
        "SEMVER_TAG",
    }
)
INPUT_SOURCES = frozenset(
    {
        "IMMUTABLE_SELECTOR",
        "UX_HINT",
        "WORKFLOW_LITERAL",
    }
)
FORBIDDEN_INPUTS = frozenset(
    {
        "audience",
        "authorization",
        "base_url",
        "body",
        "broker_url",
        "capability",
        "endpoint",
        "envelope",
        "headers",
        "hostname",
        "method",
        "origin",
        "path",
        "receipt",
        "request_json",
        "token",
        "url",
    }
)


def schema(slug: str) -> str:
    """Return a canonical operation-local schema identifier."""

    return f"dpone.release-controller-{slug}.v1"


def once(
    phase: str,
    method: str,
    path: str,
    audience: str | None,
    request_schema: str,
    response_schema: str,
    effect: str,
    *receipt_kinds: str,
    receipt_selectors: tuple[str, ...] = (),
    receipt_states: tuple[str, ...] = (),
    repeat_count: int = 1,
    authority_selectors: tuple[str, ...] | None = None,
    server_service_role: str | None = None,
    response_mode: str = "CANONICAL",
) -> OrderedCall:
    """Build a deterministic one-shot or exact-count call."""

    return OrderedCall(
        phase=phase,
        method=method,
        path=path,
        audience=audience,
        request_schema=request_schema,
        response_schema=None if response_mode == "NONE" else response_schema,
        response_mode=response_mode,
        effect=effect,
        receipt_kinds=tuple(sorted(receipt_kinds)),
        receipt_selectors=tuple(receipt_selectors),
        receipt_states=tuple(receipt_states),
        cardinality="ONCE" if repeat_count == 1 else "EXACT_COUNT",
        interval_seconds=None,
        repeat_count=repeat_count,
        authority_selectors=tuple(
            receipt_selectors if authority_selectors is None else authority_selectors
        ),
        server_service_role=server_service_role,
    )


def server_transaction(
    call: OrderedCall, *pre_transaction_reads: str
) -> ServerTransactionPlan:
    """Bind a server requery call to one post-read fenced ledger transaction."""

    return ServerTransactionPlan(
        phase=call.phase,
        pre_transaction_reads=tuple(pre_transaction_reads),
        atomic_receipt_selectors=call.receipt_selectors,
        receipt_producer_roles=tuple(
            (selector, role_for_selector(selector))
            for selector in call.receipt_selectors
        ),
        provider_io_inside_transaction=False,
        durable_commit_count=1,
        state_recheck_before_commit="RELEASE_ATTEMPT_LEASE_FENCE_AND_HEAD",
    )


def action_input(
    name: str,
    value_type: str,
    source: str = "IMMUTABLE_SELECTOR",
    literal: str | None = None,
) -> ActionInput:
    """Build one closed workflow input descriptor."""

    return ActionInput(name, value_type, source, literal)


def selector_codec(
    operation_id: str,
    step_id: str,
    phases: tuple[str, ...],
    *,
    extra_inputs: tuple[ActionInput, ...] = (),
) -> ActionCodec:
    """Build the selector-only broker-call action surface."""

    inputs = (
        action_input("operation", "OPERATION_ID", "WORKFLOW_LITERAL", operation_id),
        action_input("tag", "SEMVER_TAG"),
        *extra_inputs,
    )
    return ActionCodec(
        operation_id,
        step_id,
        phases,
        BROKER_ACTION_REF,
        tuple(sorted(inputs, key=lambda value: value.name.encode("ascii"))),
        (),
        "NONE",
    )


def materialization_codec(
    operation_id: str, step_id: str, phases: tuple[str, ...]
) -> ActionCodec:
    """Build the sole candidate-import selector surface."""

    types = {
        "candidate_artifact_digest": "DIGEST",
        "candidate_artifact_id": "POSITIVE_INTEGER",
        "candidate_run_attempt": "POSITIVE_INTEGER",
        "candidate_run_id": "POSITIVE_INTEGER",
        "expected_peeled_commit_sha": "GIT_SHA",
        "operation": "OPERATION_ID",
        "tag": "SEMVER_TAG",
    }
    return ActionCodec(
        operation_id,
        step_id,
        phases,
        BROKER_ACTION_REF,
        tuple(
            action_input(
                name,
                types[name],
                "WORKFLOW_LITERAL" if name == "operation" else "IMMUTABLE_SELECTOR",
                operation_id if name == "operation" else None,
            )
            for name in MATERIALIZATION_INPUTS
        ),
        (),
        "NONE",
    )
