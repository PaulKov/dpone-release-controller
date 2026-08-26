"""Closed workflow projection of the Commit-A operation codecs.

The operation profile owns network and receipt authority.  This module only
projects that profile into GitHub Actions syntax; it never reconstructs paths,
audiences, request bodies, or receipts from workflow input.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tools.evidence import release_controller_operations as operations
from tools.evidence.release_controller_operation_contract import ActionCodec

FINAL_JOB = "controller-complete"
FINAL_IF = "${{ always() }}"
CONTROLLER_PERMISSIONS = {"contents": "none", "id-token": "write"}
CONTROLLER_RUNNER = "ubuntu-24.04"

_IMMUTABLE_EXPRESSIONS = {
    "candidate_artifact_digest": "${{ inputs.candidate_artifact_digest }}",
    "candidate_artifact_id": "${{ inputs.candidate_artifact_id }}",
    "candidate_run_attempt": "${{ inputs.candidate_run_attempt }}",
    "candidate_run_id": "${{ inputs.candidate_run_id }}",
    "expected_peeled_commit_sha": "${{ inputs.expected_peeled_commit_sha }}",
    "tag": "${{ inputs.tag }}",
}
RECOVERY_OUTPUTS = {
    "resume_phase": "${{ steps.recovery.outputs.resume_phase }}",
}
DISPATCH_OPERATIONS = ("release", "recovery")
RELEASE_IF = "${{ inputs.operation == 'release' }}"
DISPATCH_CONTRACT = {
    "workflow_dispatch": {
        "inputs": {
            "candidate_artifact_digest": {"required": False, "type": "string"},
            "candidate_artifact_id": {"required": False, "type": "string"},
            "candidate_run_attempt": {"required": False, "type": "string"},
            "candidate_run_id": {"required": False, "type": "string"},
            "expected_peeled_commit_sha": {"required": False, "type": "string"},
            "operation": {
                "default": "release",
                "options": list(DISPATCH_OPERATIONS),
                "required": True,
                "type": "choice",
            },
            "tag": {"required": True, "type": "string"},
        }
    }
}

# The single workflow has two executable entrypoints. Recovery is a new run
# and therefore begins with a distinct fenced acquisition. Shared continuation
# jobs merge only through exact predecessor results or a UX-only recovery hint;
# every broker call re-derives current ledger state before any mutation.
JOB_NEEDS = {
    "admit": (),
    "governance-a": ("admit",),
    "candidate-import": ("governance-a",),
    "lease-acquire": ("candidate-import",),
    "recovery-lease-acquire": (),
    "recovery": ("recovery-lease-acquire",),
    "lease-renew": ("lease-acquire", "recovery-lease-acquire"),
    "tenant-hygiene": ("lease-acquire", "recovery"),
    "attest-create": ("tenant-hygiene",),
    "attest-verify": ("attest-create",),
    "bundle-verify": ("attest-verify",),
    "draft-stage": ("bundle-verify",),
    "governance-b": ("draft-stage",),
    "authorize": ("governance-b",),
    "pypi-recovery-observe": ("recovery",),
    "pypi-prepare": ("authorize", "pypi-recovery-observe"),
    "pypi-publish": ("pypi-prepare",),
    "pypi-observe": ("pypi-publish",),
    "github-publish-intent": ("pypi-observe", "recovery"),
    "github-publish": ("github-publish-intent",),
    "github-publish-observe": ("github-publish",),
    "github-verify": ("github-publish-observe",),
    "governance-c": ("github-verify", "recovery"),
    "close": ("governance-c",),
    "cancel": ("lease-acquire", "close"),
    "controller-complete": (
        "cancel",
        "close",
        "lease-renew",
        "recovery",
    ),
}

_SEQUENTIAL_IF = {
    job: f"${{{{ needs.{dependencies[0]}.result == 'success' }}}}"
    for job, dependencies in JOB_NEEDS.items()
    if len(dependencies) == 1
}
JOB_IF = {
    **_SEQUENTIAL_IF,
    "admit": RELEASE_IF,
    "recovery-lease-acquire": "${{ inputs.operation == 'recovery' }}",
    "recovery": (
        "${{ inputs.operation == 'recovery' && "
        "needs.recovery-lease-acquire.result == 'success' }}"
    ),
    "lease-renew": (
        "${{ always() && ((inputs.operation == 'release' && "
        "needs.lease-acquire.result == 'success') || "
        "(inputs.operation == 'recovery' && "
        "needs.recovery-lease-acquire.result == 'success')) }}"
    ),
    "tenant-hygiene": (
        "${{ always() && ((inputs.operation == 'release' && "
        "needs.lease-acquire.result == 'success') || "
        "(inputs.operation == 'recovery' && needs.recovery.result == 'success' && "
        "needs.recovery.outputs.resume_phase == 'LEASED_RESTART')) }}"
    ),
    "pypi-recovery-observe": (
        "${{ inputs.operation == 'recovery' && needs.recovery.result == 'success' && "
        "needs.recovery.outputs.resume_phase == 'PYPI_RECOVERY' }}"
    ),
    "pypi-prepare": (
        "${{ always() && (needs.authorize.result == 'success' || "
        "needs.pypi-recovery-observe.result == 'success') }}"
    ),
    "github-publish-intent": (
        "${{ always() && (needs.pypi-observe.result == 'success' || "
        "(inputs.operation == 'recovery' && needs.recovery.result == 'success' && "
        "needs.recovery.outputs.resume_phase == 'PYPI_VERIFIED')) }}"
    ),
    "governance-c": (
        "${{ always() && (needs.github-verify.result == 'success' || "
        "(inputs.operation == 'recovery' && needs.recovery.result == 'success' && "
        "needs.recovery.outputs.resume_phase == 'GITHUB_IMMUTABLE')) }}"
    ),
    "cancel": (
        "${{ always() && inputs.operation == 'release' && "
        "needs.lease-acquire.result == 'success' && "
        "needs.close.result != 'success' }}"
    ),
    "controller-complete": FINAL_IF,
}


@dataclass(frozen=True, slots=True)
class WorkflowJobContract:
    """One controller job projected from one operation profile."""

    operation_id: str
    environment: str
    timeout_minutes: int
    codecs: tuple[ActionCodec, ...]


def required_jobs() -> dict[str, WorkflowJobContract]:
    """Return every controller-workflow operation; runtime lives in target."""

    result: dict[str, WorkflowJobContract] = {}
    for profile in operations.OPERATIONS:
        if profile.workflow_owner == "target":
            continue
        if profile.job_name in result:
            raise RuntimeError("one workflow job owns multiple operation profiles")
        result[profile.job_name] = WorkflowJobContract(
            operation_id=profile.operation_id,
            environment=profile.environment,
            timeout_minutes=(profile.absolute_timeout_seconds + 59) // 60,
            codecs=operations.ACTION_CODECS_BY_OPERATION[profile.operation_id],
        )
    if set(JOB_NEEDS) != set(result) or set(JOB_IF) != set(result):
        raise RuntimeError("workflow topology/operation profile set drift")
    return result


def expected_step(codec: ActionCodec, action_commit: str) -> dict[str, Any]:
    """Render one exact controller-workflow action step."""

    values: dict[str, str] = {}
    for item in codec.inputs:
        if item.literal is not None:
            values[item.name] = item.literal
        elif item.source == "IMMUTABLE_SELECTOR":
            values[item.name] = _IMMUTABLE_EXPRESSIONS[item.name]
        else:
            raise RuntimeError(f"unrenderable controller input source: {item.source}")
    return {
        "id": codec.step_id,
        "uses": codec.action_ref.replace("<A>", action_commit),
        "with": values,
    }


def expected_outputs(job_name: str) -> dict[str, str]:
    """Return the sole cross-job output surface, explicitly UX-only."""

    return dict(RECOVERY_OUTPUTS) if job_name == "recovery" else {}


def expected_if(operation_id: str) -> str:
    """Return the exact state-safe condition for one operation job."""

    job_name = "lease-renew" if operation_id == "lease-sentinel" else operation_id
    return JOB_IF[job_name]


def expected_needs(job_name: str, operation_id: str) -> tuple[str, ...]:
    """Return the exact release/recovery DAG predecessors."""

    if job_name != operation_id and not (
        job_name == "lease-renew" and operation_id == "lease-sentinel"
    ):
        raise RuntimeError("operation/job topology alias is not reviewed")
    return JOB_NEEDS[job_name]
