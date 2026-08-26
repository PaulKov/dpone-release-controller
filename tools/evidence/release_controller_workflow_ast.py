"""Fail-closed AST verification for controller and target runtime workflows."""

from __future__ import annotations

import re
from typing import Any, Mapping

from tools.evidence.release_controller_operation_factory import FORBIDDEN_INPUTS
from tools.evidence.release_controller_workflow_contract import (
    CONTROLLER_PERMISSIONS,
    CONTROLLER_RUNNER,
    DISPATCH_CONTRACT,
    FINAL_JOB,
    expected_if,
    expected_needs,
    expected_outputs,
    expected_step,
    required_jobs,
)

_SHA_RE = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_PRE_LEASE_JOBS = frozenset(
    {
        "admit",
        "candidate-import",
        "governance-a",
        "lease-acquire",
        "recovery-lease-acquire",
    }
)
_LEASE_ROOTS = frozenset({"lease-acquire", "recovery-lease-acquire"})


class WorkflowAstError(ValueError):
    """A workflow can escape the frozen Commit-A operation contract."""


def verify(workflow: Mapping[str, Any], *, broker_action_commit: str) -> None:
    """Verify exact controller jobs, operation codecs, dataflow, and lease DAG."""

    _commit(broker_action_commit)
    _exact(workflow, {"jobs", "name", "on", "permissions"}, "workflow")
    if (
        workflow["name"] != "Release controller"
        or workflow["on"] != DISPATCH_CONTRACT
        or workflow["permissions"] != {}
    ):
        raise WorkflowAstError("controller workflow dispatch/default authority drift")
    jobs = _mapping(workflow.get("jobs"), "jobs")
    contracts = required_jobs()
    expected_names = set(contracts)
    if set(jobs) != expected_names:
        missing = sorted(expected_names - set(jobs))
        extra = sorted(set(jobs) - expected_names)
        raise WorkflowAstError(
            f"controller job set mismatch: missing={missing} extra={extra}"
        )
    for job_name, contract in contracts.items():
        job = _mapping(jobs[job_name], f"job {job_name}")
        expected_keys = {
            "environment",
            "if",
            "name",
            "needs",
            "permissions",
            "runs-on",
            "steps",
            "timeout-minutes",
        }
        outputs = expected_outputs(job_name)
        if outputs:
            expected_keys.add("outputs")
        _exact(job, expected_keys, f"job {job_name}")
        if (
            job["name"] != job_name
            or job["environment"] != contract.environment
            or job["permissions"] != CONTROLLER_PERMISSIONS
            or job["runs-on"] != CONTROLLER_RUNNER
            or job["timeout-minutes"] != contract.timeout_minutes
            or job["if"] != expected_if(contract.operation_id)
        ):
            raise WorkflowAstError(f"job {job_name!r} identity or permissions drift")
        if _needs(job, job_name) != expected_needs(job_name, contract.operation_id):
            raise WorkflowAstError(f"job {job_name!r} dependency contract mismatch")
        if job.get("outputs", {}) != outputs:
            raise WorkflowAstError("cross-job outputs are not exact UX hints")
        expected_steps = [
            expected_step(codec, broker_action_commit) for codec in contract.codecs
        ]
        if job["steps"] != expected_steps:
            raise WorkflowAstError(f"job {job_name!r} action codec/order mismatch")
        _forbidden_names(job, f"job {job_name}")
    _verify_lease_topology(jobs, contracts)


def verify_runtime(
    workflow: Mapping[str, Any],
    *,
    target_workflow_path: str,
    target_workflow_commit_sha: str,
    controller_action_commit_sha: str,
    controller_action_metadata_blob_sha: str,
    controller_action_bundle_sha256: str,
) -> None:
    """Reject every runtime promotion graph until its public gate is frozen."""

    del (
        workflow,
        target_workflow_path,
        target_workflow_commit_sha,
        controller_action_commit_sha,
        controller_action_metadata_blob_sha,
        controller_action_bundle_sha256,
    )
    raise WorkflowAstError("PUBLIC_CLOSURE_CONTRACT_NOT_FROZEN")


def _verify_lease_topology(
    jobs: Mapping[str, Any], contracts: Mapping[str, Any]
) -> None:
    if (
        set(_needs(_mapping(jobs["lease-renew"], "lease-renew"), "lease-renew"))
        != _LEASE_ROOTS
    ):
        raise WorkflowAstError("lease sentinel must cover both exact acquisitions")
    for job_name in contracts:
        if job_name in _PRE_LEASE_JOBS:
            continue
        ancestors = _ancestors(jobs, job_name)
        if not _LEASE_ROOTS.intersection(ancestors):
            raise WorkflowAstError(
                f"leased job {job_name!r} lacks release/recovery acquire ancestry"
            )
        if job_name not in {"lease-renew", FINAL_JOB} and "lease-renew" in ancestors:
            raise WorkflowAstError("main release DAG waits on the lease sentinel")


def _needs(job: Mapping[str, Any], name: str) -> tuple[str, ...]:
    raw = job.get("needs", [])
    values = [raw] if isinstance(raw, str) else raw
    if not isinstance(values, list) or any(
        not isinstance(value, str) or not value for value in values
    ):
        raise WorkflowAstError(f"job {name!r} needs are invalid")
    if len(set(values)) != len(values):
        raise WorkflowAstError(f"job {name!r} has duplicate dependencies")
    return tuple(values)


def _ancestors(jobs: Mapping[str, Any], name: str) -> set[str]:
    result: set[str] = set()
    visiting: set[str] = set()

    def visit(current: str) -> None:
        if current in visiting:
            raise WorkflowAstError("workflow dependency cycle")
        visiting.add(current)
        for dependency in _needs(_mapping(jobs.get(current), current), current):
            if dependency not in jobs:
                raise WorkflowAstError(f"unknown workflow dependency {dependency!r}")
            if dependency not in result:
                result.add(dependency)
                visit(dependency)
        visiting.remove(current)

    visit(name)
    return result


def _forbidden_names(value: Any, name: str, *, allow_path: bool = False) -> None:
    """Reject caller-selected authority aliases anywhere in action/job input."""

    if isinstance(value, dict):
        normalized = {str(key).lower().replace("-", "_") for key in value}
        forbidden = normalized.intersection(FORBIDDEN_INPUTS)
        upload_step = str(value.get("uses", "")).startswith("actions/upload-artifact@")
        if allow_path or upload_step:
            forbidden.discard("path")
        if forbidden:
            raise WorkflowAstError(f"{name} exposes forbidden input aliases")
        for key, child in value.items():
            _forbidden_names(
                child,
                name,
                allow_path=upload_step and key == "with",
            )
    elif isinstance(value, list):
        for child in value:
            _forbidden_names(child, name)


def _commit(value: str) -> None:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise WorkflowAstError("controller action commit/blob must be a full SHA")


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise WorkflowAstError(f"{name} must be an object")
    return value


def _exact(value: Mapping[str, Any], keys: set[str], name: str) -> None:
    if set(value) != keys:
        raise WorkflowAstError(f"{name} keys are not exact")
