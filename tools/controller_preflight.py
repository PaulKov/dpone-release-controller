"""Fail-closed input and activation checks for the controller workflow.

The module intentionally uses only the Python standard library. The first
repository-code step validates untrusted ``workflow_dispatch`` values before
any release/provider mutation or credential-bearing step can run. A pinned,
credential-free checkout precedes it. A checked-in activation policy, an
out-of-band marker, and an exact workflow commit binding are independent
requirements for live mode.

This quarantine revision does not contain a live mutation job.  Passing this
preflight is therefore necessary, but deliberately not sufficient, for future
activation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

POLICY_SCHEMA = "dpone.release-controller.activation.v1"
TARGET_REPOSITORY = "PaulKov/dpone"
TARGET_REPOSITORY_ID = 1_255_975_556
CONTROLLER_REPOSITORY = "PaulKov/dpone-release-controller"
CONTROLLER_REPOSITORY_ID = 1_305_993_853
CONTROLLER_REF = "refs/heads/master"
WORKFLOW_PATH = ".github/workflows/controller-quarantine.yml"
EXPECTED_WORKFLOW_REF = f"{CONTROLLER_REPOSITORY}/{WORKFLOW_PATH}@{CONTROLLER_REF}"
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 3_600

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
_RUN_ID_RE = re.compile(r"[1-9][0-9]*\Z")
_SEMVER_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
_TAG_RE = re.compile(
    rf"v(?:0|[1-9][0-9]*)\."
    rf"(?:0|[1-9][0-9]*)\."
    rf"(?:0|[1-9][0-9]*)"
    rf"(?:-{_SEMVER_IDENTIFIER}(?:\.{_SEMVER_IDENTIFIER})*)?\Z"
)
_POLICY_KEYS = frozenset(
    {
        "schema",
        "state",
        "policy_version",
        "live_mutation_enabled",
        "target_repository",
        "target_repository_id",
        "workflow_path",
        "activation_marker_sha256",
        "reason",
    }
)


class PreflightError(ValueError):
    """Raised when workflow inputs or activation authority are invalid."""


@dataclass(frozen=True)
class ControllerInputs:
    """Canonical, shell-safe controller dispatch values."""

    mode: str
    tag: str
    ttl_seconds: int


@dataclass(frozen=True)
class ActivationPolicy:
    """Strict projection of the checked-in controller activation policy."""

    state: str
    policy_version: int
    live_mutation_enabled: bool
    activation_marker_sha256: str | None
    reason: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ActivationPolicy":
        """Parse a policy without accepting missing or extension fields."""

        keys = frozenset(raw)
        if keys != _POLICY_KEYS:
            missing = sorted(_POLICY_KEYS - keys)
            unexpected = sorted(keys - _POLICY_KEYS)
            raise PreflightError(
                f"activation policy keys mismatch: missing={missing}, unexpected={unexpected}"
            )
        if raw["schema"] != POLICY_SCHEMA:
            raise PreflightError(f"activation policy schema must be {POLICY_SCHEMA!r}")
        if raw["target_repository"] != TARGET_REPOSITORY:
            raise PreflightError(f"target_repository must be {TARGET_REPOSITORY!r}")
        if (
            type(raw["target_repository_id"]) is not int
        ):  # bool is not an accepted integer
            raise PreflightError("target_repository_id must be an integer")
        if raw["target_repository_id"] != TARGET_REPOSITORY_ID:
            raise PreflightError(f"target_repository_id must be {TARGET_REPOSITORY_ID}")
        if raw["workflow_path"] != WORKFLOW_PATH:
            raise PreflightError(f"workflow_path must be {WORKFLOW_PATH!r}")

        state = raw["state"]
        if state not in {"quarantined", "active"}:
            raise PreflightError(
                "activation policy state must be 'quarantined' or 'active'"
            )
        policy_version = raw["policy_version"]
        if type(policy_version) is not int or policy_version < 1:
            raise PreflightError("policy_version must be a positive integer")
        enabled = raw["live_mutation_enabled"]
        if type(enabled) is not bool:
            raise PreflightError("live_mutation_enabled must be a boolean")
        marker_digest = raw["activation_marker_sha256"]
        if marker_digest is not None and (
            not isinstance(marker_digest, str)
            or _SHA256_RE.fullmatch(marker_digest) is None
        ):
            raise PreflightError(
                "activation_marker_sha256 must be null or sha256:<64 lowercase hex>"
            )
        reason = raw["reason"]
        if not isinstance(reason, str) or not reason.strip():
            raise PreflightError("activation policy reason must be a non-empty string")

        if state == "quarantined" and (enabled or marker_digest is not None):
            raise PreflightError(
                "quarantined policy must disable live mutation and omit marker digest"
            )
        if state == "active" and (not enabled or marker_digest is None):
            raise PreflightError(
                "active policy must enable live mutation and bind a marker digest"
            )

        return cls(
            state=state,
            policy_version=policy_version,
            live_mutation_enabled=enabled,
            activation_marker_sha256=marker_digest,
            reason=reason.strip(),
        )


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object while rejecting ambiguous duplicate keys."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PreflightError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _read_activation_policy(path: Path) -> tuple[ActivationPolicy, bytes]:
    """Acquire and validate one immutable byte projection of a policy."""

    try:
        policy_bytes = path.read_bytes()
        raw = json.loads(
            policy_bytes.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PreflightError(f"cannot load activation policy {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise PreflightError("activation policy root must be a JSON object")
    return ActivationPolicy.from_mapping(raw), policy_bytes


def load_activation_policy(path: Path) -> ActivationPolicy:
    """Load and strictly validate a UTF-8 JSON activation policy."""

    policy, _policy_bytes = _read_activation_policy(path)
    return policy


def validate_inputs(
    *, mode: str, tag: str, ttl_seconds: str, run_id: str
) -> ControllerInputs:
    """Validate raw dispatch values and return their canonical projection."""

    if mode not in {"dry-run", "live"}:
        raise PreflightError("mode must be exactly 'dry-run' or 'live'")
    if _RUN_ID_RE.fullmatch(run_id) is None:
        raise PreflightError("GITHUB_RUN_ID must contain a positive decimal integer")
    if not ttl_seconds.isascii() or not ttl_seconds.isdecimal():
        raise PreflightError("ttl_seconds must contain ASCII decimal digits only")
    ttl = int(ttl_seconds)
    if not MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS:
        raise PreflightError(
            f"ttl_seconds must be between {MIN_TTL_SECONDS} and {MAX_TTL_SECONDS}"
        )

    if mode == "live" and not tag:
        raise PreflightError("live mode requires an explicit canonical tag")
    canonical_tag = tag or f"v0.0.0-quarantine.{run_id}"
    if len(canonical_tag) > 128 or _TAG_RE.fullmatch(canonical_tag) is None:
        raise PreflightError("tag must be canonical vSemVer without build metadata")
    return ControllerInputs(mode=mode, tag=canonical_tag, ttl_seconds=ttl)


def require_live_authority(
    policy: ActivationPolicy,
    *,
    activation_marker: str,
    activation_commit_sha: str,
    workflow_sha: str,
) -> None:
    """Require all independent live-activation bindings or reject the run."""

    if (
        policy.state != "active"
        or policy.policy_version != 2
        or not policy.live_mutation_enabled
    ):
        raise PreflightError("live mode is quarantined: active policy v2 is required")
    if not activation_marker:
        raise PreflightError("live mode requires an out-of-band activation marker")
    marker_digest = (
        "sha256:" + hashlib.sha256(activation_marker.encode("utf-8")).hexdigest()
    )
    if marker_digest != policy.activation_marker_sha256:
        raise PreflightError("activation marker does not match the checked-in policy")
    if _COMMIT_SHA_RE.fullmatch(workflow_sha) is None:
        raise PreflightError("GITHUB_SHA must be a full lowercase commit SHA")
    if activation_commit_sha != workflow_sha:
        raise PreflightError("activation commit binding does not match GITHUB_SHA")


def require_workflow_identity(environ: Mapping[str, str]) -> None:
    """Bind every run to the protected controller repository and workflow ref."""

    required = {
        "GITHUB_REPOSITORY": CONTROLLER_REPOSITORY,
        "GITHUB_REPOSITORY_ID": str(CONTROLLER_REPOSITORY_ID),
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": CONTROLLER_REF,
        "GITHUB_WORKFLOW_REF": EXPECTED_WORKFLOW_REF,
    }
    for key, expected in required.items():
        actual = environ.get(key, "")
        if actual != expected:
            raise PreflightError(f"{key} must be exactly {expected!r}")
    workflow_sha = environ.get("GITHUB_SHA", "")
    if _COMMIT_SHA_RE.fullmatch(workflow_sha) is None:
        raise PreflightError("GITHUB_SHA must be a full lowercase commit SHA")


def _evaluate_environment(
    policy_path: Path, environ: Mapping[str, str]
) -> tuple[ControllerInputs, bool, bytes]:
    """Evaluate an environment and retain the exact validated policy bytes."""

    require_workflow_identity(environ)
    inputs = validate_inputs(
        mode=environ.get("INPUT_MODE", ""),
        tag=environ.get("INPUT_TAG", ""),
        ttl_seconds=environ.get("INPUT_TTL_SECONDS", ""),
        run_id=environ.get("GITHUB_RUN_ID", ""),
    )
    policy, policy_bytes = _read_activation_policy(policy_path)
    live_enabled = False
    if inputs.mode == "live":
        require_live_authority(
            policy,
            activation_marker=environ.get("CONTROLLER_ACTIVATION_MARKER", ""),
            activation_commit_sha=environ.get("CONTROLLER_ACTIVATION_COMMIT_SHA", ""),
            workflow_sha=environ.get("GITHUB_SHA", ""),
        )
        live_enabled = True
    return inputs, live_enabled, policy_bytes


def evaluate_environment(
    policy_path: Path, environ: Mapping[str, str]
) -> tuple[ControllerInputs, bool]:
    """Evaluate the complete preflight contract from an explicit environment."""

    inputs, live_enabled, _policy_bytes = _evaluate_environment(policy_path, environ)
    return inputs, live_enabled


def _append_github_outputs(
    path: Path, inputs: ControllerInputs, *, live_enabled: bool
) -> None:
    """Append validated scalar outputs using GitHub's line-oriented protocol."""

    values = {
        "mode": inputs.mode,
        "tag": inputs.tag,
        "ttl_seconds": str(inputs.ttl_seconds),
        "live_enabled": str(live_enabled).lower(),
    }
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        for key, value in values.items():
            stream.write(f"{key}={value}\n")


def _dry_run_receipt(policy_path: Path, environ: Mapping[str, str]) -> dict[str, Any]:
    inputs, live_enabled, policy_bytes = _evaluate_environment(policy_path, environ)
    if inputs.mode != "dry-run" or live_enabled:
        raise PreflightError(
            "receipt command is restricted to non-mutating dry-run mode"
        )
    return {
        "schema": "dpone.release-controller.quarantine-receipt.v1",
        "status": "DRY_RUN_VALIDATED",
        "mode": inputs.mode,
        "tag": inputs.tag,
        "ttl_seconds": inputs.ttl_seconds,
        "live_mutation_enabled": False,
        "controlled_release_provider_mutation_executed": False,
        "policy_sha256": "sha256:" + hashlib.sha256(policy_bytes).hexdigest(),
        "controller_repository": environ.get("GITHUB_REPOSITORY", ""),
        "controller_repository_id": environ.get("GITHUB_REPOSITORY_ID", ""),
        "controller_ref": environ.get("GITHUB_REF", ""),
        "controller_workflow_ref": environ.get("GITHUB_WORKFLOW_REF", ""),
        "workflow_sha": environ.get("GITHUB_SHA", ""),
        "run_id": environ.get("GITHUB_RUN_ID", ""),
    }


def main(argv: list[str] | None = None) -> int:
    """Run the workflow-facing preflight CLI."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "receipt"))
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            inputs, live_enabled = evaluate_environment(args.policy, os.environ)
            if args.github_output is None:
                parser.error("validate requires --github-output")
            _append_github_outputs(
                args.github_output, inputs, live_enabled=live_enabled
            )
        else:
            print(json.dumps(_dry_run_receipt(args.policy, os.environ), sort_keys=True))
    except PreflightError as exc:
        print(f"controller preflight rejected: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
