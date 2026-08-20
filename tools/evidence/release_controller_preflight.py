"""Dependency-free preflight for the production release-controller graph.

Dispatch values are selectors only. Live activation requires a fresh broker
A0/A1 proof obtained with this exact run's OIDC identity. Configuration is a
locator and never manufactures authority.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from tools.evidence import release_controller_activation as activation
from tools.evidence import release_controller_activation_proof as activation_proof
from tools.evidence import release_public_closure_hold as public_closure_hold
from tools.evidence.release_canonical import MAX_SAFE_INTEGER

ProductionPreflightError = activation.ProductionPreflightError
ActivationContract = activation.ActivationContract
load_activation_contract = activation.load_activation_contract

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_POSITIVE_INTEGER_RE = re.compile(r"[1-9][0-9]*\Z")
_TAG_RE = re.compile(
    r"v(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\Z"
)
_CONTROLLER_TAG_REF_RE = re.compile(
    r"refs/tags/v(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\Z"
)


@dataclass(frozen=True, slots=True)
class DispatchSelectors:
    """Canonical projection of the seven frozen workflow inputs."""

    mode: str
    tag: str
    expected_peeled_commit_sha: str
    candidate_run_id: int
    candidate_run_attempt: int
    candidate_artifact_id: int
    candidate_artifact_digest: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, str]) -> "DispatchSelectors":
        """Reject optional overrides, Unicode digits, zero IDs and loose tags."""

        expected = {
            "mode",
            "tag",
            "expected_peeled_commit_sha",
            "candidate_run_id",
            "candidate_run_attempt",
            "candidate_artifact_id",
            "candidate_artifact_digest",
        }
        if set(raw) != expected:
            raise ProductionPreflightError("dispatch selector keys are not exact")
        if raw["mode"] not in {"dry-run", "live"}:
            raise ProductionPreflightError("mode must be exactly dry-run or live")
        if len(raw["tag"]) > 128 or _TAG_RE.fullmatch(raw["tag"]) is None:
            raise ProductionPreflightError(
                "tag must be canonical stable vMAJOR.MINOR.PATCH"
            )
        commit = raw["expected_peeled_commit_sha"]
        if _COMMIT_RE.fullmatch(commit) is None:
            raise ProductionPreflightError(
                "expected_peeled_commit_sha must be a full lowercase SHA"
            )
        parsed: dict[str, int] = {}
        for name in (
            "candidate_run_id",
            "candidate_run_attempt",
            "candidate_artifact_id",
        ):
            if _POSITIVE_INTEGER_RE.fullmatch(raw[name]) is None:
                raise ProductionPreflightError(
                    f"{name} must be a positive ASCII integer"
                )
            parsed[name] = int(raw[name])
            if parsed[name] > MAX_SAFE_INTEGER:
                raise ProductionPreflightError(f"{name} exceeds the JS-safe range")
        digest = raw["candidate_artifact_digest"]
        if _SHA256_RE.fullmatch(digest) is None:
            raise ProductionPreflightError(
                "candidate_artifact_digest must be sha256:<64 lowercase hex>"
            )
        return cls(
            mode=raw["mode"],
            tag=raw["tag"],
            expected_peeled_commit_sha=commit,
            candidate_run_id=parsed["candidate_run_id"],
            candidate_run_attempt=parsed["candidate_run_attempt"],
            candidate_artifact_id=parsed["candidate_artifact_id"],
            candidate_artifact_digest=digest,
        )

    def as_json(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "tag": self.tag,
            "expected_peeled_commit_sha": self.expected_peeled_commit_sha,
            "candidate_run_id": self.candidate_run_id,
            "candidate_run_attempt": self.candidate_run_attempt,
            "candidate_artifact_id": self.candidate_artifact_id,
            "candidate_artifact_digest": self.candidate_artifact_digest,
        }


@dataclass(frozen=True, slots=True)
class ControllerRunIdentity:
    """Exact GitHub-hosted controller workflow/run identity."""

    repository_id: int
    ref: str
    workflow_ref: str
    workflow_sha: str
    run_id: int
    run_attempt: int


def require_controller_identity(environ: Mapping[str, str]) -> ControllerRunIdentity:
    """Bind execution to an A0-resolvable immutable controller tag."""

    required = {
        "GITHUB_REPOSITORY": activation.CONTROLLER_REPOSITORY,
        "GITHUB_REPOSITORY_ID": str(activation.CONTROLLER_REPOSITORY_ID),
        "GITHUB_REPOSITORY_OWNER_ID": str(activation.REPOSITORY_OWNER_ID),
        "GITHUB_EVENT_NAME": "workflow_dispatch",
    }
    for name, expected in required.items():
        if environ.get(name, "") != expected:
            raise ProductionPreflightError(f"{name} must be exactly {expected!r}")
    ref = environ.get("GITHUB_REF", "")
    if _CONTROLLER_TAG_REF_RE.fullmatch(ref) is None:
        raise ProductionPreflightError("GITHUB_REF must be a stable controller tag ref")
    workflow_ref = environ.get("GITHUB_WORKFLOW_REF", "")
    expected_workflow_ref = (
        f"{activation.CONTROLLER_REPOSITORY}/"
        f"{activation.CONTROLLER_WORKFLOW_PATH}@{ref}"
    )
    if workflow_ref != expected_workflow_ref:
        raise ProductionPreflightError(
            "GITHUB_WORKFLOW_REF must bind the controller tag"
        )
    workflow_sha = environ.get("GITHUB_SHA", "")
    if _COMMIT_RE.fullmatch(workflow_sha) is None:
        raise ProductionPreflightError("GITHUB_SHA must be a full lowercase SHA")
    run_values: dict[str, int] = {}
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        value = environ.get(name, "")
        if _POSITIVE_INTEGER_RE.fullmatch(value) is None:
            raise ProductionPreflightError(f"{name} must be a positive ASCII integer")
        run_values[name] = int(value)
        if run_values[name] > MAX_SAFE_INTEGER:
            raise ProductionPreflightError(f"{name} exceeds the JS-safe range")
    return ControllerRunIdentity(
        repository_id=activation.CONTROLLER_REPOSITORY_ID,
        ref=ref,
        workflow_ref=workflow_ref,
        workflow_sha=workflow_sha,
        run_id=run_values["GITHUB_RUN_ID"],
        run_attempt=run_values["GITHUB_RUN_ATTEMPT"],
    )


def require_live_activation(
    contract: ActivationContract,
    *,
    controller: ControllerRunIdentity,
    client: activation_proof.BrokerActivationClient | None,
    clock: activation_proof.Clock = activation_proof.SYSTEM_UTC_CLOCK,
) -> activation_proof.ActivationProof:
    """Obtain and validate fresh external authority; no local flag can replace it."""

    try:
        public_closure_hold.reject()
    except public_closure_hold.PublicClosureContractHoldError as exc:
        raise ProductionPreflightError(str(exc)) from exc
    if contract.credential_broker_url is None or client is None:
        raise ProductionPreflightError("fresh broker activation proof is unavailable")
    exchange = client.request_activation_proof(
        endpoint=contract.credential_broker_url,
        path=contract.activation_proof_path,
        audience=activation_proof.AUDIENCE,
        environment=activation_proof.ENVIRONMENT,
        request_bytes=activation_proof.request_bytes(),
    )
    try:
        return activation_proof.verify_exchange(
            exchange,
            expected=activation_proof.ExpectedControllerRun(
                repository_id=controller.repository_id,
                ref=controller.ref,
                workflow_ref=controller.workflow_ref,
                workflow_sha=controller.workflow_sha,
                run_id=controller.run_id,
                run_attempt=controller.run_attempt,
            ),
            clock=clock,
        )
    except activation_proof.ActivationProofError as exc:
        raise ProductionPreflightError(str(exc)) from exc


def evaluate(
    *,
    config_path: Path,
    selectors: Mapping[str, str],
    environ: Mapping[str, str],
    activation_client: activation_proof.BrokerActivationClient | None = None,
    clock: activation_proof.Clock = activation_proof.SYSTEM_UTC_CLOCK,
) -> tuple[
    DispatchSelectors,
    ActivationContract,
    ControllerRunIdentity,
    activation_proof.ActivationProof | None,
]:
    """Evaluate all local pre-capability controls in deterministic order."""

    parsed = DispatchSelectors.from_mapping(selectors)
    contract = load_activation_contract(config_path)
    controller = require_controller_identity(environ)
    proof = None
    if parsed.mode == "live":
        proof = require_live_activation(
            contract,
            controller=controller,
            client=activation_client,
            clock=clock,
        )
    return parsed, contract, controller, proof


def _selectors_from_environment(environ: Mapping[str, str]) -> Mapping[str, str]:
    return {
        "mode": environ.get("INPUT_MODE", ""),
        "tag": environ.get("INPUT_TAG", ""),
        "expected_peeled_commit_sha": environ.get(
            "INPUT_EXPECTED_PEELED_COMMIT_SHA", ""
        ),
        "candidate_run_id": environ.get("INPUT_CANDIDATE_RUN_ID", ""),
        "candidate_run_attempt": environ.get("INPUT_CANDIDATE_RUN_ATTEMPT", ""),
        "candidate_artifact_id": environ.get("INPUT_CANDIDATE_ARTIFACT_ID", ""),
        "candidate_artifact_digest": environ.get("INPUT_CANDIDATE_ARTIFACT_DIGEST", ""),
    }


def _write_outputs(
    path: Path,
    selectors: DispatchSelectors,
    proof: activation_proof.ActivationProof | None,
) -> None:
    values = {**selectors.as_json(), "live": str(selectors.mode == "live").lower()}
    if proof is not None:
        values.update(
            {
                "activation_proof_sha256": proof.proof_sha256,
                "activation_provisioned_record_id": proof.provisioned_record_id,
                "activation_record_id": proof.activated_record_id,
            }
        )
    with path.open("a", encoding="utf-8") as stream:
        for key, value in values.items():
            stream.write(f"{key}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    selectors, contract, controller, proof = evaluate(
        config_path=args.config,
        selectors=_selectors_from_environment(os.environ),
        environ=os.environ,
    )
    result = {
        "schema": "dpone.release-controller-preflight.v2",
        "schema_version": 2,
        "status": "PASS",
        "decision": "DRY_RUN" if selectors.mode == "dry-run" else "ADMIT_LOCAL",
        "selectors": selectors.as_json(),
        "activation": {
            "locator_ready": contract.locator_ready,
            "proof_sha256": None if proof is None else proof.proof_sha256,
            "config_sha256": contract.raw_sha256,
        },
        "controller_workflow_sha": controller.workflow_sha,
    }
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(encoded, end="")
    else:
        args.output.write_text(encoded, encoding="utf-8")
    if args.github_output is not None:
        _write_outputs(args.github_output, selectors, proof)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
