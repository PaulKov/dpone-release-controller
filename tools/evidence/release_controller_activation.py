"""Strict checked-in activation contract for release-controller v2."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from tools.evidence import release_controller_action_bundle as action_bundle
from tools.evidence import release_controller_provider_profile as provider_profile
from tools.evidence import release_pypi_limits
from tools.evidence import release_public_closure_hold as public_closure

SCHEMA = "dpone.release-controller.activation.v2"
SCHEMA_VERSION = 2
CONTROLLER_REPOSITORY = "PaulKov/dpone-release-controller"
CONTROLLER_REPOSITORY_ID = 1_305_993_853
REPOSITORY_OWNER_ID = 74_862_786
CONTROLLER_WORKFLOW_PATH = ".github/workflows/release-controller.yml"
TARGET_PROTECTED_BASE_REF = "refs/heads/master"
TARGET_REPOSITORY = "PaulKov/dpone"
TARGET_REPOSITORY_ID = 1_255_975_556
CANDIDATE_WORKFLOW_PATH = ".github/workflows/release.yml"
POLICY_PATH = ".agents/policy/github-branch-protection.yml"
CANDIDATE_HANDOFF_SCHEMA_SHA256 = (
    "sha256:b4245cfadeab72fc104e5723a3188169ac0c6a705d190e00140ea0e1d10103c3"
)
PROJECTS = (
    "apache-airflow-providers-dpone",
    "dpone",
    "dpone-airflow-pack",
    "dpone-native-accel",
)
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")

AUDIENCES = {
    "ledger_write": "dpone-release-controller-ledger-write",
    "candidate_read": "dpone-release-controller-candidate-read",
    "governance_read": "dpone-release-controller-governance-read",
    "attest": "dpone-release-controller-attest",
    "pypi": "dpone-release-controller-pypi",
    "github_release": "dpone-release-controller-github-release",
    "runtime_closure_read": "dpone-runtime-controller-closure-read",
}

EXECUTION_REF_PROFILE = {
    "authority": "A0_PROVISIONED_RECORD",
    "ref_type": "tag",
    "object_type": "tag",
    "stable_semver_required": True,
    "protected": True,
    "bypass_allowed": False,
    "controller_mutation_allowed": False,
    "default_branch_workflow_path": {
        "ref": TARGET_PROTECTED_BASE_REF,
        "required_until": "CLOSED_OR_ABORTED",
        "provider_recheck_required": True,
    },
}


class ProductionPreflightError(ValueError):
    """The dispatch or activation boundary is not exact and closed."""


@dataclass(frozen=True, slots=True)
class ActivationContract:
    """Immutable local locator; only a fresh broker A0/A1 proof activates."""

    credential_broker_url: str | None
    activation_proof_path: str
    raw_sha256: str

    @property
    def locator_ready(self) -> bool:
        return self.credential_broker_url is not None


def load_activation_contract(path: Path) -> ActivationContract:
    """Read, close and validate all activation/provider values."""

    try:
        data = path.read_bytes()
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProductionPreflightError(
            f"cannot load activation contract: {exc}"
        ) from exc
    raw = _mapping(raw, "activation contract")
    _keys(
        raw,
        {
            "schema",
            "schema_version",
            "controller",
            "target",
            "candidate_handoff",
            "publication",
            "required_provider_profile",
            "credential_broker",
            "ledger",
            "closure_projection",
            "reason",
        },
        "activation contract",
    )
    if raw["schema"] != SCHEMA or raw["schema_version"] != SCHEMA_VERSION:
        raise ProductionPreflightError("activation schema/version mismatch")
    _fixed(
        raw["controller"],
        {
            "repository": CONTROLLER_REPOSITORY,
            "repository_id": CONTROLLER_REPOSITORY_ID,
            "repository_owner_id": REPOSITORY_OWNER_ID,
            "workflow_path": CONTROLLER_WORKFLOW_PATH,
            "execution_ref": EXECUTION_REF_PROFILE,
            "action_bundle": {
                "authority": "A0_PROVISIONED_RECORD",
                "repository": action_bundle.REPOSITORY,
                "repository_id": action_bundle.REPOSITORY_ID,
                "commit_field": "controller_action_commit_sha",
                "metadata_path": action_bundle.RUNTIME_CLOSURE_METADATA_PATH,
                "metadata_blob_field": "controller_action_metadata_blob_sha",
                "bundle_digest_field": "controller_action_bundle_sha256",
                "executable_paths": list(action_bundle.EXECUTABLE_PATHS),
                "controller_allowed_action_patterns": list(
                    action_bundle.CONTROLLER_ALLOWED_ACTION_PATTERNS
                ),
                "target_allowed_action_patterns": list(
                    action_bundle.TARGET_ALLOWED_ACTION_PATTERNS
                ),
                "workflow_commit_must_differ": True,
            },
        },
        "controller",
    )
    _fixed(
        raw["target"],
        {
            "repository": TARGET_REPOSITORY,
            "repository_id": TARGET_REPOSITORY_ID,
            "repository_owner_id": REPOSITORY_OWNER_ID,
            "protected_base_ref": TARGET_PROTECTED_BASE_REF,
            "candidate_workflow_path": CANDIDATE_WORKFLOW_PATH,
            "governance_policy_path": POLICY_PATH,
        },
        "target",
    )
    _fixed(
        raw["candidate_handoff"],
        {
            "artifact_name": "release-candidates",
            "manifest_path": "candidate-handoff-v2.json",
            "manifest_schema": "dpone.release-candidate-handoff.v2",
            "manifest_schema_sha256": CANDIDATE_HANDOFF_SCHEMA_SHA256,
            "expected_file_count": 25,
            "max_artifact_files": 25,
            "max_artifact_total_bytes": 805_306_368,
            "max_artifact_member_bytes": 268_435_456,
            "max_distribution_file_bytes": release_pypi_limits.MAX_PYPI_FILE_BYTES,
            "max_distribution_total_bytes": release_pypi_limits.MAX_PYPI_TOTAL_BYTES,
        },
        "candidate_handoff",
    )
    _validate_publication(_mapping(raw["publication"], "publication"))
    _fixed(
        raw["required_provider_profile"],
        provider_profile.REQUIRED_PROVIDER_PROFILE,
        "required_provider_profile",
    )
    broker = _mapping(raw["credential_broker"], "credential_broker")
    _validate_broker(broker)
    _validate_ledger(_mapping(raw["ledger"], "ledger"))
    _fixed(
        raw["closure_projection"],
        {
            "status": public_closure.STATUS,
            "reason_code": public_closure.REASON_CODE,
            "public_projection_enabled": public_closure.PUBLIC_PROJECTION_ENABLED,
            "runtime_gate_enabled": public_closure.RUNTIME_GATE_ENABLED,
        },
        "closure_projection",
    )
    if not isinstance(raw["reason"], str) or not raw["reason"].strip():
        raise ProductionPreflightError("activation reason must be non-empty")
    return ActivationContract(
        credential_broker_url=broker["endpoint"],
        activation_proof_path=broker["activation_proof_path"],
        raw_sha256="sha256:" + hashlib.sha256(data).hexdigest(),
    )


def _validate_publication(raw: Mapping[str, Any]) -> None:
    _keys(
        raw,
        {
            "projects",
            "trusted_publisher_owner",
            "trusted_publisher_repository",
            "trusted_publisher_workflow",
            "trusted_publisher_environment",
            "github_release_environment",
            "attestation_environment",
        },
        "publication",
    )
    if tuple(raw["projects"]) != PROJECTS:
        raise ProductionPreflightError("publication project order mismatch")
    expected = {
        "trusted_publisher_owner": "PaulKov",
        "trusted_publisher_repository": "dpone-release-controller",
        "trusted_publisher_workflow": "release-controller.yml",
        "trusted_publisher_environment": "pypi",
        "github_release_environment": "github-release",
        "attestation_environment": "release-attest",
    }
    if any(raw[key] != value for key, value in expected.items()):
        raise ProductionPreflightError("publication identity mismatch")


def _validate_broker(raw: Mapping[str, Any]) -> None:
    _keys(
        raw,
        {
            "endpoint",
            "activation_proof_path",
            "activation_request_schema",
            "activation_response_schema",
            "capability_ttl_seconds",
            "audiences",
        },
        "credential_broker",
    )
    if (
        raw["activation_proof_path"] != "/v1/activation/proof"
        or raw["activation_request_schema"]
        != "dpone.release-broker-activation-proof-request.v1"
        or raw["activation_response_schema"]
        != "dpone.release-broker-activation-proof.v1"
        or raw["capability_ttl_seconds"] != 60
    ):
        raise ProductionPreflightError("credential broker proof contract mismatch")
    endpoint = raw["endpoint"]
    if endpoint is not None:
        if not isinstance(endpoint, str):
            raise ProductionPreflightError(
                "credential broker endpoint must be string or null"
            )
        parsed = urllib.parse.urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in {None, 443}
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ProductionPreflightError(
                "credential broker endpoint must be closed HTTPS"
            )
    if _mapping(raw["audiences"], "audiences") != AUDIENCES:
        raise ProductionPreflightError("credential broker audience contract mismatch")


def _validate_ledger(raw: Mapping[str, Any]) -> None:
    _keys(
        raw,
        {
            "store_id",
            "lease_ttl_seconds",
            "lease_renew_interval_seconds",
            "max_pending_attempts",
            "mirror_retention_days",
            "writer_can_change_retention",
        },
        "ledger",
    )
    if (
        raw["store_id"]
        != "b2://dpone-release-evidence-v1?object_lock=compliance&retention_days=2557"
        or raw["lease_ttl_seconds"] != 300
        or raw["lease_renew_interval_seconds"] != 45
        or raw["max_pending_attempts"] != 32
        or raw["mirror_retention_days"] != 2557
        or raw["writer_can_change_retention"] is not False
    ):
        raise ProductionPreflightError("ledger CAS, lease or WORM contract mismatch")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProductionPreflightError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ProductionPreflightError(f"{name} must be an object")
    return value


def _keys(raw: Mapping[str, Any], expected: set[str], name: str) -> None:
    if set(raw) != expected:
        raise ProductionPreflightError(
            f"{name} keys mismatch: missing={sorted(expected - set(raw))}, "
            f"unexpected={sorted(set(raw) - expected)}"
        )


def _fixed(value: Any, expected: Mapping[str, Any], name: str) -> None:
    if _mapping(value, name) != expected:
        raise ProductionPreflightError(f"fixed {name} contract mismatch")
