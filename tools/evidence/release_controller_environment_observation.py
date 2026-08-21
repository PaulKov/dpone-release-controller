"""Normalized, provider-observed controller environment contract for A0."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from tools.evidence import release_receipt_contract as receipt

SCHEMA = "dpone.release-controller-environment-observation.v1"
SCHEMA_VERSION = 1
PROVIDER_API_VERSION = "2026-03-10"
ENVIRONMENT_NAMES = ("release-attest", "pypi", "github-release")
GATE_APP_ROLE = "pypi_deployment_gate"
GATE_APP_SLUG = "dpone-release-controller-pypi-gate"
MAX_OBSERVATION_AGE = timedelta(minutes=5)
MAX_FUTURE_SKEW = timedelta(seconds=30)


class EnvironmentObservationError(ValueError):
    """A normalized provider observation is incomplete, stale, or unsafe."""


def verify(
    value: Mapping[str, Any],
    *,
    gate_app_id: int,
    gate_installation_id: int,
    now: datetime,
) -> None:
    """Validate the exact three-environment A0 projection."""

    _exact(
        value,
        {
            "schema",
            "schema_version",
            "provider_api_version",
            "controller_ref",
            "controller_tag_name",
            "observed_at",
            "controller_environments",
        },
        "environment observation",
    )
    _constant(value, "schema", SCHEMA)
    _constant(value, "schema_version", SCHEMA_VERSION)
    _constant(value, "provider_api_version", PROVIDER_API_VERSION)
    _stable_controller_ref(value)
    observed = _timestamp(value["observed_at"], "observed_at")
    current = _utc(now)
    if observed < current - MAX_OBSERVATION_AGE or observed > current + MAX_FUTURE_SKEW:
        raise EnvironmentObservationError("environment observation is stale or future")
    environments = _mapping(value["controller_environments"], "controller_environments")
    _exact(environments, set(ENVIRONMENT_NAMES), "controller_environments")
    environment_ids: set[int] = set()
    policy_ids: set[int] = set()
    for name in ENVIRONMENT_NAMES:
        environment = _environment(
            environments[name],
            name=name,
            tag_name=value["controller_tag_name"],
            observed_at=value["observed_at"],
            gate_app_id=gate_app_id,
            gate_installation_id=gate_installation_id,
        )
        _unique(environment_ids, environment["environment_id"], "environment_id")
        _unique(
            policy_ids,
            environment["deployment_policies"][0]["id"],
            "deployment policy id",
        )


def _environment(
    raw: Any,
    *,
    name: str,
    tag_name: str,
    observed_at: str,
    gate_app_id: int,
    gate_installation_id: int,
) -> Mapping[str, Any]:
    value = _mapping(raw, name)
    _exact(
        value,
        {
            "environment_id",
            "environment_name",
            "can_admins_bypass",
            "deployment_branch_policy",
            "deployment_policy_count",
            "deployment_policies",
            "protection_rule_count",
            "protection_rules",
            "secret_count",
            "variable_count",
            "provider_observation_sha256",
            "deployment_policy_observation_sha256",
            "zero_secrets_variables_observation_sha256",
            "observed_at",
            *({"activation_evidence"} if name == "pypi" else set()),
        },
        f"environment {name}",
    )
    _positive(value["environment_id"], f"{name}.environment_id")
    _constant(value, "environment_name", name)
    _constant(value, "can_admins_bypass", False)
    _constant(value, "deployment_policy_count", 1)
    _constant(value, "secret_count", 0)
    _constant(value, "variable_count", 0)
    branch_policy = _mapping(
        value["deployment_branch_policy"], "deployment_branch_policy"
    )
    _exact(
        branch_policy,
        {"protected_branches", "custom_branch_policies"},
        "deployment_branch_policy",
    )
    _constant(branch_policy, "protected_branches", False)
    _constant(branch_policy, "custom_branch_policies", True)
    policies = _list(value["deployment_policies"], "deployment_policies")
    if len(policies) != 1:
        raise EnvironmentObservationError("exactly one deployment policy is required")
    policy = _mapping(policies[0], "deployment policy")
    _exact(policy, {"id", "name", "type"}, "deployment policy")
    _positive(policy["id"], "deployment policy id")
    _constant(policy, "name", tag_name)
    _constant(policy, "type", "tag")
    for key in (
        "provider_observation_sha256",
        "deployment_policy_observation_sha256",
        "zero_secrets_variables_observation_sha256",
    ):
        _digest(value[key], f"{name}.{key}")
    _constant(value, "observed_at", observed_at)
    _rules(value, name, gate_app_id, gate_installation_id)
    return value


def _rules(
    value: Mapping[str, Any], name: str, gate_app_id: int, gate_installation_id: int
) -> None:
    rules = _list(value["protection_rules"], f"{name}.protection_rules")
    expected_count = 1 if name == "pypi" else 0
    _constant(value, "protection_rule_count", expected_count)
    if len(rules) != expected_count:
        raise EnvironmentObservationError("environment protection rule count mismatch")
    if name != "pypi":
        return
    rule = _mapping(rules[0], "pypi protection rule")
    _exact(
        rule,
        {
            "id",
            "type",
            "app_role",
            "app_id",
            "installation_id",
            "app_slug",
            "enabled",
            "accepted_action",
        },
        "pypi protection rule",
    )
    _positive(rule["id"], "pypi protection rule id")
    for key, expected in {
        "type": "custom",
        "app_role": GATE_APP_ROLE,
        "app_id": gate_app_id,
        "installation_id": gate_installation_id,
        "app_slug": GATE_APP_SLUG,
        "enabled": True,
        "accepted_action": "requested",
    }.items():
        _constant(rule, key, expected)
    evidence = _mapping(value["activation_evidence"], "pypi activation_evidence")
    _exact(
        evidence,
        {
            "provider_observation_sha256",
            "public_preview_feature_evidence_sha256",
            "fail_closed_readiness_evidence_sha256",
        },
        "pypi activation_evidence",
    )
    for key, digest in evidence.items():
        _digest(digest, f"activation_evidence.{key}")
    if evidence["provider_observation_sha256"] != value["provider_observation_sha256"]:
        raise EnvironmentObservationError("pypi provider evidence cross-bind mismatch")


def _stable_controller_ref(value: Mapping[str, Any]) -> None:
    ref = value["controller_ref"]
    if not isinstance(ref, str) or not ref.startswith("refs/tags/"):
        raise EnvironmentObservationError("controller_ref must be a tag")
    tag = ref.removeprefix("refs/tags/")
    try:
        receipt.stable_tag(tag)
    except receipt.ReceiptValidationError as exc:
        raise EnvironmentObservationError(str(exc)) from exc
    _constant(value, "controller_tag_name", tag)


def _positive(value: Any, name: str) -> int:
    if type(value) is not int or not 1 <= value <= receipt.MAX_SAFE_INTEGER:
        raise EnvironmentObservationError(f"{name} must be a positive JS-safe integer")
    return value


def _digest(value: Any, name: str) -> None:
    try:
        receipt.digest(value, name)
    except receipt.ReceiptValidationError as exc:
        raise EnvironmentObservationError(str(exc)) from exc


def _timestamp(value: Any, name: str) -> datetime:
    try:
        return receipt.timestamp(value, name)
    except receipt.ReceiptValidationError as exc:
        raise EnvironmentObservationError(str(exc)) from exc


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise EnvironmentObservationError("clock must be timezone-aware UTC")
    return value.astimezone(timezone.utc)


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise EnvironmentObservationError(f"{name} must be an object")
    return value


def _list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise EnvironmentObservationError(f"{name} must be an array")
    return value


def _exact(value: Mapping[str, Any], keys: set[str], name: str) -> None:
    if set(value) != keys:
        raise EnvironmentObservationError(f"{name} keys are not exact")


def _constant(value: Mapping[str, Any], key: str, expected: Any) -> None:
    if value[key] != expected or type(value[key]) is not type(expected):
        raise EnvironmentObservationError(f"{key} must be exactly {expected!r}")


def _unique(values: set[int], value: int, name: str) -> None:
    if value in values:
        raise EnvironmentObservationError(f"duplicate {name}")
    values.add(value)
