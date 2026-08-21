"""Fresh, operation-bound authority guard for private provider effects.

The guard contains no bearer or portable capability bytes.  It proves that the
permission-scoped service, its WORM-mirrored deployment observation, and the
global activated-authority head were rechecked immediately before consuming a
one-use mutation intent.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence.release_canonical import sha256_id
from tools.evidence.release_controller_service_roles import role_for_selector

SCHEMA = "dpone.release-authority-effect-guard.v1"
SCHEMA_VERSION = 1
DIGEST_DOMAIN = SCHEMA
CAPABILITY_BINDING_DOMAIN = "dpone.release-capability-authority-binding.v1"
MAX_TTL_SECONDS = 60

SERVICE_MUTATOR_OPERATIONS = frozenset(
    {
        "ATTESTATION_CREATE",
        "GITHUB_DRAFT_ASSET_UPLOAD",
        "GITHUB_DRAFT_CREATE",
        "GITHUB_DRAFT_UPDATE",
        "GITHUB_RELEASE_PUBLISH",
        "PYPI_DEPLOYMENT_APPROVE",
        "PYPI_DEPLOYMENT_REJECT",
    }
)
GITHUB_ACTION_OPERATIONS = frozenset({"PYPI_FILE_UPLOAD_SET"})
GUARDED_OPERATIONS = SERVICE_MUTATOR_OPERATIONS | GITHUB_ACTION_OPERATIONS


class AuthorityGuardError(ValueError):
    """A fresh effect-authority guard or capability binding is invalid."""


def build(
    *,
    operation: str,
    intent_id: str,
    intent_subject_sha256: str,
    lease_id: str,
    fencing_token: int,
    attempt_id: str,
    producer: Mapping[str, Any],
    provider_observation_sha256: str,
    provider_observation_record_id: str,
    provider_observation_record_sha256: str,
    observed_at: str,
    accepted_at: str,
    expires_at: str,
    github_consumer: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one closed guard from server-authenticated authority projections."""

    variant = (
        "GITHUB_ACTION_DISPATCH"
        if operation in GITHUB_ACTION_OPERATIONS
        else "SERVICE_MUTATOR_EFFECT"
    )
    guard = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "guard_variant": variant,
        "operation": operation,
        "intent_id": intent_id,
        "intent_subject_sha256": intent_subject_sha256,
        "lease_id": lease_id,
        "fencing_token": fencing_token,
        "attempt_id": attempt_id,
        "service_role": producer["service_role"],
        "service_authority_role": producer["service_authority_role"],
        "service_identity": producer["service_identity"],
        "service_version_id": producer["service_version_id"],
        "deployment_observation_sha256": producer["deployment_observation_sha256"],
        "deployment_observation_record_id": producer[
            "deployment_observation_record_id"
        ],
        "deployment_observation_record_sha256": producer[
            "deployment_observation_record_sha256"
        ],
        "service_authority_inventory_sha256": producer[
            "service_authority_inventory_sha256"
        ],
        "activated_authority_head_record_id": producer[
            "activated_authority_head_record_id"
        ],
        "activated_authority_head_record_sha256": producer[
            "activated_authority_head_record_sha256"
        ],
        "activated_authority_head_generation": producer[
            "activated_authority_head_generation"
        ],
        "provider_observation_sha256": provider_observation_sha256,
        "provider_observation_record_id": provider_observation_record_id,
        "provider_observation_record_sha256": (provider_observation_record_sha256),
        "observed_at": observed_at,
        "accepted_at": accepted_at,
        "expires_at": expires_at,
    }
    if variant == "GITHUB_ACTION_DISPATCH":
        if github_consumer is None:
            raise AuthorityGuardError("GitHub action guard lacks its consumer")
        guard["github_consumer"] = _github_consumer_projection(github_consumer)
    elif github_consumer is not None:
        raise AuthorityGuardError("service mutator guard has a GitHub consumer")
    validate(guard)
    return guard


def validate(value: Any) -> Mapping[str, Any]:
    """Validate one exact guard and its bounded provider-observation window."""

    guard = _mapping(value, "authority guard")
    variant = guard.get("guard_variant")
    if variant not in {"SERVICE_MUTATOR_EFFECT", "GITHUB_ACTION_DISPATCH"}:
        raise AuthorityGuardError("authority guard variant is not closed")
    extra = {"github_consumer"} if variant == "GITHUB_ACTION_DISPATCH" else set()
    _keys(
        guard,
        {
            "schema",
            "schema_version",
            "guard_variant",
            "operation",
            "intent_id",
            "intent_subject_sha256",
            "lease_id",
            "fencing_token",
            "attempt_id",
            "service_role",
            "service_authority_role",
            "service_identity",
            "service_version_id",
            "deployment_observation_sha256",
            "deployment_observation_record_id",
            "deployment_observation_record_sha256",
            "service_authority_inventory_sha256",
            "activated_authority_head_record_id",
            "activated_authority_head_record_sha256",
            "activated_authority_head_generation",
            "provider_observation_sha256",
            "provider_observation_record_id",
            "provider_observation_record_sha256",
            "observed_at",
            "accepted_at",
            "expires_at",
            *extra,
        },
        "authority guard",
    )
    if guard["schema"] != SCHEMA or guard["schema_version"] != 1:
        raise AuthorityGuardError("authority guard schema/version mismatch")
    operation = guard["operation"]
    if operation not in GUARDED_OPERATIONS:
        raise AuthorityGuardError("authority guard operation is not closed")
    expected_role = (
        "ledger_orchestrator"
        if operation in GITHUB_ACTION_OPERATIONS
        else role_for_selector(f"MUTATION_INTENT_CONSUMED:{operation}")
    )
    if guard["service_role"] != expected_role or (
        operation in GITHUB_ACTION_OPERATIONS
    ) != (variant == "GITHUB_ACTION_DISPATCH"):
        raise AuthorityGuardError("authority guard service role mismatch")
    if variant == "GITHUB_ACTION_DISPATCH":
        _validate_github_consumer(guard["github_consumer"])
    for key in (
        "service_role",
        "service_authority_role",
        "service_identity",
        "service_version_id",
    ):
        _opaque(guard[key], key)
    for key in (
        "intent_id",
        "intent_subject_sha256",
        "lease_id",
        "attempt_id",
        "deployment_observation_sha256",
        "deployment_observation_record_id",
        "deployment_observation_record_sha256",
        "service_authority_inventory_sha256",
        "activated_authority_head_record_id",
        "activated_authority_head_record_sha256",
        "provider_observation_sha256",
        "provider_observation_record_id",
        "provider_observation_record_sha256",
    ):
        _digest(guard[key], key)
    _positive(guard["fencing_token"], "fencing_token")
    if guard["activated_authority_head_generation"] != 1:
        raise AuthorityGuardError("authority guard v1 head generation must be one")
    observed = _timestamp(guard["observed_at"], "observed_at")
    accepted = _timestamp(guard["accepted_at"], "accepted_at")
    expires = _timestamp(guard["expires_at"], "expires_at")
    if (
        not observed <= accepted < expires
        or accepted - observed > timedelta(seconds=MAX_TTL_SECONDS)
        or expires - observed > timedelta(seconds=MAX_TTL_SECONDS)
        or expires - accepted > timedelta(seconds=MAX_TTL_SECONDS)
    ):
        raise AuthorityGuardError("authority guard time window is invalid")
    return guard


def digest(value: Any) -> str:
    """Return a domain-separated digest of one validated guard."""

    guard = validate(value)
    return sha256_id(DIGEST_DOMAIN, guard)


def bind_to_consumption(
    guard: Mapping[str, Any],
    payload: Mapping[str, Any],
    producer: Mapping[str, Any],
) -> None:
    """Cross-bind the guard to the consumed intent and authenticated service."""

    validate(guard)
    payload_fields = (
        "operation",
        "intent_id",
        "intent_subject_sha256",
        "lease_id",
        "fencing_token",
        "attempt_id",
    )
    authorizer_fields = (
        "service_role",
        "service_authority_role",
        "service_identity",
        "service_version_id",
        "deployment_observation_sha256",
        "deployment_observation_record_id",
        "deployment_observation_record_sha256",
        "service_authority_inventory_sha256",
        "activated_authority_head_record_id",
        "activated_authority_head_record_sha256",
        "activated_authority_head_generation",
    )
    authorizer_matches = (
        True
        if guard["guard_variant"] == "GITHUB_ACTION_DISPATCH"
        else all(guard[key] == producer[key] for key in authorizer_fields)
    )
    consumer_matches = (
        guard.get("github_consumer") == _github_consumer_projection(producer)
        if guard["guard_variant"] == "GITHUB_ACTION_DISPATCH"
        else producer.get("kind") == "trusted_controller_service"
    )
    if (
        any(guard[key] != payload[key] for key in payload_fields)
        or not authorizer_matches
        or not consumer_matches
    ):
        raise AuthorityGuardError("authority guard consumption binding mismatch")


def _github_consumer_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = (
        "repository_id",
        "workflow_id",
        "workflow_path",
        "workflow_sha",
        "run_id",
        "run_attempt",
        "job_name",
        "environment",
        "audience",
        "check_run_id",
        "request_id",
        "oidc_jti_sha256",
    )
    return {key: value[key] for key in fields}


def _validate_github_consumer(value: Any) -> None:
    consumer = _mapping(value, "authority guard GitHub consumer")
    _keys(
        consumer,
        {
            "repository_id",
            "workflow_id",
            "workflow_path",
            "workflow_sha",
            "run_id",
            "run_attempt",
            "job_name",
            "environment",
            "audience",
            "check_run_id",
            "request_id",
            "oidc_jti_sha256",
        },
        "authority guard GitHub consumer",
    )
    for key in (
        "repository_id",
        "workflow_id",
        "run_id",
        "run_attempt",
        "check_run_id",
    ):
        _positive(consumer[key], f"github_consumer.{key}")
    _git_sha(consumer["workflow_sha"], "github_consumer.workflow_sha")
    if consumer["workflow_path"] != contract.CONTROLLER_WORKFLOW_PATH:
        raise AuthorityGuardError("GitHub consumer workflow path mismatch")
    for key in ("job_name", "environment", "audience"):
        _opaque(consumer[key], f"github_consumer.{key}")
    try:
        contract.request_id(consumer["request_id"], "github_consumer.request_id")
    except contract.ReceiptValidationError as exc:
        raise AuthorityGuardError(str(exc)) from exc
    _digest(consumer["oidc_jti_sha256"], "github_consumer.oidc_jti_sha256")


def capability_binding_sha256(payload: Mapping[str, Any]) -> str:
    """Bind an opaque one-use capability hash to its exact fresh guard."""

    projection = {
        "operation": payload["operation"],
        "intent_id": payload["intent_id"],
        "intent_subject_sha256": payload["intent_subject_sha256"],
        "lease_id": payload["lease_id"],
        "fencing_token": payload["fencing_token"],
        "attempt_id": payload["attempt_id"],
        "capability_sha256": payload["capability_sha256"],
        "authority_guard_sha256": payload["authority_guard_sha256"],
    }
    return sha256_id(CAPABILITY_BINDING_DOMAIN, projection)


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise AuthorityGuardError(f"{name} must be an object")
    return value


def _keys(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise AuthorityGuardError(f"{name} keys are not exact")


def _digest(value: Any, name: str) -> None:
    try:
        contract.digest(value, name)
    except contract.ReceiptValidationError as exc:
        raise AuthorityGuardError(str(exc)) from exc


def _opaque(value: Any, name: str) -> None:
    try:
        contract.opaque(value, name)
    except contract.ReceiptValidationError as exc:
        raise AuthorityGuardError(str(exc)) from exc


def _git_sha(value: Any, name: str) -> None:
    try:
        contract.git_sha(value, name)
    except contract.ReceiptValidationError as exc:
        raise AuthorityGuardError(str(exc)) from exc


def _positive(value: Any, name: str) -> None:
    try:
        contract.positive_int(value, name)
    except contract.ReceiptValidationError as exc:
        raise AuthorityGuardError(str(exc)) from exc


def _timestamp(value: Any, name: str) -> Any:
    try:
        return contract.timestamp(value, name)
    except contract.ReceiptValidationError as exc:
        raise AuthorityGuardError(str(exc)) from exc
