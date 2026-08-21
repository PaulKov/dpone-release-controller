"""Closed one-use provider mutation intents and consumption bindings."""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence.release_canonical import sha256_id
from tools.evidence import release_receipt_inventory as inventory

SUBJECT_DOMAIN = "dpone.release.mutation-subject.v2"
OPERATIONS = frozenset(
    {
        "ATTESTATION_CREATE",
        "GITHUB_DRAFT_CREATE",
        "GITHUB_DRAFT_ASSET_UPLOAD",
        "GITHUB_DRAFT_UPDATE",
        "PYPI_DEPLOYMENT_APPROVE",
        "PYPI_DEPLOYMENT_REJECT",
        "PYPI_FILE_UPLOAD_SET",
        "GITHUB_RELEASE_PUBLISH",
    }
)
CANDIDATE_OPERATIONS = frozenset(
    {
        "ATTESTATION_CREATE",
        "GITHUB_DRAFT_CREATE",
        "GITHUB_DRAFT_ASSET_UPLOAD",
        "GITHUB_DRAFT_UPDATE",
    }
)
SERVICE_ISSUED_OPERATIONS = frozenset(
    {
        "ATTESTATION_CREATE",
        "GITHUB_RELEASE_PUBLISH",
    }
)


def validate_intent(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Validate one durable intent before a capability can be issued."""

    operation = contract.enum(payload.get("operation"), OPERATIONS, "operation")
    scope = "candidate" if operation in CANDIDATE_OPERATIONS else "authorization"
    scope_key = f"{scope}_id"
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "intent_id",
            "lease_id",
            "fencing_token",
            "attempt_id",
            "operation",
            "subject",
            "subject_identity_sha256",
            "capability_ttl_seconds",
            "one_use",
            scope_key,
        },
        "MUTATION_INTENT payload",
    )
    _constant(payload, "kind", "MUTATION_INTENT")
    _constant(payload, "state", "MUTATION_INTENT_RECORDED")
    _constant(payload, "capability_ttl_seconds", contract.CAPABILITY_TTL_SECONDS)
    _constant(payload, "one_use", True)
    contract.digest_fields(payload, "intent_id", "lease_id", "attempt_id", scope_key)
    contract.positive_int(payload["fencing_token"], "fencing_token")
    subject = contract.mapping(payload["subject"], "intent.subject")
    _validate_subject(operation, subject)
    expected = subject_identity_sha256(operation, subject)
    if payload["subject_identity_sha256"] != expected:
        raise contract.ReceiptValidationError("intent subject digest mismatch")
    producer = (
        "trusted_controller_service"
        if operation in SERVICE_ISSUED_OPERATIONS
        or operation.startswith(("PYPI_DEPLOYMENT_", "GITHUB_DRAFT_"))
        else "github_actions_job"
    )
    return contract.PayloadSemantics(scope, True, frozenset({producer}))


def subject_identity_sha256(operation: str, subject: Mapping[str, Any]) -> str:
    """Derive the only accepted operation/subject identity."""

    return sha256_id(SUBJECT_DOMAIN, {"operation": operation, "subject": dict(subject)})


def _validate_subject(operation: str, subject: Mapping[str, Any]) -> None:
    validators = {
        "ATTESTATION_CREATE": _attestation,
        "GITHUB_DRAFT_CREATE": _draft_create,
        "GITHUB_DRAFT_ASSET_UPLOAD": _draft_asset,
        "GITHUB_DRAFT_UPDATE": _draft_update,
        "PYPI_DEPLOYMENT_APPROVE": _deployment,
        "PYPI_DEPLOYMENT_REJECT": _deployment,
        "PYPI_FILE_UPLOAD_SET": _pypi_upload_set,
        "GITHUB_RELEASE_PUBLISH": _release_publish,
    }
    validators[operation](subject)


def _attestation(value: Mapping[str, Any]) -> None:
    contract.exact_keys(value, {"candidate_id", "subject_manifest_sha256"}, "subject")
    contract.digest_fields(value, "candidate_id", "subject_manifest_sha256")


def _draft_create(value: Mapping[str, Any]) -> None:
    contract.exact_keys(
        value, {"candidate_id", "tag", "release_body_sha256"}, "subject"
    )
    contract.digest_fields(value, "candidate_id", "release_body_sha256")
    contract.stable_tag(value["tag"])


def _draft_asset(value: Mapping[str, Any]) -> None:
    contract.exact_keys(
        value,
        {"candidate_id", "release_id", "name", "size_bytes", "sha256"},
        "subject",
    )
    contract.digest_fields(value, "candidate_id", "sha256")
    contract.positive_fields(value, "release_id", "size_bytes")
    contract.filename(value["name"], "subject.name")


def _draft_update(value: Mapping[str, Any]) -> None:
    contract.exact_keys(
        value,
        {"candidate_id", "release_id", "release_body_sha256", "asset_inventory_sha256"},
        "subject",
    )
    contract.digest_fields(
        value, "candidate_id", "release_body_sha256", "asset_inventory_sha256"
    )
    contract.positive_int(value["release_id"], "subject.release_id")


def _deployment(value: Mapping[str, Any]) -> None:
    contract.exact_keys(
        value,
        {
            "authorization_id",
            "candidate_id",
            "gate_request_id",
            "gate_request_provider_observation_sha256",
            "tag",
            "ref",
            "deployment_id",
            "environment_name",
            "environment_id",
            "protection_rule_id",
            "gate_app_id",
            "gate_installation_id",
            "app_slug",
            "controller_repository_id",
            "controller_workflow_id",
            "controller_workflow_sha",
            "controller_run_id",
            "controller_run_attempt",
            "expected_file_count",
            "expected_file_inventory_sha256",
        },
        "subject",
    )
    contract.digest_fields(
        value,
        "authorization_id",
        "candidate_id",
        "gate_request_id",
        "gate_request_provider_observation_sha256",
        "expected_file_inventory_sha256",
    )
    contract.positive_fields(value, "deployment_id", "environment_id")
    contract.positive_fields(
        value,
        "protection_rule_id",
        "gate_app_id",
        "gate_installation_id",
        "controller_repository_id",
        "controller_workflow_id",
        "controller_run_id",
        "controller_run_attempt",
    )
    if value["controller_repository_id"] != contract.CONTROLLER_REPOSITORY_ID:
        raise contract.ReceiptValidationError("subject controller repository mismatch")
    if value["environment_name"] != "pypi":
        raise contract.ReceiptValidationError("subject gate environment mismatch")
    if value["app_slug"] != "dpone-release-controller-pypi-gate":
        raise contract.ReceiptValidationError("subject gate app slug mismatch")
    contract.stable_tag(value["tag"])
    if value["ref"] != f"refs/tags/{value['tag']}":
        raise contract.ReceiptValidationError("subject gate tag/ref mismatch")
    contract.git_sha(value["controller_workflow_sha"], "controller_workflow_sha")
    if (
        value["expected_file_count"] != 8
        or type(value["expected_file_count"]) is not int
    ):
        raise contract.ReceiptValidationError("subject.expected_file_count must be 8")


def _release_publish(value: Mapping[str, Any]) -> None:
    contract.exact_keys(
        value,
        {
            "authorization_id",
            "release_id",
            "release_body_sha256",
            "public_bundle_manifest_sha256",
            "asset_inventory_sha256",
        },
        "subject",
    )
    contract.digest_fields(
        value,
        "authorization_id",
        "release_body_sha256",
        "public_bundle_manifest_sha256",
        "asset_inventory_sha256",
    )
    contract.positive_int(value["release_id"], "subject.release_id")


def _pypi_upload_set(value: Mapping[str, Any]) -> None:
    contract.exact_keys(
        value,
        {
            "authorization_id",
            "candidate_id",
            "deployment_id",
            "environment_id",
            "candidate_file_inventory_sha256",
            "upload_file_count",
            "upload_file_inventory",
            "upload_file_inventory_sha256",
        },
        "subject",
    )
    contract.digest_fields(
        value,
        "authorization_id",
        "candidate_id",
        "candidate_file_inventory_sha256",
        "upload_file_inventory_sha256",
    )
    contract.positive_fields(value, "deployment_id", "environment_id")
    count = contract.bounded_int(
        value["upload_file_count"], 1, 8, "subject.upload_file_count"
    )
    files = inventory.distribution_subset_inventory(value["upload_file_inventory"])
    if len(files) != count:
        raise contract.ReceiptValidationError("subject upload file count mismatch")
    inventory.require_digest(
        value["upload_file_inventory_sha256"],
        inventory.DISTRIBUTION_SCHEMA,
        files,
        "subject.upload_file_inventory_sha256",
    )


def _constant(value: Mapping[str, Any], key: str, expected: Any) -> None:
    if value[key] != expected or type(value[key]) is not type(expected):
        raise contract.ReceiptValidationError(f"{key} must be exactly {expected!r}")
