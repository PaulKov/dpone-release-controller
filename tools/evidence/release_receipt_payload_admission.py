"""Closed admission, governance, candidate, hygiene, and lease payloads."""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_inventory as inventory
from tools.evidence import release_controller_service_activation as service_activation
from tools.evidence.release_receipt_payload_lease import (
    validate_lease as validate_lease,
)

_JOB = frozenset({"github_actions_job"})
_SERVICE = frozenset({"trusted_controller_service"})


def validate_request(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "queue_sequence",
            "pending_count",
            "max_pending_attempts",
            "service_authority_activation_record",
            "service_authority_activation_record_id",
            "service_authority_activation_record_sha256",
            "activated_authority_head",
            "activated_authority_head_record_id",
            "activated_authority_head_record_sha256",
        },
        "REQUEST_ENQUEUED payload",
    )
    _constants(payload, kind="REQUEST_ENQUEUED", state="QUEUED")
    contract.nonnegative_int(payload["queue_sequence"], "queue_sequence")
    contract.bounded_int(
        payload["pending_count"], 1, contract.MAX_PENDING_ATTEMPTS, "pending_count"
    )
    if payload["max_pending_attempts"] != contract.MAX_PENDING_ATTEMPTS:
        raise contract.ReceiptValidationError("max_pending_attempts must be 32")
    _service_authority_genesis(payload)
    return contract.PayloadSemantics("release", False, _JOB)


def validate_governance(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "label",
            "snapshot_sha256",
            "provider_observation_sha256",
            "started_at",
            "completed_at",
            "read_count",
            "attempt_number",
            "pagination_complete",
            "protected_base_sha",
            "tag",
            "tag_ref",
            "tag_object_type",
            "tag_object_sha",
            "peeled_commit_sha",
            "tag_created_by_controller",
            "tag_mutation_performed",
            "tag_ruleset_id",
            "tag_ruleset_version",
            "ruleset_projection_sha256",
            "activation_bypass_actors_sha256",
            "tag_rule_suites_sha256",
            "tag_rule_suite_count",
            "tag_rule_suite_transition_result",
            "tag_ruleset_bypass_observed",
            "required_checks_sha256",
            "actions_policy_observation_sha256",
            "actions_allowed",
            "actions_sha_pinning_required",
            "github_owned_allowed",
            "verified_allowed",
            "patterns_allowed_sha256",
            "immutable_releases_enabled",
        },
        "GOVERNANCE_SNAPSHOT payload",
    )
    label = contract.enum(payload["label"], {"A", "B", "C"}, "label")
    _constants(payload, kind="GOVERNANCE_SNAPSHOT", state=f"GOVERNANCE_{label}")
    contract.digest_fields(
        payload,
        "snapshot_sha256",
        "provider_observation_sha256",
        "ruleset_projection_sha256",
        "activation_bypass_actors_sha256",
        "tag_rule_suites_sha256",
        "required_checks_sha256",
        "actions_policy_observation_sha256",
        "patterns_allowed_sha256",
    )
    contract.ordered_timestamps(
        payload["started_at"], payload["completed_at"], "started_at", "completed_at"
    )
    if payload["read_count"] != 2:
        raise contract.ReceiptValidationError("governance read_count must be 2")
    contract.bounded_int(payload["attempt_number"], 1, 3, "attempt_number")
    contract.positive_fields(
        payload, "tag_ruleset_id", "tag_ruleset_version", "tag_rule_suite_count"
    )
    if (
        contract.boolean(payload["pagination_complete"], "pagination_complete")
        is not True
        or contract.boolean(
            payload["immutable_releases_enabled"], "immutable_releases_enabled"
        )
        is not True
    ):
        raise contract.ReceiptValidationError("governance provider controls must pass")
    for key in ("actions_sha_pinning_required", "github_owned_allowed"):
        if contract.boolean(payload[key], key) is not True:
            raise contract.ReceiptValidationError("Actions policy must pass")
    for key in (
        "verified_allowed",
        "tag_created_by_controller",
        "tag_mutation_performed",
        "tag_ruleset_bypass_observed",
    ):
        if contract.boolean(payload[key], key) is not False:
            raise contract.ReceiptValidationError("tag/provider authority mismatch")
    if (
        payload["actions_allowed"] != "selected"
        or payload["tag_object_type"] != "tag"
        or payload["tag_rule_suite_transition_result"] != "pass"
    ):
        raise contract.ReceiptValidationError("governance provider state mismatch")
    contract.stable_tag(payload["tag"])
    if payload["tag_ref"] != f"refs/tags/{payload['tag']}":
        raise contract.ReceiptValidationError("governance tag ref mismatch")
    for key in ("protected_base_sha", "tag_object_sha", "peeled_commit_sha"):
        contract.git_sha(payload[key], key)
    if payload["tag_object_sha"] == payload["peeled_commit_sha"]:
        raise contract.ReceiptValidationError("governance tag must be annotated")
    if payload["protected_base_sha"] != payload["peeled_commit_sha"]:
        raise contract.ReceiptValidationError(
            "governance protected base/peeled commit mismatch"
        )
    return contract.PayloadSemantics("release", label != "A", _SERVICE)


def validate_candidate(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "candidate_id",
            "candidate_inventory_sha256",
            "candidate_run_id",
            "candidate_run_attempt",
            "candidate_artifact_id",
            "candidate_artifact_digest",
            "candidate_manifest_sha256",
            "file_count",
            "total_bytes",
            "candidate_artifact_raw_zip_sha256",
            "candidate_artifact_raw_zip_size_bytes",
            "candidate_artifact_provider_response_sha256",
            "candidate_artifact_provider_observation_sha256",
            "candidate_artifact_broker_request_id",
            "candidate_artifact_provider_metadata_schema",
            "candidate_artifact_provider_api_version",
            "candidate_artifact_created_at",
            "candidate_artifact_expires_at",
            "candidate_artifact_source_url_expires_at",
            "candidate_artifact_source_url_sha256",
            "candidate_reader_service_identity",
            "candidate_reader_service_version_id",
            "candidate_reader_deployment_observation_record_id",
            "candidate_reader_deployment_observation_record_sha256",
            "candidate_artifact_tag_object_sha",
            "candidate_artifact_policy_blob_sha",
            "candidate_artifact_policy_sha256",
            "candidate_artifact_file_count",
            "candidate_artifact_expanded_bytes",
            "distribution_inventory",
            "distribution_inventory_sha256",
        },
        "CANDIDATE_HANDOFF payload",
    )
    _constants(
        payload,
        kind="CANDIDATE_HANDOFF",
        state="CANDIDATE_HANDOFF",
        candidate_artifact_provider_metadata_schema=(
            "dpone.github-actions-artifact-observation.v1"
        ),
        candidate_artifact_provider_api_version=contract.GITHUB_API_VERSION,
    )
    contract.digest_fields(
        payload,
        "candidate_id",
        "candidate_inventory_sha256",
        "candidate_artifact_digest",
        "candidate_manifest_sha256",
        "candidate_artifact_raw_zip_sha256",
        "candidate_artifact_provider_response_sha256",
        "candidate_artifact_provider_observation_sha256",
        "candidate_artifact_source_url_sha256",
        "candidate_artifact_policy_sha256",
    )
    contract.positive_fields(
        payload,
        "candidate_run_id",
        "candidate_run_attempt",
        "candidate_artifact_id",
        "candidate_artifact_raw_zip_size_bytes",
        "total_bytes",
        "candidate_artifact_expanded_bytes",
    )
    if payload["file_count"] != 25 or payload["candidate_artifact_file_count"] != 25:
        raise contract.ReceiptValidationError(
            "candidate provider file count must be 25"
        )
    if (
        payload["candidate_artifact_digest"]
        != payload["candidate_artifact_raw_zip_sha256"]
    ):
        raise contract.ReceiptValidationError(
            "candidate provider/raw ZIP digest mismatch"
        )
    distributions = inventory.distribution_inventory(payload["distribution_inventory"])
    inventory.require_digest(
        payload["distribution_inventory_sha256"],
        inventory.DISTRIBUTION_SCHEMA,
        distributions,
        "distribution_inventory_sha256",
    )
    contract.request_id(
        payload["candidate_artifact_broker_request_id"],
        "candidate_artifact_broker_request_id",
    )
    contract.opaque(
        payload["candidate_reader_service_identity"],
        "candidate_reader_service_identity",
    )
    contract.opaque(
        payload["candidate_reader_service_version_id"],
        "candidate_reader_service_version_id",
    )
    contract.digest_fields(
        payload,
        "candidate_reader_deployment_observation_record_id",
        "candidate_reader_deployment_observation_record_sha256",
    )
    for key in (
        "candidate_artifact_tag_object_sha",
        "candidate_artifact_policy_blob_sha",
    ):
        contract.git_sha(payload[key], key)
    contract.ordered_timestamps(
        payload["candidate_artifact_created_at"],
        payload["candidate_artifact_expires_at"],
        "candidate_artifact_created_at",
        "candidate_artifact_expires_at",
    )
    contract.ordered_timestamps(
        payload["candidate_artifact_created_at"],
        payload["candidate_artifact_source_url_expires_at"],
        "candidate_artifact_created_at",
        "candidate_artifact_source_url_expires_at",
    )
    return contract.PayloadSemantics("candidate", False, _JOB)


def _service_authority_genesis(payload: Mapping[str, Any]) -> None:
    record = contract.mapping(
        payload["service_authority_activation_record"],
        "service_authority_activation_record",
    )
    head = contract.mapping(
        payload["activated_authority_head"], "activated_authority_head"
    )
    try:
        service_activation.validate_activation(record)
        service_activation.validate_authority_head(head, record)
    except service_activation.ServiceActivationError as exc:
        raise contract.ReceiptValidationError(str(exc)) from exc
    if (
        payload["service_authority_activation_record_id"]
        != service_activation.activation_record_id(record)
        or payload["service_authority_activation_record_sha256"]
        != service_activation.activation_record_sha256(record)
        or payload["activated_authority_head_record_id"]
        != service_activation.authority_head_record_id(head, record)
        or payload["activated_authority_head_record_sha256"]
        != service_activation.authority_head_sha256(head, record)
    ):
        raise contract.ReceiptValidationError(
            "service authority genesis identity mismatch"
        )


def validate_hygiene(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "candidate_id",
            "scanner_service_version_id",
            "policy_sha256",
            "tag_tree_archive_sha256",
            "tag_tree_result_sha256",
            "candidate_archives_inventory_sha256",
            "archive_results_sha256",
            "archive_count",
            "finding_count",
            "decision",
        },
        "TENANT_HYGIENE_VERIFIED payload",
    )
    _constants(
        payload,
        kind="TENANT_HYGIENE_VERIFIED",
        state="TENANT_HYGIENE_VERIFIED",
        archive_count=8,
        finding_count=0,
        decision="CLEAN",
    )
    contract.opaque(payload["scanner_service_version_id"], "scanner_service_version_id")
    contract.digest_fields(
        payload,
        "candidate_id",
        "policy_sha256",
        "tag_tree_archive_sha256",
        "tag_tree_result_sha256",
        "candidate_archives_inventory_sha256",
        "archive_results_sha256",
    )
    return contract.PayloadSemantics("candidate", True, _SERVICE)


def _constants(payload: Mapping[str, Any], **expected: Any) -> None:
    for key, value in expected.items():
        if payload[key] != value or type(payload[key]) is not type(value):
            raise contract.ReceiptValidationError(f"{key} must be exactly {value!r}")
