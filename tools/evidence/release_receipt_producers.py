"""Closed requester and broker-committer identities for receipt v2."""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_controller_routes as routes
from tools.evidence import release_receipt_service_producers as service_producers


def validate_producer(value: Any, payload: Mapping[str, Any]) -> str:
    """Validate the requester identity and return its closed union tag."""

    producer = contract.mapping(value, "producer")
    kind = contract.enum(
        producer.get("kind"),
        {
            "github_actions_job",
            "trusted_controller_service",
            "maintainer_incident_action",
            "release_authority_broker_timer",
        },
        "producer.kind",
    )
    if kind == "github_actions_job":
        _github_job(producer, payload)
    elif kind == "trusted_controller_service":
        service_producers.validate(producer, payload)
    elif kind == "maintainer_incident_action":
        _incident_actor(producer)
    else:
        _broker_timer(producer, payload)
    return kind


def validate_committer(value: Any) -> None:
    """Require the immutable, activation-bound Cloudflare Worker identity."""

    committer = contract.mapping(value, "committer")
    contract.exact_keys(
        committer,
        {
            "kind",
            "service_identity",
            "cloudflare_account_id",
            "worker_script",
            "worker_version_id",
            "source_sha256",
            "deployment_observation_record_id",
            "deployment_observation_record_sha256",
            "activation_provisioned_record_id",
            "activation_provisioned_digest",
            "activation_record_id",
            "activation_digest",
            "expected_service_authorities_sha256",
            "service_authority_activation_record_id",
            "service_authority_activation_record_sha256",
            "service_authority_inventory_sha256",
            "activated_authority_head_record_id",
            "activated_authority_head_record_sha256",
            "activated_authority_head_generation",
        },
        "committer",
    )
    if committer["kind"] != "release_authority_broker":
        raise contract.ReceiptValidationError("committer kind mismatch")
    for key in ("cloudflare_account_id", "worker_script", "worker_version_id"):
        contract.opaque(committer[key], f"committer.{key}")
    expected_identity = (
        "cloudflare-worker:"
        f"{committer['cloudflare_account_id']}/{committer['worker_script']}"
        f"@{committer['worker_version_id']}"
    )
    if committer["service_identity"] != expected_identity:
        raise contract.ReceiptValidationError(
            "versioned broker service identity mismatch"
        )
    contract.digest_fields(
        committer,
        "source_sha256",
        "deployment_observation_record_id",
        "deployment_observation_record_sha256",
        "activation_provisioned_record_id",
        "activation_provisioned_digest",
        "activation_record_id",
        "activation_digest",
        "expected_service_authorities_sha256",
        "service_authority_activation_record_id",
        "service_authority_activation_record_sha256",
        "service_authority_inventory_sha256",
        "activated_authority_head_record_id",
        "activated_authority_head_record_sha256",
    )
    if committer["activated_authority_head_generation"] != 1:
        raise contract.ReceiptValidationError("committer head generation must be one")


def _github_job(producer: Mapping[str, Any], payload: Mapping[str, Any]) -> None:
    contract.exact_keys(
        producer,
        {
            "kind",
            "repository_id",
            "workflow_id",
            "workflow_path",
            "workflow_sha",
            "run_id",
            "run_attempt",
            "job_name",
            "environment",
            "actor_id",
            "audience",
            "check_run_id",
            "request_id",
            "oidc_claims_sha256",
            "oidc_jti_sha256",
            "provider_job_observation_sha256",
            "provider_api_version",
        },
        "github_actions_job producer",
    )
    if (
        producer["repository_id"] != contract.CONTROLLER_REPOSITORY_ID
        or producer["workflow_path"] != contract.CONTROLLER_WORKFLOW_PATH
    ):
        raise contract.ReceiptValidationError("controller workflow identity mismatch")
    contract.positive_fields(
        producer,
        "repository_id",
        "workflow_id",
        "run_id",
        "run_attempt",
        "actor_id",
        "check_run_id",
    )
    contract.git_sha(producer["workflow_sha"], "producer.workflow_sha")
    expected_job, expected_environment, expected_audience = github_job_profile(payload)
    if (
        producer["job_name"] != expected_job
        or producer["environment"] != expected_environment
        or producer["audience"] != expected_audience
    ):
        raise contract.ReceiptValidationError("producer job profile mismatch")
    contract.request_id(producer["request_id"], "producer.request_id")
    contract.digest_fields(
        producer,
        "oidc_claims_sha256",
        "oidc_jti_sha256",
        "provider_job_observation_sha256",
    )
    if producer["provider_api_version"] != contract.GITHUB_API_VERSION:
        raise contract.ReceiptValidationError("provider API version mismatch")


def trusted_service_role(payload: Mapping[str, Any]) -> str:
    """Return the exact internal service role for one service-produced receipt."""

    return service_producers.trusted_service_role(payload)


def _incident_actor(producer: Mapping[str, Any]) -> None:
    contract.exact_keys(
        producer,
        {
            "kind",
            "provider_actor_id",
            "approved_incident_record_sha256",
            "action",
            "request_id",
        },
        "maintainer_incident_action producer",
    )
    contract.positive_int(producer["provider_actor_id"], "producer.provider_actor_id")
    contract.digest(
        producer["approved_incident_record_sha256"],
        "producer.approved_incident_record_sha256",
    )
    contract.enum(producer["action"], {"HOLD", "RELEASE_HOLD"}, "producer.action")
    contract.request_id(producer["request_id"], "producer.request_id")


def _broker_timer(producer: Mapping[str, Any], payload: Mapping[str, Any]) -> None:
    contract.exact_keys(
        producer,
        {
            "kind",
            "service_authority_role",
            "service_identity",
            "worker_version_id",
            "deployment_observation_sha256",
            "deployment_observation_record_id",
            "deployment_observation_record_sha256",
            "service_authority_inventory_sha256",
            "activated_authority_head_record_id",
            "activated_authority_head_record_sha256",
            "activated_authority_head_generation",
            "lease_object_key_sha256",
            "alarm_observation_sha256",
            "request_id",
        },
        "release_authority_broker_timer producer",
    )
    if payload["kind"] != "LEASE_EXPIRED":
        raise contract.ReceiptValidationError("broker timer payload mismatch")
    if producer["service_authority_role"] != "release_authority_ingress":
        raise contract.ReceiptValidationError("broker timer authority role mismatch")
    for key in ("service_identity", "worker_version_id"):
        contract.opaque(producer[key], f"producer.{key}")
    contract.digest_fields(
        producer,
        "deployment_observation_sha256",
        "deployment_observation_record_id",
        "deployment_observation_record_sha256",
        "service_authority_inventory_sha256",
        "activated_authority_head_record_id",
        "activated_authority_head_record_sha256",
        "lease_object_key_sha256",
        "alarm_observation_sha256",
    )
    contract.request_id(producer["request_id"], "producer.request_id")
    if producer["activated_authority_head_generation"] != 1:
        raise contract.ReceiptValidationError(
            "broker timer head generation must be one"
        )


def github_job_profile(payload: Mapping[str, Any]) -> tuple[str, str, str]:
    """Return the sole authenticated job/environment/audience tuple."""

    profile = routes.profile_for(payload)
    if profile.requester_kind != "github_actions_job":
        raise contract.ReceiptValidationError(
            "payload is not produced by a workflow job"
        )
    assert profile.job_name and profile.environment and profile.audience
    return profile.job_name, profile.environment, profile.audience
