"""Producer and committer projections for receipt-v2 fixtures."""

from __future__ import annotations

from typing import Any, Mapping

from tests import release_service_authority_fixtures as service_authority
from tests.release_receipt_fixture_identity import WORKFLOW_SHA, digest
from tools.evidence import release_controller_routes
from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_producers


def producer_for(payload: Mapping[str, Any]) -> dict[str, Any]:
    payload_kind = payload["kind"]
    if payload_kind == "LEASE_EXPIRED":
        ingress = service_authority.authority_for_role("release_authority_ingress")
        return {
            "kind": "release_authority_broker_timer",
            "service_authority_role": "release_authority_ingress",
            "service_identity": ingress["service_identity"],
            "worker_version_id": ingress["worker_version_id"],
            "deployment_observation_sha256": ingress["deployment_observation_sha256"],
            "deployment_observation_record_id": ingress[
                "deployment_observation_record_id"
            ],
            "deployment_observation_record_sha256": ingress[
                "deployment_observation_record_sha256"
            ],
            "service_authority_inventory_sha256": (
                service_authority.authority_inventory_sha256()
            ),
            "activated_authority_head_record_id": (
                service_authority.authority_head_record_id()
            ),
            "activated_authority_head_record_sha256": (
                service_authority.authority_head_sha256()
            ),
            "activated_authority_head_generation": 1,
            "lease_object_key_sha256": digest("lease object"),
            "alarm_observation_sha256": digest("lease alarm"),
            "request_id": "alarm-01HXDPONE",
        }
    try:
        role = release_receipt_producers.trusted_service_role(payload)
    except contract.ReceiptValidationError:
        role = None
    if role is not None:
        if role in {
            "attestation_mutator",
            "closed_check_mutator",
            "github_release_mutator",
        }:
            operation = {
                "attestation_mutator": "ATTESTATION_CREATE",
                "closed_check_mutator": "GITHUB_CLOSED_CHECK_PROJECT",
                "github_release_mutator": "GITHUB_RELEASE_PUBLISH",
            }[role]
            result = {
                **service_authority.producer_common(role),
                "github_app_id": {
                    "attestation_mutator": 9_300_001,
                    "closed_check_mutator": 9_300_002,
                    "github_release_mutator": 9_300_003,
                }[role],
                "installation_id": {
                    "attestation_mutator": 10_300_001,
                    "closed_check_mutator": 10_300_002,
                    "github_release_mutator": 10_300_003,
                }[role],
                "operation": operation,
                "intent_id": payload["intent_id"],
                "intent_subject_sha256": payload["intent_subject_sha256"],
                "request_id": "request-01HXDPONE",
                "authority_guard_sha256": payload["authority_guard_sha256"],
                "authority_guard_accepted_at": payload["authority_guard_accepted_at"],
                "authority_guard_expires_at": payload["authority_guard_expires_at"],
                "capability_binding_sha256": payload["capability_binding_sha256"],
            }
            if payload_kind == "MUTATION_INTENT_CONSUMED":
                result["capability_sha256"] = payload["capability_sha256"]
            else:
                result.update(
                    provider_response_sha256=payload["provider_response_sha256"],
                    provider_api_version="2026-03-10",
                    intent_consumption_receipt_id=payload[
                        "intent_consumption_receipt_id"
                    ],
                    intent_consumption_receipt_sha256=payload[
                        "intent_consumption_receipt_sha256"
                    ],
                )
                if payload_kind == "CLOSED_CHECK_TRANSITION":
                    result.update(
                        controller_workflow_id=payload["controller_workflow_id"],
                        controller_workflow_sha=payload["controller_workflow_sha"],
                        controller_run_id=payload["controller_run_id"],
                        controller_run_attempt=payload["controller_run_attempt"],
                    )
            return result
        if role == "draft_ledger_orchestrator":
            result = {
                **service_authority.producer_common(role),
                "operation": payload["operation"],
                "subject_identity_sha256": payload["subject_identity_sha256"],
                "request_id": "request-01HXDPONE",
            }
            return result
        if role == "github_draft_mutator":
            return {
                **service_authority.producer_common(role),
                "github_app_id": 9_100_001,
                "installation_id": 10_100_001,
                "operation": payload["operation"],
                "intent_id": payload["intent_id"],
                "intent_subject_sha256": payload["intent_subject_sha256"],
                "capability_sha256": payload["capability_sha256"],
                "authority_guard_sha256": payload["authority_guard_sha256"],
                "authority_guard_accepted_at": payload["authority_guard_accepted_at"],
                "authority_guard_expires_at": payload["authority_guard_expires_at"],
                "capability_binding_sha256": payload["capability_binding_sha256"],
                "request_id": "request-01HXDPONE",
            }
        if role in {
            "attestation_reader",
            "controller_run_reader",
            "github_governance_reader",
        }:
            observation = next(
                payload[key]
                for key in (
                    "provider_observation_sha256",
                    "observation_sha256",
                    "provider_receipt_inventory_sha256",
                    "provider_response_sha256",
                )
                if key in payload
            )
            result = {
                **service_authority.producer_common(role),
                "github_app_id": 9_200_001,
                "installation_id": 10_200_001,
                "provider_observation_sha256": observation,
                "provider_api_version": "2026-03-10",
                "request_id": "request-01HXDPONE",
            }
            if payload["kind"] in {
                "CLOSURE_ARTIFACT_VERIFIED",
                "CLOSED_CHECK_TRANSITION",
            }:
                result.update(
                    controller_workflow_id=payload["controller_workflow_id"],
                    controller_workflow_sha=payload["controller_workflow_sha"],
                    controller_run_id=payload["controller_run_id"],
                    controller_run_attempt=payload["controller_run_attempt"],
                )
            return result
        if role in {"cancellation_observer", "recovery_observer"}:
            aggregate_key = (
                "provider_observation_sha256"
                if payload["kind"] == "CANCELLATION"
                else "observation_sha256"
            )
            return {
                **service_authority.producer_common(role),
                "github_app_id": 9_200_001,
                "installation_id": 10_200_001,
                **service_authority.composite_constituents(),
                "github_provider_observation_sha256": payload[
                    "github_provider_observation_sha256"
                ],
                "github_provider_api_version": "2026-03-10",
                "pypi_provider_observation_sha256": payload[
                    "pypi_provider_observation_sha256"
                ],
                "pypi_provider_api_version": "pypi-integrity-v1",
                "aggregate_observation_sha256": payload[aggregate_key],
                "request_id": "request-01HXDPONE",
            }
        if role == "pypi_reader":
            return {
                **service_authority.producer_common(role),
                "provider_observation_sha256": payload["provider_observation_sha256"],
                "provider_api_version": "pypi-integrity-v1",
                "request_id": "request-01HXDPONE",
            }
        if role == "tenant_scanner":
            common = service_authority.producer_common(role)
            return {
                **common,
                "candidate_id": payload["candidate_id"],
                "scan_result_sha256": payload["archive_results_sha256"],
                "scanner_service_version_id": common["service_version_id"],
                "request_id": "request-01HXDPONE",
            }
        if role == "ledger_orchestrator":
            evidence = next(
                payload[key]
                for key in (
                    "observation_sha256",
                    "incident_record_sha256",
                    "lease_id",
                )
                if key in payload
            )
            return {
                **service_authority.producer_common(role),
                "selector": release_controller_routes.selector_for(payload),
                "authority_evidence_sha256": evidence,
                "request_id": "request-01HXDPONE",
            }
        if role == "lease_orchestrator":
            return {
                **service_authority.producer_common(role),
                "lease_id": payload["lease_id"],
                "fencing_token": payload["fencing_token"],
                "reason": payload["reason"],
                "request_id": "request-01HXDPONE",
            }
        assert role == "pypi_deployment_gate"
        result = {
            **service_authority.producer_common("pypi_deployment_gate"),
            "github_app_id": 9_000_001,
            "installation_id": 10_000_001,
            "workload_identity": "broker-gate-webhook-v1",
            "request_id": "request-01HXDPONE",
            "provider_observation_sha256": digest("gate service observation"),
            "provider_api_version": "2026-03-10",
        }
        if payload_kind == "MUTATION_INTENT_CONSUMED":
            result.update(
                authority_guard_sha256=payload["authority_guard_sha256"],
                authority_guard_accepted_at=payload["authority_guard_accepted_at"],
                authority_guard_expires_at=payload["authority_guard_expires_at"],
                capability_binding_sha256=payload["capability_binding_sha256"],
            )
        return result
    if payload_kind == "INCIDENT_HOLD_RELEASED":
        return {
            "kind": "maintainer_incident_action",
            "provider_actor_id": 1001,
            "approved_incident_record_sha256": digest("incident approval"),
            "action": "RELEASE_HOLD",
            "request_id": "request-01HXDPONE",
        }
    job, environment, audience = release_receipt_producers.github_job_profile(payload)
    return {
        "kind": "github_actions_job",
        "repository_id": 1_305_993_853,
        "workflow_id": 316_322_127,
        "workflow_path": ".github/workflows/release-controller.yml",
        "workflow_sha": WORKFLOW_SHA,
        "run_id": 123_456_789,
        "run_attempt": 2,
        "job_name": job,
        "environment": environment,
        "actor_id": 1001,
        "audience": audience,
        "check_run_id": 2001,
        "request_id": "request-01HXDPONE",
        "oidc_claims_sha256": digest("OIDC claims"),
        "oidc_jti_sha256": digest("OIDC jti"),
        "provider_job_observation_sha256": digest("job observation"),
        "provider_api_version": "2026-03-10",
    }


def committer() -> dict[str, Any]:
    ingress = service_authority.authority_for_role("release_authority_ingress")
    return {
        "kind": "release_authority_broker",
        "service_identity": ingress["service_identity"],
        "cloudflare_account_id": service_authority.ACCOUNT_ID,
        "worker_script": ingress["service"],
        "worker_version_id": ingress["worker_version_id"],
        "source_sha256": ingress["source_sha256"],
        "deployment_observation_record_id": ingress["deployment_observation_record_id"],
        "deployment_observation_record_sha256": ingress[
            "deployment_observation_record_sha256"
        ],
        "activation_provisioned_record_id": (
            service_authority.service_activation_record()["provisioned"]["record_id"]
        ),
        "activation_provisioned_digest": (
            service_authority.service_activation_record()["provisioned"][
                "record_sha256"
            ]
        ),
        "activation_record_id": (
            service_authority.service_activation_record()["previous"]["record_id"]
        ),
        "activation_digest": (
            service_authority.service_activation_record()["previous"]["record_sha256"]
        ),
        "expected_service_authorities_sha256": (
            service_authority.expected_authorities_sha256()
        ),
        "service_authority_activation_record_id": (
            service_authority.activation_record_id()
        ),
        "service_authority_activation_record_sha256": (
            service_authority.activation_record_sha256()
        ),
        "service_authority_inventory_sha256": (
            service_authority.authority_inventory_sha256()
        ),
        "activated_authority_head_record_id": (
            service_authority.authority_head_record_id()
        ),
        "activated_authority_head_record_sha256": (
            service_authority.authority_head_sha256()
        ),
        "activated_authority_head_generation": 1,
    }
