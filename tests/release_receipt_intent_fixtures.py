"""Deterministic one-use mutation-intent fixtures."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from tests import release_receipt_fixtures as base
from tests import release_service_authority_fixtures as service_authority
from tools.evidence import release_authority_guard as authority_guard
from tools.evidence import release_receipt_intents as intents
from tools.evidence import release_receipt_consumption as consumption_contract
from tools.evidence import release_receipt_inventory as inventory
from tools.evidence import release_private_closure_inventory as closure_inventory
from tools.evidence.release_controller_service_roles import role_for_selector


def intent(
    operation: str,
    *,
    asset_index: int = 0,
    upload_files: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return one exact operation/subject-bound intent."""

    subject = _subject(operation, asset_index, upload_files)
    candidate_scope = operation in intents.CANDIDATE_OPERATIONS
    scope_key = "candidate_id" if candidate_scope else "authorization_id"
    result = {
        "kind": "MUTATION_INTENT",
        "state": "MUTATION_INTENT_RECORDED",
        "intent_id": base.digest(f"intent-{operation}-{asset_index}"),
        "lease_id": base.LEASE_ID,
        "fencing_token": 3,
        "attempt_id": base.ATTEMPT_ID,
        "operation": operation,
        "subject": subject,
        "subject_identity_sha256": intents.subject_identity_sha256(operation, subject),
        "capability_ttl_seconds": 60,
        "one_use": True,
        scope_key: base.CANDIDATE_ID if candidate_scope else base.AUTHORIZATION_ID,
    }
    return result


def consumption(
    operation: str,
    *,
    asset_index: int = 0,
    upload_files: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return the exact result-side binding for ``intent``."""

    value = intent(
        operation,
        asset_index=asset_index,
        upload_files=upload_files,
    )
    result = {
        "intent_id": value["intent_id"],
        "intent_receipt_id": base.digest(f"intent-receipt-{operation}-{asset_index}"),
        "intent_receipt_sha256": base.digest(
            f"intent-receipt-bytes-{operation}-{asset_index}"
        ),
        "intent_subject_sha256": value["subject_identity_sha256"],
        "intent_consumption_receipt_sha256": base.digest(
            f"consumed-{operation}-{asset_index}"
        ),
        "intent_consumption_receipt_id": base.digest(
            f"consumed-receipt-{operation}-{asset_index}"
        ),
        "intent_consumed_once": True,
    }
    if operation in authority_guard.GUARDED_OPERATIONS:
        consumed_payload = consumed(operation, asset_index=asset_index)
        result.update(
            {
                key: consumed_payload[key]
                for key in consumption_contract.OUTCOME_GUARD_KEYS
            }
        )
    return result


def consumed(operation: str, *, asset_index: int = 0) -> dict[str, Any]:
    """Return a standalone valid pre-mutation consumption receipt payload."""

    source = intent(operation, asset_index=asset_index)
    scope_key = (
        "candidate_id"
        if operation in intents.CANDIDATE_OPERATIONS
        else "authorization_id"
    )
    payload = {
        "kind": "MUTATION_INTENT_CONSUMED",
        "state": "MUTATION_INTENT_CONSUMED",
        "intent_id": source["intent_id"],
        "intent_receipt_id": base.digest(f"intent-receipt-{operation}-{asset_index}"),
        "intent_receipt_sha256": base.digest(
            f"intent-receipt-bytes-{operation}-{asset_index}"
        ),
        "intent_subject_sha256": source["subject_identity_sha256"],
        "lease_id": source["lease_id"],
        "fencing_token": source["fencing_token"],
        "attempt_id": source["attempt_id"],
        "operation": operation,
        "capability_sha256": base.digest(f"capability-{operation}-{asset_index}"),
        "consumer_identity_sha256": base.digest("placeholder consumer"),
        "consumed_at": "2026-08-15T00:00:01Z",
        scope_key: source[scope_key],
    }
    attach_guard(payload)
    payload["consumer_identity_sha256"] = consumption_contract.consumer_identity_sha256(
        base._producer(payload)
    )
    return payload


def attach_guard(
    payload: dict[str, Any],
    *,
    github_consumer: Mapping[str, Any] | None = None,
) -> None:
    """Attach the exact fresh service/head guard to a consumption fixture."""

    operation = payload["operation"]
    if operation not in authority_guard.GUARDED_OPERATIONS:
        return
    role = (
        "ledger_orchestrator"
        if operation in authority_guard.GITHUB_ACTION_OPERATIONS
        else role_for_selector(f"MUTATION_INTENT_CONSUMED:{operation}")
    )
    producer = service_authority.producer_common(role)
    accepted = _parse(payload["consumed_at"])
    expires = accepted + timedelta(seconds=authority_guard.MAX_TTL_SECONDS)
    guard = authority_guard.build(
        operation=operation,
        intent_id=payload["intent_id"],
        intent_subject_sha256=payload["intent_subject_sha256"],
        lease_id=payload["lease_id"],
        fencing_token=payload["fencing_token"],
        attempt_id=payload["attempt_id"],
        producer=producer,
        provider_observation_sha256=base.digest(
            f"authority guard observation/{operation}/{payload['intent_id']}"
        ),
        provider_observation_record_id=base.digest(
            f"authority guard observation record/{operation}/{payload['intent_id']}"
        ),
        provider_observation_record_sha256=base.digest(
            f"authority guard observation record bytes/{operation}/{payload['intent_id']}"
        ),
        observed_at=_format(accepted),
        accepted_at=_format(accepted),
        expires_at=_format(expires),
        github_consumer=(
            github_consumer or base._producer(payload)
            if operation in authority_guard.GITHUB_ACTION_OPERATIONS
            else None
        ),
    )
    payload.update(
        authority_guard=guard,
        authority_guard_sha256=authority_guard.digest(guard),
        authority_guard_observed_at=guard["observed_at"],
        authority_guard_accepted_at=guard["accepted_at"],
        authority_guard_expires_at=guard["expires_at"],
    )
    payload["capability_binding_sha256"] = authority_guard.capability_binding_sha256(
        payload
    )


def _parse(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _format(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _subject(
    operation: str,
    asset_index: int,
    upload_files: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    asset = base._release_assets()[asset_index]
    asset_digest = inventory.inventory_sha256(
        inventory.GITHUB_ASSET_SCHEMA, base._release_assets()
    )
    values = {
        "ATTESTATION_CREATE": {
            "candidate_id": base.CANDIDATE_ID,
            "subject_manifest_sha256": base.digest("subjects"),
        },
        "GITHUB_DRAFT_CREATE": {
            "candidate_id": base.CANDIDATE_ID,
            "tag": base.TAG,
            "release_body_sha256": base.digest("body"),
        },
        "GITHUB_DRAFT_ASSET_UPLOAD": {
            "candidate_id": base.CANDIDATE_ID,
            "release_id": 5_000_000_001,
            **asset,
        },
        "GITHUB_DRAFT_UPDATE": {
            "candidate_id": base.CANDIDATE_ID,
            "release_id": 5_000_000_001,
            "release_body_sha256": base.digest("body"),
            "asset_inventory_sha256": asset_digest,
        },
        "PYPI_DEPLOYMENT_APPROVE": {
            "authorization_id": base.AUTHORIZATION_ID,
            "candidate_id": base.CANDIDATE_ID,
            "gate_request_id": base.digest("gate request"),
            "gate_request_provider_observation_sha256": base.digest(
                "gate provider PYPI_GATE_REQUESTED"
            ),
            "tag": base.TAG,
            "ref": f"refs/tags/{base.TAG}",
            "deployment_id": 18_000_001,
            "environment_name": "pypi",
            "environment_id": 18_405_660_890,
            "protection_rule_id": 7_000_000_001,
            "gate_app_id": 9_000_001,
            "gate_installation_id": 10_000_001,
            "app_slug": "dpone-release-controller-pypi-gate",
            "controller_repository_id": 1_305_993_853,
            "controller_workflow_id": 316_322_127,
            "controller_workflow_sha": base.WORKFLOW_SHA,
            "controller_run_id": 123_456_789,
            "controller_run_attempt": 2,
            "expected_file_count": 8,
            "expected_file_inventory_sha256": inventory.inventory_sha256(
                inventory.DISTRIBUTION_SCHEMA, base._distributions()
            ),
        },
        "PYPI_DEPLOYMENT_REJECT": {
            "authorization_id": base.AUTHORIZATION_ID,
            "candidate_id": base.CANDIDATE_ID,
            "gate_request_id": base.digest("gate request"),
            "gate_request_provider_observation_sha256": base.digest(
                "gate provider PYPI_GATE_REQUESTED"
            ),
            "tag": base.TAG,
            "ref": f"refs/tags/{base.TAG}",
            "deployment_id": 18_000_001,
            "environment_name": "pypi",
            "environment_id": 18_405_660_890,
            "protection_rule_id": 7_000_000_001,
            "gate_app_id": 9_000_001,
            "gate_installation_id": 10_000_001,
            "app_slug": "dpone-release-controller-pypi-gate",
            "controller_repository_id": 1_305_993_853,
            "controller_workflow_id": 316_322_127,
            "controller_workflow_sha": base.WORKFLOW_SHA,
            "controller_run_id": 123_456_789,
            "controller_run_attempt": 2,
            "expected_file_count": 8,
            "expected_file_inventory_sha256": inventory.inventory_sha256(
                inventory.DISTRIBUTION_SCHEMA, base._distributions()
            ),
        },
        "PYPI_FILE_UPLOAD_SET": _upload_subject(upload_files),
        "GITHUB_RELEASE_PUBLISH": {
            "authorization_id": base.AUTHORIZATION_ID,
            "release_id": 5_000_000_001,
            "release_body_sha256": base.digest("body"),
            "public_bundle_manifest_sha256": base.digest("bundle manifest"),
            "asset_inventory_sha256": asset_digest,
        },
        "GITHUB_CLOSED_CHECK_PROJECT": {
            "authorization_id": base.AUTHORIZATION_ID,
            "closed_receipt_id": base.digest("closed receipt id"),
            "closure_artifact_id": 9_500_000_001,
            "closure_artifact_digest": base.digest("closure artifact"),
            "release_identity_id": base.RELEASE_ID,
            "controller_run_id": 123_456_789,
            "controller_run_attempt": 2,
            "external_id": (
                f"dpone-release-controller.closed.v1|{base.RELEASE_ID}|123456789|2"
            ),
        },
        "GITHUB_CLOSURE_ARTIFACT_UPLOAD": _closure_subject(),
    }
    return values[operation]


def _upload_subject(
    upload_files: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    files = list(upload_files or base._distributions())
    return {
        "authorization_id": base.AUTHORIZATION_ID,
        "candidate_id": base.CANDIDATE_ID,
        "deployment_id": 18_000_001,
        "environment_id": 18_405_660_890,
        "candidate_file_inventory_sha256": inventory.inventory_sha256(
            inventory.DISTRIBUTION_SCHEMA, base._distributions()
        ),
        "upload_file_count": len(files),
        "upload_file_inventory": files,
        "upload_file_inventory_sha256": inventory.inventory_sha256(
            inventory.DISTRIBUTION_SCHEMA, files
        ),
    }


def _closure_subject() -> dict[str, Any]:
    member_digests = {
        closure_inventory.CLOSED_RECEIPT_PATH: base.digest("closed receipt bytes"),
        closure_inventory.RECEIPT_CHAIN_PATH: base.digest("receipt chain"),
        closure_inventory.RELEASE_EVIDENCE_PATH: base.digest("release evidence"),
        closure_inventory.MANIFEST_PATH: base.digest("closure manifest"),
    }
    members = [
        {
            "path": path,
            "size_bytes": index + 100,
            "sha256": member_digests[path],
        }
        for index, path in enumerate(closure_inventory.MEMBER_PATHS)
    ]
    return {
        "authorization_id": base.AUTHORIZATION_ID,
        "release_identity_id": base.RELEASE_ID,
        "closed_receipt_id": base.digest("closed receipt id"),
        "closed_receipt_sha256": base.digest("closed receipt bytes"),
        "controller_run_id": 123_456_789,
        "controller_run_attempt": 2,
        "artifact_name": "release-controller-closure-123456789-2",
        "member_count": 4,
        "member_inventory": members,
        "member_inventory_sha256": closure_inventory.digest(members),
        "total_bytes": sum(member["size_bytes"] for member in members),
    }
