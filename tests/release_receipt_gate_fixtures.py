"""Valid closed PyPI deployment-gate payload fixtures."""

from __future__ import annotations

import hashlib
from typing import Any

from tests import release_receipt_fixtures as base
from tools.evidence import release_receipt_inventory as inventory

AUTHORIZATION_ID = "sha256:" + "7" * 64
LEASE_ID = "sha256:" + "6" * 64


def digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def all_gate_payloads() -> list[dict[str, Any]]:
    return [requested(), approved(), rejected(), ambiguous(), reconciled()]


def requested() -> dict[str, Any]:
    return {
        **_base("PYPI_GATE_REQUESTED", "PYPI_GATE_PENDING"),
        "action": "requested",
        "webhook_delivery_id": "delivery-01HXDPONE",
        "webhook_payload_sha256": digest("gate webhook"),
        "requested_at": "2026-08-15T00:00:00Z",
    }


def approved() -> dict[str, Any]:
    return {
        **_base("PYPI_GATE_APPROVED", "PYPI_GATE_APPROVED"),
        **_consumption("APPROVE"),
        "callback_request_sha256": digest("approve request"),
        "callback_response_sha256": digest("approve response"),
        "callback_http_status": 204,
        "approved_at": "2026-08-15T00:00:02Z",
        "intent_state": "CONSUMED",
    }


def rejected() -> dict[str, Any]:
    return {
        **_base("PYPI_GATE_REJECTED", "PYPI_GATE_REJECTED"),
        **_consumption("REJECT"),
        "reason_code": "INTENT_INVALID",
        "callback_request_sha256": digest("reject request"),
        "callback_response_sha256": digest("reject response"),
        "callback_http_status": 204,
        "rejected_at": "2026-08-15T00:00:02Z",
        "intent_state": "CONSUMED",
    }


def ambiguous() -> dict[str, Any]:
    return {
        **_base(
            "PYPI_GATE_CALLBACK_AMBIGUOUS",
            "PYPI_GATE_RECONCILIATION_REQUIRED",
        ),
        **_consumption("APPROVE"),
        "attempted_decision": "APPROVE",
        "callback_request_sha256": digest("ambiguous request"),
        "transport_evidence_sha256": digest("timeout"),
        "ambiguity_observed_at": "2026-08-15T00:00:03Z",
        "intent_state": "CONSUMED",
        "resolution_required": True,
    }


def reconciled() -> dict[str, Any]:
    return {
        **_base("PYPI_GATE_RECONCILED", "PYPI_GATE_APPROVED"),
        "attempted_decision": "APPROVE",
        "resolution": "APPROVED_CONFIRMED",
        "original_ambiguity_receipt_id": digest("ambiguous receipt"),
        "provider_query_sha256": digest("pending deployments query"),
        "provider_response_sha256": digest("pending deployments response"),
        "reconciled_at": "2026-08-15T00:00:04Z",
        "same_callback_retry_permitted": False,
        "new_publish_authority_issued": False,
        "new_decision_intent_required": False,
    }


def _base(kind: str, state: str) -> dict[str, Any]:
    payload = {
        "kind": kind,
        "state": state,
        "authorization_id": AUTHORIZATION_ID,
        "candidate_id": base.CANDIDATE_ID,
        "gate_request_id": digest("gate request"),
        "lease_id": LEASE_ID,
        "fencing_token": 3,
        "tag": "v0.74.0",
        "environment_name": "pypi",
        "environment_id": 18_405_660_890,
        "protection_rule_id": 7_000_000_001,
        "deployment_id": 18_000_001,
        "gate_app_id": 9_000_001,
        "gate_installation_id": 10_000_001,
        "app_slug": "dpone-release-controller-pypi-gate",
        "controller_repository_id": 1_305_993_853,
        "controller_workflow_id": 316_322_127,
        "controller_workflow_sha": "c" * 40,
        "controller_run_id": 123_456_789,
        "controller_run_attempt": 2,
        "ref": "refs/tags/v0.74.0",
        "provider_observation_sha256": digest(f"gate provider {kind}"),
        "expected_file_count": 8,
        "expected_file_inventory_sha256": inventory.inventory_sha256(
            inventory.DISTRIBUTION_SCHEMA, base._distributions()
        ),
    }
    if kind != "PYPI_GATE_REQUESTED":
        payload["gate_request_provider_observation_sha256"] = digest(
            "gate provider PYPI_GATE_REQUESTED"
        )
    return payload


def _consumption(decision: str) -> dict[str, Any]:
    from tests import release_receipt_intent_fixtures as intent_fixture

    return intent_fixture.consumption(f"PYPI_DEPLOYMENT_{decision}")
