"""Deployment-protection gate transitions for the receipt-v2 chain."""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_outcome_bindings as outcome_bindings
from tools.evidence.release_receipt_chain_state import ChainState


def apply_gate(state: ChainState, envelope: Mapping[str, Any], event: str) -> None:
    """Apply the deployment-protection gate under its one-use intent."""

    payload = envelope["payload"]

    if event == "PYPI_GATE_REQUESTED":
        if state.phase != "AUTHORIZED":
            raise contract.ReceiptValidationError("gate request phase mismatch")
        _equal(
            payload["authorization_id"], state.authorization_id, "gate authorization"
        )
        state.gate_binding = _select(payload, _GATE_KEYS)
        state.gate_binding["gate_request_provider_observation_sha256"] = payload[
            "provider_observation_sha256"
        ]
        state.phase = "PYPI_GATE_PENDING"
        return
    if state.gate_binding is None:
        raise contract.ReceiptValidationError("gate request receipt missing")
    decision_binding = _select(payload, _GATE_KEYS)
    decision_binding["gate_request_provider_observation_sha256"] = payload[
        "gate_request_provider_observation_sha256"
    ]
    _equal(decision_binding, state.gate_binding, "gate binding")
    decisions = {
        "PYPI_GATE_APPROVED": ("PYPI_DEPLOYMENT_APPROVE", "PYPI_READY"),
        "PYPI_GATE_REJECTED": ("PYPI_DEPLOYMENT_REJECT", "RECOVERY_REQUIRED"),
        "PYPI_GATE_CALLBACK_AMBIGUOUS": (
            "PYPI_DEPLOYMENT_" + payload.get("attempted_decision", ""),
            "PYPI_GATE_RECONCILIATION",
        ),
    }
    if event in decisions:
        if state.phase != "PYPI_GATE_DECISION_INTENT":
            raise contract.ReceiptValidationError("gate decision phase mismatch")
        operation, target = decisions[event]
        state.intent_ledger.require_outcome(
            payload,
            operation=operation,
            expected_subject=outcome_bindings.deployment_subject(payload),
            outcome_observed_at=envelope["timestamps"]["observed_at"],
            outcome_committed_at=envelope["timestamps"]["committed_at"],
        )
        state.phase = target
        if event == "PYPI_GATE_CALLBACK_AMBIGUOUS":
            state.gate_ambiguity_receipt_id = envelope["receipt_id"]
            state.gate_ambiguity_decision = payload["attempted_decision"]
    elif event == "PYPI_GATE_RECONCILED" and state.phase == "PYPI_GATE_RECONCILIATION":
        _equal(
            payload["original_ambiguity_receipt_id"],
            state.gate_ambiguity_receipt_id,
            "gate ambiguity receipt",
        )
        _equal(
            payload["attempted_decision"],
            state.gate_ambiguity_decision,
            "gate ambiguity decision",
        )
        state.phase = {
            "APPROVED_CONFIRMED": "PYPI_READY",
            "REJECTED_CONFIRMED": "RECOVERY_REQUIRED",
            "STILL_PENDING": "PYPI_GATE_PENDING",
        }[payload["resolution"]]
    else:
        raise contract.ReceiptValidationError("gate transition mismatch")


def _select(value: Mapping[str, Any], keys: frozenset[str]) -> dict[str, Any]:
    return {key: value[key] for key in sorted(keys)}


def _equal(actual: Any, expected: Any, name: str) -> None:
    if actual != expected:
        raise contract.ReceiptValidationError(f"{name} mismatch")


_GATE_KEYS = frozenset(
    {
        "authorization_id",
        "candidate_id",
        "gate_request_id",
        "lease_id",
        "fencing_token",
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
        "controller_run_id",
        "controller_run_attempt",
        "controller_workflow_id",
        "controller_workflow_sha",
        "expected_file_count",
        "expected_file_inventory_sha256",
    }
)
