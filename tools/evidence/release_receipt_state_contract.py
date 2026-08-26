"""Declarative state contract shared by the broker and chain verifier."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from tools.evidence.release_canonical import canonical_json_bytes


@dataclass(frozen=True, slots=True)
class TransitionRule:
    """One deterministic event edge in the successful release lifecycle."""

    event: str
    source: frozenset[str]
    target: str


def _rule(event: str, source: str | set[str], target: str) -> TransitionRule:
    sources = {source} if isinstance(source, str) else source
    return TransitionRule(event, frozenset(sources), target)


RULES = (
    _rule("REQUEST_ENQUEUED", "START", "QUEUED"),
    _rule("GOVERNANCE_A", "QUEUED", "GOVERNANCE_A"),
    _rule("CANDIDATE_HANDOFF", "GOVERNANCE_A", "CANDIDATE_READY"),
    _rule("TENANT_HYGIENE_VERIFIED", "LEASED", "HYGIENE_VERIFIED"),
    _rule("INTENT_ATTESTATION", "HYGIENE_VERIFIED", "ATTESTATION_INTENT"),
    _rule("ATTESTATION_VERIFIED", "ATTESTATION_INTENT", "ATTESTED"),
    _rule("PUBLIC_BUNDLE_VERIFIED", "ATTESTED", "PUBLIC_BUNDLE_VERIFIED"),
    _rule(
        "INTENT_GITHUB_DRAFT_CREATE",
        "PUBLIC_BUNDLE_VERIFIED",
        "DRAFT_CREATE_INTENT",
    ),
    _rule("DRAFT_CREATED", "DRAFT_CREATE_INTENT", "DRAFT_CREATED"),
    _rule(
        "INTENT_GITHUB_DRAFT_ASSET",
        {"DRAFT_CREATED", "DRAFT_ASSETS"},
        "DRAFT_ASSET_INTENT",
    ),
    _rule("DRAFT_ASSET_UPLOADED", "DRAFT_ASSET_INTENT", "DRAFT_ASSETS"),
    _rule("INTENT_GITHUB_DRAFT_UPDATE", "DRAFT_ASSETS", "DRAFT_UPDATE_INTENT"),
    _rule("DRAFT_STAGED", "DRAFT_UPDATE_INTENT", "DRAFT_STAGED"),
    _rule("DRAFT_VERIFIED", "DRAFT_STAGED", "DRAFT_VERIFIED"),
    _rule("GOVERNANCE_B", "DRAFT_VERIFIED", "GOVERNANCE_B"),
    _rule("AUTHORIZED", "GOVERNANCE_B", "AUTHORIZED"),
    _rule("PYPI_GATE_REQUESTED", "AUTHORIZED", "PYPI_GATE_PENDING"),
    _rule(
        "INTENT_PYPI_DEPLOYMENT_APPROVE",
        "PYPI_GATE_PENDING",
        "PYPI_GATE_DECISION_INTENT",
    ),
    _rule(
        "INTENT_PYPI_DEPLOYMENT_REJECT",
        "PYPI_GATE_PENDING",
        "PYPI_GATE_DECISION_INTENT",
    ),
    _rule("PYPI_GATE_APPROVED", "PYPI_GATE_DECISION_INTENT", "PYPI_READY"),
    _rule(
        "INTENT_PYPI_FILE_UPLOAD_SET",
        {"PYPI_SEALED", "PYPI_RECOVERY"},
        "PYPI_UPLOAD_INTENT",
    ),
    _rule(
        "PYPI_GATE_REJECTED",
        "PYPI_GATE_DECISION_INTENT",
        "RECOVERY_REQUIRED",
    ),
    _rule(
        "PYPI_GATE_CALLBACK_AMBIGUOUS",
        "PYPI_GATE_DECISION_INTENT",
        "PYPI_GATE_RECONCILIATION",
    ),
    _rule(
        "INTENT_GITHUB_RELEASE_PUBLISH",
        "PYPI_VERIFIED",
        "GITHUB_PUBLISH_INTENT",
    ),
    _rule(
        "GITHUB_RELEASE_PUBLISH_ACCEPTED",
        "GITHUB_PUBLISH_INTENT",
        "GITHUB_PUBLISHING",
    ),
    _rule(
        "GITHUB_RELEASE_IMMUTABLE_VERIFIED",
        "GITHUB_PUBLISHING",
        "GITHUB_IMMUTABLE",
    ),
    _rule("GOVERNANCE_C", "GITHUB_IMMUTABLE", "GOVERNANCE_C"),
    _rule("CLOSED", "GOVERNANCE_C", "TERMINAL"),
)
RULE_BY_EVENT = {rule.event: rule for rule in RULES}


def event_key(payload: Mapping[str, Any]) -> str:
    """Return the closed semantic discriminator for one payload."""

    kind = payload["kind"]
    if kind == "GOVERNANCE_SNAPSHOT":
        return f"GOVERNANCE_{payload['label']}"
    if kind == "MUTATION_INTENT":
        return (
            "INTENT_"
            + {
                "ATTESTATION_CREATE": "ATTESTATION",
                "GITHUB_DRAFT_CREATE": "GITHUB_DRAFT_CREATE",
                "GITHUB_DRAFT_ASSET_UPLOAD": "GITHUB_DRAFT_ASSET",
                "GITHUB_DRAFT_UPDATE": "GITHUB_DRAFT_UPDATE",
                "PYPI_DEPLOYMENT_APPROVE": "PYPI_DEPLOYMENT_APPROVE",
                "PYPI_DEPLOYMENT_REJECT": "PYPI_DEPLOYMENT_REJECT",
                "PYPI_FILE_UPLOAD_SET": "PYPI_FILE_UPLOAD_SET",
                "GITHUB_RELEASE_PUBLISH": "GITHUB_RELEASE_PUBLISH",
            }[payload["operation"]]
        )
    if kind == "DRAFT_TRANSITION":
        return f"DRAFT_{payload['transition']}"
    if kind == "GITHUB_RELEASE_TRANSITION":
        return f"GITHUB_RELEASE_{payload['transition']}"
    return kind


MAX_CLOSURE_RECEIPTS = 256
MAX_CLOSURE_CHAIN_BYTES = 16_777_216


def receipt_chain_document(
    receipts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Return the self-contained exact envelope stream through CLOSED."""

    if not 1 <= len(receipts) <= MAX_CLOSURE_RECEIPTS:
        raise ValueError("closure receipt count is outside bounds")
    return {
        "schema": "dpone.release-receipt-chain.v2",
        "schema_version": 2,
        "receipt_count": len(receipts),
        "receipts": [dict(receipt) for receipt in receipts],
    }


def receipt_chain_sha256(receipts: Sequence[Mapping[str, Any]]) -> str:
    """Hash exact canonical ``receipt-chain-v2.json`` member bytes."""

    encoded = canonical_json_bytes(receipt_chain_document(receipts))
    if len(encoded) > MAX_CLOSURE_CHAIN_BYTES:
        raise ValueError("closure receipt chain exceeds the byte limit")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
