"""Immutable ports and value objects for broker activation proof admission."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol


class ActivationProofError(ValueError):
    """Broker activation proof is missing, stale, ambiguous, or mismatched."""


class Clock(Protocol):
    """UTC clock injected at the fresh-proof boundary."""

    def now(self) -> datetime:
        """Return one timezone-aware UTC instant."""


@dataclass(frozen=True, slots=True)
class SystemUtcClock:
    """Production UTC clock; tests inject deterministic implementations."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


SYSTEM_UTC_CLOCK = SystemUtcClock()


@dataclass(frozen=True, slots=True)
class BrokerActivationExchange:
    """One response paired with the client-generated anti-replay request ID."""

    request_id: str
    response_bytes: bytes


class BrokerActivationClient(Protocol):
    """Pinned adapter which mints OIDC and performs the broker request."""

    def request_activation_proof(
        self,
        *,
        endpoint: str,
        path: str,
        audience: str,
        environment: str,
        request_bytes: bytes,
    ) -> BrokerActivationExchange:
        """POST one canonical request with a fresh OIDC token and request ID."""


@dataclass(frozen=True, slots=True)
class ExpectedControllerRun:
    repository_id: int
    ref: str
    workflow_ref: str
    workflow_sha: str
    run_id: int
    run_attempt: int


@dataclass(frozen=True, slots=True)
class ActivationProof:
    """Validated A0/A1 registry projection bound to the controller run."""

    request_id: str
    controller_workflow_id: int
    controller_ref: str
    controller_tag_object_sha: str
    provisioned_record_id: str
    provisioned_digest: str
    worker_version_id: str
    provisioned_worm_version_id: str
    controller_workflow_commit_sha: str
    controller_workflow_blob_sha: str
    controller_action_commit_sha: str
    controller_action_metadata_blob_sha: str
    controller_action_bundle_sha256: str
    activated_record_id: str
    activated_digest: str
    activated_worm_version_id: str
    target_policy_commit_sha: str
    target_policy_sha256: str
    target_policy_blob_sha: str
    proof_sha256: str
    admitted_at: str
    expires_at: str
