"""Semantic candidate selector and provider-proof cross-binding."""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_candidate_contract as candidate_contract
from tools.evidence import release_candidate_provider as candidate_provider
from tools.evidence import release_candidate_stream as candidate_stream
from tools.evidence import release_identity
from tools.evidence.release_controller_exchange_errors import ControllerExchangeError


def candidate_selector(value: Any) -> Mapping[str, Any]:
    """Parse an exact candidate-stream selector document."""

    raw = _mapping(value, "candidate selector")
    expected_keys = {
        "candidate_artifact_digest",
        "candidate_artifact_id",
        "candidate_run_attempt",
        "candidate_run_id",
        "expected_peeled_commit_sha",
        "schema",
        "schema_version",
        "tag",
    }
    if set(raw) != expected_keys:
        raise ControllerExchangeError("candidate selector keys are not exact")
    try:
        expected = candidate_stream.CandidateStreamRequest(
            tag=raw["tag"],
            expected_peeled_commit_sha=raw["expected_peeled_commit_sha"],
            candidate_run_id=raw["candidate_run_id"],
            candidate_run_attempt=raw["candidate_run_attempt"],
            candidate_artifact_id=raw["candidate_artifact_id"],
            candidate_artifact_digest=raw["candidate_artifact_digest"],
        ).document()
    except candidate_contract.CandidateHandoffError as exc:
        raise ControllerExchangeError(f"invalid candidate selector: {exc}") from exc
    if raw != expected:
        raise ControllerExchangeError("candidate selector schema/version mismatch")
    return raw


def require_observation_binding_without_clock(
    observation: candidate_provider.ProviderArtifactObservation,
    binding: candidate_contract.ArtifactBinding,
) -> None:
    """Check deterministic fields after a builder's earlier fresh provider read."""

    expected = {
        "artifact_digest": binding.artifact_digest,
        "artifact_id": binding.artifact_id,
        "head_sha": binding.expected_peeled_commit_sha,
        "release": binding.expected_release,
        "run_attempt": binding.run_attempt,
        "run_id": binding.run_id,
    }
    if any(getattr(observation, key) != value for key, value in expected.items()):
        raise candidate_contract.CandidateHandoffError(
            "provider observation selector mismatch"
        )


def verify_projection(
    payload: Mapping[str, Any],
    observation: candidate_provider.ProviderArtifactObservation,
    binding: candidate_contract.ArtifactBinding,
    release_identity_id: str,
) -> None:
    """Cross-bind provider archive evidence to candidate and authority IDs."""

    archive = candidate_provider.VerifiedProviderArchive(
        observation=observation,
        raw_zip_sha256=payload["candidate_artifact_raw_zip_sha256"],
        raw_zip_size_bytes=payload["candidate_artifact_raw_zip_size_bytes"],
        extracted_file_count=payload["candidate_artifact_file_count"],
        extracted_total_bytes=payload["candidate_artifact_expanded_bytes"],
    )
    expected_provider = archive.receipt_payload()
    if any(payload[key] != value for key, value in expected_provider.items()):
        raise ControllerExchangeError("candidate provider projection mismatch")
    authority_id = release_identity.release_authority_id(
        release_identity_id=release_identity_id,
        tag_object_sha=observation.tag_object_sha,
        peeled_commit_sha=binding.expected_peeled_commit_sha,
        policy_sha256=observation.policy_sha256,
    )
    expected_candidate_id = release_identity.candidate_id(
        release_authority_id=authority_id,
        candidate_inventory_sha256=payload["candidate_inventory_sha256"],
    )
    if payload["candidate_id"] != expected_candidate_id:
        raise ControllerExchangeError("candidate identity/evidence mismatch")


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ControllerExchangeError(f"{name} must be an object")
    return value
