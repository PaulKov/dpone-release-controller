"""Deterministic positive vector for the candidate streaming contract."""

from __future__ import annotations

from tools.evidence.release_candidate_provider import ProviderArtifactObservation
from tools.evidence.release_candidate_stream import CandidateStreamRequest
from tools.evidence.release_candidate_stream_vectors import encoded


def request() -> CandidateStreamRequest:
    return CandidateStreamRequest(
        tag="v0.74.0",
        expected_peeled_commit_sha="a" * 40,
        candidate_run_id=31_900_000_001,
        candidate_run_attempt=1,
        candidate_artifact_id=9_300_000_001,
        candidate_artifact_digest="sha256:" + ("4" * 64),
    )


def observation() -> ProviderArtifactObservation:
    return ProviderArtifactObservation(
        schema="dpone.github-actions-artifact-observation.v1",
        schema_version=1,
        provider_api_version="2026-03-10",
        repository="PaulKov/dpone",
        repository_id=1_255_975_556,
        release="v0.74.0",
        workflow_path=".github/workflows/release.yml",
        event="push",
        run_status="completed",
        head_branch="v0.74.0",
        head_sha="a" * 40,
        run_id=31_900_000_001,
        run_attempt=1,
        conclusion="success",
        artifact_id=9_300_000_001,
        artifact_name="release-candidates",
        artifact_digest="sha256:" + ("4" * 64),
        artifact_size_bytes=123_456,
        artifact_expired=False,
        artifact_created_at="2026-08-15T00:00:00Z",
        artifact_expires_at="2026-08-16T00:00:00Z",
        source_url_sha256="sha256:" + ("5" * 64),
        source_url_expires_at="2026-08-15T00:01:00Z",
        tag_ref="refs/tags/v0.74.0",
        tag_object_type="tag",
        tag_object_sha="b" * 40,
        policy_path=".agents/policy/github-branch-protection.yml",
        policy_source_commit_sha="a" * 40,
        policy_blob_sha="c" * 40,
        policy_sha256="sha256:" + ("d" * 64),
        provider_response_sha256="sha256:" + ("e" * 64),
        broker_request_id="request-01HXDPONE",
        candidate_reader_service_identity=(
            "cloudflare-worker:account-01/dpone-release-candidate-reader@candidate-reader-version-01"
        ),
        candidate_reader_service_version_id="candidate-reader-version-01",
        candidate_reader_deployment_observation_record_id=("sha256:" + ("8" * 64)),
        candidate_reader_deployment_observation_record_sha256=("sha256:" + ("9" * 64)),
    )


def golden_bytes() -> bytes:
    return encoded(request(), observation())
