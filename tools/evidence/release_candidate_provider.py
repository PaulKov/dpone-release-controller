"""Provider-bound raw Actions artifact ZIP verification and extraction.

The broker client is deliberately injected. Its HTTP response schema is not
guessed here: a reviewed client must first produce ``ProviderArtifactObservation``
from authenticated provider metadata and expose the exact bounded byte stream.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Protocol

from tools.evidence import release_candidate_contract as contract
from tools.evidence import release_candidate_files as files
from tools.evidence import release_candidate_provider_archive as provider_archive
from tools.evidence import release_candidate_provider_time as provider_time
from tools.evidence.release_canonical import MAX_SAFE_INTEGER, canonical_json_bytes

ARTIFACT_NAME = "release-candidates"
MAX_RAW_ZIP_BYTES = 805_306_368
MAX_EXPANDED_BYTES = provider_archive.MAX_EXPANDED_BYTES
MAX_ZIP_ENTRIES = provider_archive.MAX_ZIP_ENTRIES
EXPECTED_FILE_COUNT = provider_archive.EXPECTED_FILE_COUNT
PROVIDER_METADATA_SCHEMA = "dpone.github-actions-artifact-observation.v1"
PROVIDER_API_VERSION = "2026-03-10"
MAX_CLOCK_SKEW = timedelta(seconds=30)
MAX_SOURCE_URL_TTL = timedelta(seconds=60)
_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_SERVICE_IDENTITY_RE = re.compile(
    r"cloudflare-worker:[A-Za-z0-9_-]+/[a-z0-9-]+@[A-Za-z0-9._:-]{1,128}\Z",
    re.ASCII,
)
_WORKER_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)


class CandidateArchiveSource(Protocol):
    """One exact, already-authorized candidate artifact byte source."""

    def chunks(self, *, maximum_bytes: int) -> Iterable[bytes]:
        """Yield the response body once, stopping before ``maximum_bytes``."""


Clock = provider_time.Clock
SystemUtcClock = provider_time.SystemUtcClock
SYSTEM_UTC_CLOCK = provider_time.SYSTEM_UTC_CLOCK


@dataclass(frozen=True, slots=True)
class ProviderArtifactObservation:
    """Authenticated provider metadata returned by the candidate-read adapter."""

    schema: str
    schema_version: int
    provider_api_version: str
    repository: str
    repository_id: int
    release: str
    workflow_path: str
    event: str
    run_status: str
    head_branch: str
    head_sha: str
    run_id: int
    run_attempt: int
    conclusion: str
    artifact_id: int
    artifact_name: str
    artifact_digest: str
    artifact_size_bytes: int
    artifact_expired: bool
    artifact_created_at: str
    artifact_expires_at: str
    source_url_sha256: str
    source_url_expires_at: str
    tag_ref: str
    tag_object_type: str
    tag_object_sha: str
    policy_path: str
    policy_source_commit_sha: str
    policy_blob_sha: str
    policy_sha256: str
    provider_response_sha256: str
    broker_request_id: str
    candidate_reader_service_identity: str
    candidate_reader_service_version_id: str
    candidate_reader_deployment_observation_record_id: str
    candidate_reader_deployment_observation_record_sha256: str

    def require_matches(
        self,
        binding: contract.ArtifactBinding,
        *,
        now: datetime,
    ) -> None:
        """Cross-check every provider field before accepting artifact bytes."""

        integer_fields = {
            "schema_version": self.schema_version,
            "repository_id": self.repository_id,
            "run_id": self.run_id,
            "run_attempt": self.run_attempt,
            "artifact_id": self.artifact_id,
            "artifact_size_bytes": self.artifact_size_bytes,
        }
        if any(
            type(value) is not int or not 1 <= value <= MAX_SAFE_INTEGER
            for value in integer_fields.values()
        ):
            raise contract.CandidateHandoffError(
                "provider numeric fields must be positive JS-safe integers"
            )
        if type(self.artifact_expired) is not bool:
            raise contract.CandidateHandoffError(
                "provider artifact_expired must be boolean"
            )
        expected = {
            "schema": PROVIDER_METADATA_SCHEMA,
            "schema_version": 1,
            "provider_api_version": PROVIDER_API_VERSION,
            "repository": contract.TARGET_REPOSITORY,
            "repository_id": contract.TARGET_REPOSITORY_ID,
            "release": binding.expected_release,
            "workflow_path": contract.CANDIDATE_WORKFLOW_PATH,
            "event": "push",
            "run_status": "completed",
            "head_branch": binding.expected_release,
            "head_sha": binding.expected_peeled_commit_sha,
            "run_id": binding.run_id,
            "run_attempt": binding.run_attempt,
            "conclusion": "success",
            "artifact_id": binding.artifact_id,
            "artifact_name": ARTIFACT_NAME,
            "artifact_digest": binding.artifact_digest,
            "artifact_expired": False,
            "tag_ref": f"refs/tags/{binding.expected_release}",
            "tag_object_type": "tag",
            "policy_path": contract.POLICY_PATH,
            "policy_source_commit_sha": binding.expected_peeled_commit_sha,
        }
        actual = {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "provider_api_version": self.provider_api_version,
            "repository": self.repository,
            "repository_id": self.repository_id,
            "release": self.release,
            "workflow_path": self.workflow_path,
            "event": self.event,
            "run_status": self.run_status,
            "head_branch": self.head_branch,
            "head_sha": self.head_sha,
            "run_id": self.run_id,
            "run_attempt": self.run_attempt,
            "conclusion": self.conclusion,
            "artifact_id": self.artifact_id,
            "artifact_name": self.artifact_name,
            "artifact_digest": self.artifact_digest,
            "artifact_expired": self.artifact_expired,
            "tag_ref": self.tag_ref,
            "tag_object_type": self.tag_object_type,
            "policy_path": self.policy_path,
            "policy_source_commit_sha": self.policy_source_commit_sha,
        }
        mismatches = sorted(
            key for key, value in expected.items() if actual[key] != value
        )
        if mismatches:
            raise contract.CandidateHandoffError(
                f"provider candidate observation mismatch: {mismatches}"
            )
        if self.artifact_size_bytes > MAX_RAW_ZIP_BYTES:
            raise contract.CandidateHandoffError(
                "provider artifact size is outside bounds"
            )
        contract.require_digest(
            self.provider_response_sha256, "provider_response_sha256"
        )
        contract.require_digest(self.source_url_sha256, "source_url_sha256")
        contract.require_digest(self.policy_sha256, "provider policy_sha256")
        contract.require_commit(self.tag_object_sha, "provider tag_object_sha")
        contract.require_commit(self.policy_blob_sha, "provider policy_blob_sha")
        if _REQUEST_ID_RE.fullmatch(self.broker_request_id) is None:
            raise contract.CandidateHandoffError("broker request identity is invalid")
        if (
            _SERVICE_IDENTITY_RE.fullmatch(self.candidate_reader_service_identity)
            is None
            or _WORKER_VERSION_RE.fullmatch(self.candidate_reader_service_version_id)
            is None
        ):
            raise contract.CandidateHandoffError(
                "candidate reader service identity/version is invalid"
            )
        contract.require_digest(
            self.candidate_reader_deployment_observation_record_id,
            "candidate_reader_deployment_observation_record_id",
        )
        contract.require_digest(
            self.candidate_reader_deployment_observation_record_sha256,
            "candidate_reader_deployment_observation_record_sha256",
        )
        created = provider_time.timestamp(
            self.artifact_created_at, "artifact_created_at"
        )
        artifact_expires = provider_time.timestamp(
            self.artifact_expires_at, "artifact_expires_at"
        )
        source_expires = provider_time.timestamp(
            self.source_url_expires_at, "source_url_expires_at"
        )
        now = provider_time.utc_now(now)
        if (
            not created < artifact_expires
            or created > now + MAX_CLOCK_SKEW
            or artifact_expires <= now
            or source_expires <= now
            or source_expires > now + MAX_SOURCE_URL_TTL
            or source_expires > artifact_expires
        ):
            raise contract.CandidateHandoffError(
                "provider artifact/source timestamps are stale or inverted"
            )

    def require_manifest_authority(self, manifest: contract.CandidateManifest) -> None:
        """Bind fresh provider tag and policy reads to the imported manifest."""

        if (
            self.release != manifest.release
            or self.tag_object_sha != manifest.tag_object_sha
            or self.policy_sha256 != manifest.policy_sha256
            or self.head_sha != manifest.peeled_commit_sha
        ):
            raise contract.CandidateHandoffError(
                "provider tag/policy authority mismatches manifest"
            )


@dataclass(frozen=True, slots=True)
class VerifiedProviderArchive:
    """Raw provider ZIP proof retained in the candidate handoff receipt."""

    observation: ProviderArtifactObservation
    raw_zip_sha256: str
    raw_zip_size_bytes: int
    extracted_file_count: int
    extracted_total_bytes: int

    def receipt_payload(self) -> dict[str, Any]:
        """Project provider response and raw-byte proof without source URL secrets."""

        observation_sha256 = (
            "sha256:"
            + hashlib.sha256(canonical_json_bytes(asdict(self.observation))).hexdigest()
        )
        return {
            "candidate_artifact_id": self.observation.artifact_id,
            "candidate_artifact_digest": self.observation.artifact_digest,
            "candidate_artifact_raw_zip_sha256": self.raw_zip_sha256,
            "candidate_artifact_raw_zip_size_bytes": self.raw_zip_size_bytes,
            "candidate_artifact_provider_response_sha256": (
                self.observation.provider_response_sha256
            ),
            "candidate_artifact_provider_observation_sha256": observation_sha256,
            "candidate_artifact_broker_request_id": self.observation.broker_request_id,
            "candidate_artifact_provider_metadata_schema": self.observation.schema,
            "candidate_artifact_provider_api_version": (
                self.observation.provider_api_version
            ),
            "candidate_artifact_created_at": self.observation.artifact_created_at,
            "candidate_artifact_expires_at": self.observation.artifact_expires_at,
            "candidate_artifact_source_url_expires_at": (
                self.observation.source_url_expires_at
            ),
            "candidate_artifact_source_url_sha256": (
                self.observation.source_url_sha256
            ),
            "candidate_reader_service_identity": (
                self.observation.candidate_reader_service_identity
            ),
            "candidate_reader_service_version_id": (
                self.observation.candidate_reader_service_version_id
            ),
            "candidate_reader_deployment_observation_record_id": (
                self.observation.candidate_reader_deployment_observation_record_id
            ),
            "candidate_reader_deployment_observation_record_sha256": (
                self.observation.candidate_reader_deployment_observation_record_sha256
            ),
            "candidate_artifact_tag_object_sha": self.observation.tag_object_sha,
            "candidate_artifact_policy_blob_sha": self.observation.policy_blob_sha,
            "candidate_artifact_policy_sha256": self.observation.policy_sha256,
            "candidate_artifact_file_count": self.extracted_file_count,
            "candidate_artifact_expanded_bytes": self.extracted_total_bytes,
        }


def verify_and_extract_provider_archive(
    source: CandidateArchiveSource,
    observation: ProviderArtifactObservation,
    binding: contract.ArtifactBinding,
    destination: Path,
    *,
    clock: Clock = SYSTEM_UTC_CLOCK,
) -> VerifiedProviderArchive:
    """Hash an exact raw ZIP, validate its directory, then extract atomically."""

    observation.require_matches(binding, now=clock.now())
    if destination.exists() or destination.is_symlink():
        raise contract.CandidateHandoffError(
            "candidate extraction destination must not exist"
        )
    destination = destination.absolute()
    contract.require_safe_path(destination.name, "candidate destination name")
    destination_parent = files.require_root(destination.parent)

    digest = hashlib.sha256()
    observed = 0
    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b") as raw_zip:
        for chunk in source.chunks(maximum_bytes=MAX_RAW_ZIP_BYTES):
            if not isinstance(chunk, bytes) or not chunk:
                raise contract.CandidateHandoffError(
                    "candidate byte source yielded an invalid chunk"
                )
            observed += len(chunk)
            if observed > MAX_RAW_ZIP_BYTES:
                raise contract.CandidateHandoffError(
                    "candidate raw ZIP exceeds byte limit"
                )
            raw_zip.write(chunk)
            digest.update(chunk)
        if observed != observation.artifact_size_bytes:
            raise contract.CandidateHandoffError(
                "provider artifact response size mismatch"
            )
        raw_digest = "sha256:" + digest.hexdigest()
        if raw_digest != binding.artifact_digest:
            raise contract.CandidateHandoffError("raw provider ZIP digest mismatch")
        raw_zip.seek(0)
        parent_descriptor = files.open_directory_no_follow(destination_parent)
        temporary_root: Path | None = None
        try:
            temporary_root = Path(
                tempfile.mkdtemp(prefix=".candidate-import-", dir=destination_parent)
            )
            file_count, expanded = provider_archive.validate_and_extract(
                raw_zip, temporary_root
            )
            os.rename(
                temporary_root.name,
                destination.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            os.fsync(parent_descriptor)
        except Exception:
            if temporary_root is not None:
                shutil.rmtree(temporary_root, ignore_errors=True)
            raise
        finally:
            os.close(parent_descriptor)
    return VerifiedProviderArchive(
        observation=observation,
        raw_zip_sha256=raw_digest,
        raw_zip_size_bytes=observed,
        extracted_file_count=file_count,
        extracted_total_bytes=expanded,
    )
