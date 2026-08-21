"""Closed broker streaming transport for one provider-bound candidate ZIP.

The GitHub signed artifact URL remains inside the private broker. The
controller receives a one-shot byte stream plus a bounded canonical provider
observation in response headers; no App token or redirect URL is exposed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Protocol

from tools.evidence import release_candidate_contract as contract
from tools.evidence.release_canonical import canonical_json_bytes
from tools.evidence.release_canonical import CanonicalJsonError

REQUEST_SCHEMA = "dpone.release-candidate-stream-request.v1"
RESPONSE_SCHEMA = "dpone.release-candidate-stream-response.v1"
PATH = "/v1/providers/github/candidate"
METHOD = "POST"
CONTENT_TYPE = "application/vnd.dpone.release-candidate-artifact.v1+zip"
CACHE_CONTROL = "private, no-store, max-age=0"
MAX_OBSERVATION_BYTES = 8_192
MAX_OBSERVATION_HEADER_CHARS = 10_923


class CandidateStreamResponse(Protocol):
    """Injected HTTP response; implementations must not buffer the ZIP."""

    status_code: int
    headers: Mapping[str, str]

    def chunks(self, *, maximum_bytes: int) -> Iterable[bytes]:
        """Yield body bytes at most once under the supplied hard limit."""


@dataclass(frozen=True, slots=True)
class CandidateReaderAuthority:
    """A0/A1-bound private service identity expected by this controller run."""

    service_identity: str
    service_version_id: str


@dataclass(frozen=True, slots=True)
class CandidateStreamRequest:
    """The six candidate selectors; provider authority is never caller input."""

    tag: str
    expected_peeled_commit_sha: str
    candidate_run_id: int
    candidate_run_attempt: int
    candidate_artifact_id: int
    candidate_artifact_digest: str

    @classmethod
    def from_binding(cls, value: contract.ArtifactBinding) -> "CandidateStreamRequest":
        return cls(
            tag=value.expected_release,
            expected_peeled_commit_sha=value.expected_peeled_commit_sha,
            candidate_run_id=value.run_id,
            candidate_run_attempt=value.run_attempt,
            candidate_artifact_id=value.artifact_id,
            candidate_artifact_digest=value.artifact_digest,
        )

    def document(self) -> dict[str, Any]:
        """Return the canonical JSON request body."""

        binding = contract.ArtifactBinding(
            run_id=contract.require_positive_int(
                self.candidate_run_id, "candidate_run_id"
            ),
            run_attempt=contract.require_positive_int(
                self.candidate_run_attempt, "candidate_run_attempt"
            ),
            artifact_id=contract.require_positive_int(
                self.candidate_artifact_id, "candidate_artifact_id"
            ),
            artifact_digest=self.candidate_artifact_digest,
            expected_release=self.tag,
            expected_peeled_commit_sha=self.expected_peeled_commit_sha,
        )
        contract.require_digest(binding.artifact_digest, "candidate_artifact_digest")
        contract.require_release(binding.expected_release)
        contract.require_commit(
            binding.expected_peeled_commit_sha, "expected_peeled_commit_sha"
        )
        return {
            "schema": REQUEST_SCHEMA,
            "schema_version": 1,
            "tag": binding.expected_release,
            "expected_peeled_commit_sha": binding.expected_peeled_commit_sha,
            "candidate_run_id": binding.run_id,
            "candidate_run_attempt": binding.run_attempt,
            "candidate_artifact_id": binding.artifact_id,
            "candidate_artifact_digest": binding.artifact_digest,
        }

    def encoded(self) -> bytes:
        return canonical_json_bytes(self.document())

    @classmethod
    def parse(cls, data: bytes) -> "CandidateStreamRequest":
        """Parse exact canonical selector bytes without accepting field aliases."""

        try:
            raw = json.loads(data, object_pairs_hook=_unique_object)
            if not isinstance(raw, dict) or canonical_json_bytes(raw) != data:
                raise contract.CandidateHandoffError(
                    "candidate stream request is not canonical JSON"
                )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            CanonicalJsonError,
            contract.CandidateHandoffError,
        ) as exc:
            raise contract.CandidateHandoffError(
                "candidate stream request is invalid"
            ) from exc
        expected = {
            "candidate_artifact_digest",
            "candidate_artifact_id",
            "candidate_run_attempt",
            "candidate_run_id",
            "expected_peeled_commit_sha",
            "schema",
            "schema_version",
            "tag",
        }
        if (
            set(raw) != expected
            or raw["schema"] != REQUEST_SCHEMA
            or raw["schema_version"] != 1
        ):
            raise contract.CandidateHandoffError(
                "candidate stream request keys/schema are not exact"
            )
        result = cls(
            tag=raw["tag"],
            expected_peeled_commit_sha=raw["expected_peeled_commit_sha"],
            candidate_run_id=raw["candidate_run_id"],
            candidate_run_attempt=raw["candidate_run_attempt"],
            candidate_artifact_id=raw["candidate_artifact_id"],
            candidate_artifact_digest=raw["candidate_artifact_digest"],
        )
        if result.document() != raw:
            raise contract.CandidateHandoffError("candidate stream request drift")
        return result


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise contract.CandidateHandoffError(f"duplicate JSON key: {key}")
        result[key] = value
    return result
