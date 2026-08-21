"""Immutable types and fixed identities for candidate handoff v2."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Mapping

from tools.evidence import release_identity
from tools.evidence import release_pypi_limits
from tools.evidence import release_receipt_contract
from tools.evidence import release_receipt_inventory
from tools.evidence.release_canonical import MAX_SAFE_INTEGER

SCHEMA = "dpone.release-candidate-handoff.v2"
SCHEMA_VERSION = 2
MANIFEST_PATH = "candidate-handoff-v2.json"
TARGET_REPOSITORY = "PaulKov/dpone"
TARGET_REPOSITORY_ID = release_identity.TARGET_REPOSITORY_ID
CANDIDATE_WORKFLOW_PATH = ".github/workflows/release.yml"
POLICY_PATH = ".agents/policy/github-branch-protection.yml"
PROTECTED_BASE_REF = release_identity.PROTECTED_BASE_REF
PROJECTS = release_identity.PROJECTS
CHECKSUM_PATH = "release-candidate-sha256sums.txt"
SUPPORT_MEMBERS = tuple(
    sorted(
        (
            CHECKSUM_PATH,
            "release_notes.md",
            "evidence/preflight/release_identity.json",
            "evidence/preflight/exact_commit_checks.json",
            "evidence/preflight/exact_commit_merge_receipt.json",
            "evidence/preflight/release_candidate_evidence_verification.json",
            "evidence/preflight/workflow_context.json",
            "evidence/candidate/candidate-inventory.json",
            "evidence/candidate/package-archive-gate.json",
            "evidence/candidate/pip-check.txt",
            "evidence/candidate/candidate-versions.json",
            "evidence/candidate/package-smoke.txt",
            "evidence/supply-chain/unsigned-sbom.spdx.json",
            "evidence/supply-chain/unsigned-sbom.cyclonedx.json",
            "evidence/supply-chain/unsigned-provenance.intoto.json",
            "evidence/supply-chain/unsigned-supply-chain-diagnostic.json",
        ),
        key=lambda value: value.encode("utf-8"),
    )
)
SUPPLEMENTAL_UNSIGNED_MEMBERS = tuple(
    sorted(
        (
            "evidence/supply-chain/unsigned-sbom.spdx.json",
            "evidence/supply-chain/unsigned-sbom.cyclonedx.json",
            "evidence/supply-chain/unsigned-provenance.intoto.json",
            "evidence/supply-chain/unsigned-supply-chain-diagnostic.json",
        ),
        key=lambda value: value.encode("utf-8"),
    )
)
CANDIDATE_INVENTORY_PATH = "evidence/candidate/candidate-inventory.json"
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 768 * 1024 * 1024
EXPECTED_DECLARED_MEMBER_COUNT = 24
EXPECTED_PROVIDER_FILE_COUNT = EXPECTED_DECLARED_MEMBER_COUNT + 1
MAX_MEMBER_COUNT = EXPECTED_PROVIDER_FILE_COUNT

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_POSITIVE_INTEGER_RE = re.compile(r"[1-9][0-9]*\Z")
_TAG_RE = re.compile(
    r"v(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\Z"
)
_PROJECT_NORMALIZER_RE = re.compile(r"[-_.]+")


class CandidateHandoffError(ValueError):
    """Candidate artifact is incomplete, ambiguous, or identity-mismatched."""


@dataclass(frozen=True, slots=True)
class ArtifactBinding:
    """Outer GitHub Actions identity supplied as untrusted dispatch selectors."""

    run_id: int
    run_attempt: int
    artifact_id: int
    artifact_digest: str
    expected_release: str
    expected_peeled_commit_sha: str

    @classmethod
    def from_strings(
        cls,
        *,
        run_id: str,
        run_attempt: str,
        artifact_id: str,
        artifact_digest: str,
        expected_tag: str,
        expected_peeled_commit_sha: str,
    ) -> "ArtifactBinding":
        """Parse selectors without signs, Unicode digits, zero or aliases."""

        raw_integers = {
            "candidate_run_id": run_id,
            "candidate_run_attempt": run_attempt,
            "candidate_artifact_id": artifact_id,
        }
        parsed: dict[str, int] = {}
        for name, value in raw_integers.items():
            if _POSITIVE_INTEGER_RE.fullmatch(value) is None:
                raise CandidateHandoffError(f"{name} must be a positive ASCII integer")
            parsed[name] = int(value)
            if parsed[name] > MAX_SAFE_INTEGER:
                raise CandidateHandoffError(f"{name} exceeds the JS-safe range")
        require_digest(artifact_digest, "candidate_artifact_digest")
        require_release(expected_tag)
        require_commit(expected_peeled_commit_sha, "expected_peeled_commit_sha")
        return cls(
            run_id=parsed["candidate_run_id"],
            run_attempt=parsed["candidate_run_attempt"],
            artifact_id=parsed["candidate_artifact_id"],
            artifact_digest=artifact_digest,
            expected_release=expected_tag,
            expected_peeled_commit_sha=expected_peeled_commit_sha,
        )


@dataclass(frozen=True, slots=True)
class FileRecord:
    """One closed artifact member declared by the handoff manifest."""

    path: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class DistributionRecord(FileRecord):
    """One archive rederived from the bound candidate inventory."""

    package: str
    filename: str
    artifact_type: str
    version: str


@dataclass(frozen=True, slots=True)
class CandidateManifest:
    """Validated semantic projection of ``candidate-handoff-v2.json``."""

    release: str
    tag_object_sha: str
    peeled_commit_sha: str
    policy_sha256: str
    run_id: int
    run_attempt: int
    release_identity_id: str
    release_authority_id: str
    candidate_inventory_sha256: str
    candidate_id: str
    manifest_sha256: str
    members: tuple[FileRecord, ...]
    supplemental_unsigned_members: tuple[str, ...]
    distributions: tuple[DistributionRecord, ...] = ()


@dataclass(frozen=True, slots=True)
class VerifiedCandidate:
    """Exact result safe to place in a ``CANDIDATE_HANDOFF`` receipt."""

    binding: ArtifactBinding
    manifest: CandidateManifest
    total_bytes: int
    file_count: int

    def receipt_payload(self) -> dict[str, Any]:
        """Return the canonical outer/inner binding for the durable ledger."""

        distributions = [
            {
                "project": record.package,
                "version": record.version,
                "filename": record.filename,
                "size_bytes": record.size_bytes,
                "sha256": record.sha256,
            }
            for record in self.manifest.distributions
        ]
        try:
            normalized = release_receipt_inventory.distribution_inventory(distributions)
        except release_receipt_contract.ReceiptValidationError as exc:
            raise CandidateHandoffError(
                f"candidate distribution receipt projection is invalid: {exc}"
            ) from exc
        return {
            "kind": "CANDIDATE_HANDOFF",
            "state": "CANDIDATE_HANDOFF",
            "candidate_id": self.manifest.candidate_id,
            "candidate_inventory_sha256": (self.manifest.candidate_inventory_sha256),
            "candidate_run_id": self.binding.run_id,
            "candidate_run_attempt": self.binding.run_attempt,
            "candidate_artifact_id": self.binding.artifact_id,
            "candidate_artifact_digest": self.binding.artifact_digest,
            "candidate_manifest_sha256": self.manifest.manifest_sha256,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "distribution_inventory": list(normalized),
            "distribution_inventory_sha256": (
                release_receipt_inventory.inventory_sha256(
                    release_receipt_inventory.DISTRIBUTION_SCHEMA,
                    normalized,
                )
            ),
        }


def require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise CandidateHandoffError(f"{name} must be an object")
    return value


def require_list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise CandidateHandoffError(f"{name} must be an array")
    return value


def require_exact_keys(raw: Mapping[str, Any], expected: set[str], name: str) -> None:
    actual = set(raw)
    if actual != expected:
        raise CandidateHandoffError(
            f"{name} keys mismatch: missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )


def require_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise CandidateHandoffError(f"{name} must be a non-empty string")
    return value


def require_positive_int(value: Any, name: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_SAFE_INTEGER:
        raise CandidateHandoffError(f"{name} must be a positive JS-safe integer")
    return value


def require_file_size(value: Any, path: str) -> int:
    size = require_positive_int(value, f"size for {path}")
    if size > MAX_FILE_BYTES:
        raise CandidateHandoffError(f"declared size exceeds limit: {path}")
    return size


def require_distribution_size(value: Any, path: str) -> int:
    """Require one dist member to satisfy generic and frozen PyPI limits."""

    size = require_file_size(value, path)
    try:
        return release_pypi_limits.require_file_size(size, path)
    except release_pypi_limits.PyPISizeLimitError as exc:
        raise CandidateHandoffError(str(exc)) from exc


def require_distribution_inventory_sizes(
    records: tuple[DistributionRecord, ...],
) -> int:
    """Require the exact distribution matrix to fit the A1 PyPI budget."""

    try:
        return release_pypi_limits.require_inventory_sizes(
            (record.size_bytes for record in records),
            "candidate distribution inventory",
        )
    except release_pypi_limits.PyPISizeLimitError as exc:
        raise CandidateHandoffError(str(exc)) from exc


def require_safe_path(value: Any, name: str) -> str:
    path = require_string(value, name)
    pure = PurePosixPath(path)
    if (
        len(path.encode("utf-8")) > 240
        or pure.is_absolute()
        or path != pure.as_posix()
        or any(part in {"", ".", ".."} for part in pure.parts)
        or ":" in path
        or "\\" in path
        or "\x00" in path
    ):
        raise CandidateHandoffError(f"{name} is not a canonical relative path")
    return path


def require_release(value: str) -> None:
    if len(value) > 128 or _TAG_RE.fullmatch(value) is None:
        raise CandidateHandoffError(
            "release must be canonical stable vMAJOR.MINOR.PATCH"
        )


def require_commit(value: str, name: str) -> None:
    if _COMMIT_RE.fullmatch(value) is None:
        raise CandidateHandoffError(f"{name} must be a full lowercase commit SHA")


def require_digest(value: str, name: str) -> None:
    if _SHA256_RE.fullmatch(value) is None:
        raise CandidateHandoffError(f"{name} must be sha256:<64 lowercase hex>")


def require_digest_value(value: Any, name: str) -> str:
    digest = require_string(value, name)
    require_digest(digest, name)
    return digest


def normalize_project(value: str) -> str:
    """Return the PEP 503 normalized project name."""

    return _PROJECT_NORMALIZER_RE.sub("-", value).lower()
