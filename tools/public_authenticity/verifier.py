"""Offline-input authenticity adapter for a future public release archive.

This module does not generate an attestation and cannot lift the controller
HOLD. It invokes one content-pinned GitHub CLI binary against caller-supplied
bundle and trusted-root files, while requiring the exact repository, workflow,
tag-ref claim and source commit recorded by the future A0 authority record.

GitHub CLI owns Sigstore certificate, transparency-log and subject-digest
verification. This wrapper owns the closed invocation contract and converts a
successful verification into a content-addressed observation suitable for
later A0/A1 admission. Offline inputs are mandatory; OS-level network
isolation remains a separate activation ceremony requirement.
"""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from tools.public_authenticity.files import (
    AuthenticityFileError,
    closed_environment,
    snapshot_file,
)

from tools.public_authenticity.process import (
    BoundedProcessError,
    run_bounded_process,
)

SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
SEMVER_NUMBER = r"(?:0|[1-9][0-9]*)"
TAG_REF = re.compile(rf"refs/tags/v{SEMVER_NUMBER}\.{SEMVER_NUMBER}\.{SEMVER_NUMBER}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
WORKFLOW = re.compile(
    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml\Z"
)

MAX_ARTIFACT_BYTES = 805_306_368
MAX_BUNDLE_BYTES = 8_388_608
MAX_TRUSTED_ROOT_BYTES = 8_388_608
MAX_VERIFIER_OUTPUT_BYTES = 8_388_608
MAX_VERIFIER_STDERR_BYTES = 1_048_576
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"


class PublicAuthenticityError(RuntimeError):
    """Stable fail-closed error for the offline-input authenticity boundary."""


@dataclass(frozen=True, slots=True)
class PublicAuthenticityPolicy:
    """Exact immutable identity expected from the signed attestation."""

    artifact_sha256: str
    bundle_sha256: str
    trusted_root_sha256: str
    repository: str
    signer_workflow: str
    signer_digest: str
    source_digest: str
    source_ref: str
    gh_binary_sha256: str
    predicate_type: str = PREDICATE_TYPE
    oidc_issuer: str = OIDC_ISSUER

    def validate(self) -> None:
        for label, digest in (
            ("ARTIFACT", self.artifact_sha256),
            ("BUNDLE", self.bundle_sha256),
            ("TRUSTED_ROOT", self.trusted_root_sha256),
        ):
            if SHA256.fullmatch(digest) is None:
                raise PublicAuthenticityError(f"PUBLIC_AUTH_{label}_DIGEST_INVALID")
        if REPOSITORY.fullmatch(self.repository) is None:
            raise PublicAuthenticityError("PUBLIC_AUTH_REPOSITORY_INVALID")
        if WORKFLOW.fullmatch(self.signer_workflow) is None:
            raise PublicAuthenticityError("PUBLIC_AUTH_WORKFLOW_INVALID")
        if GIT_SHA.fullmatch(self.signer_digest) is None:
            raise PublicAuthenticityError("PUBLIC_AUTH_SIGNER_DIGEST_INVALID")
        if GIT_SHA.fullmatch(self.source_digest) is None:
            raise PublicAuthenticityError("PUBLIC_AUTH_SOURCE_DIGEST_INVALID")
        if TAG_REF.fullmatch(self.source_ref) is None:
            raise PublicAuthenticityError("PUBLIC_AUTH_SOURCE_REF_INVALID")
        if SHA256.fullmatch(self.gh_binary_sha256) is None:
            raise PublicAuthenticityError("PUBLIC_AUTH_VERIFIER_DIGEST_INVALID")
        if self.predicate_type != PREDICATE_TYPE:
            raise PublicAuthenticityError("PUBLIC_AUTH_PREDICATE_INVALID")
        if self.oidc_issuer != OIDC_ISSUER:
            raise PublicAuthenticityError("PUBLIC_AUTH_ISSUER_INVALID")


@dataclass(frozen=True, slots=True)
class PublicAuthenticityObservation:
    """Content-addressed result; not a caller-constructible authority record."""

    artifact_sha256: str
    bundle_sha256: str
    trusted_root_sha256: str
    verifier_binary_sha256: str
    verifier_output_sha256: str
    verifier_stderr_sha256: str
    repository: str
    signer_workflow: str
    signer_digest: str
    source_digest: str
    source_ref: str
    predicate_type: str
    oidc_issuer: str

    def as_dict(self) -> dict[str, object]:
        """Project verifier output; future A0 must rerun and retain raw evidence."""
        return {
            "artifact_sha256": self.artifact_sha256,
            "bundle_sha256": self.bundle_sha256,
            "oidc_issuer": self.oidc_issuer,
            "predicate_type": self.predicate_type,
            "repository": self.repository,
            "schema": "dpone.release-public-authenticity-observation.v1",
            "schema_version": 1,
            "signer_digest": self.signer_digest,
            "signer_workflow": self.signer_workflow,
            "source_digest": self.source_digest,
            "source_ref": self.source_ref,
            "trusted_root_sha256": self.trusted_root_sha256,
            "verifier_binary_sha256": self.verifier_binary_sha256,
            "verifier_output_sha256": self.verifier_output_sha256,
            "verifier_stderr_sha256": self.verifier_stderr_sha256,
        }


def verify_public_archive_authenticity(
    *,
    artifact: Path,
    bundle: Path,
    gh_binary: Path,
    policy: PublicAuthenticityPolicy,
    trusted_root: Path,
) -> PublicAuthenticityObservation:
    """Verify one public archive with exact offline GitHub/Sigstore inputs."""
    policy.validate()
    try:
        with tempfile.TemporaryDirectory(prefix="dpone-public-auth-") as temporary:
            snapshot_root = Path(temporary)
            artifact_copy, artifact_sha = _snapshot(
                artifact,
                snapshot_root / "public-closure.zip",
                MAX_ARTIFACT_BYTES,
                "ARTIFACT",
            )
            bundle_copy, bundle_sha = _snapshot(
                bundle, snapshot_root / "bundle.jsonl", MAX_BUNDLE_BYTES, "BUNDLE"
            )
            root_copy, root_sha = _snapshot(
                trusted_root,
                snapshot_root / "trusted-root.jsonl",
                MAX_TRUSTED_ROOT_BYTES,
                "TRUSTED_ROOT",
            )
            verifier_copy, verifier_sha = _snapshot(
                gh_binary,
                snapshot_root / "gh",
                134_217_728,
                "VERIFIER",
                executable=True,
            )
            _require_digest("ARTIFACT", artifact_sha, policy.artifact_sha256)
            _require_digest("BUNDLE", bundle_sha, policy.bundle_sha256)
            _require_digest("TRUSTED_ROOT", root_sha, policy.trusted_root_sha256)
            if verifier_sha != policy.gh_binary_sha256:
                raise PublicAuthenticityError("PUBLIC_AUTH_VERIFIER_DIGEST_MISMATCH")
            command = _command(
                artifact=artifact_copy,
                bundle=bundle_copy,
                gh_binary=verifier_copy,
                policy=policy,
                trusted_root=root_copy,
            )
            try:
                result = run_bounded_process(
                    command,
                    cwd=snapshot_root,
                    env=closed_environment(snapshot_root),
                    max_stderr_bytes=MAX_VERIFIER_STDERR_BYTES,
                    max_stdout_bytes=MAX_VERIFIER_OUTPUT_BYTES,
                    timeout_seconds=120,
                )
            except AuthenticityFileError as error:
                raise PublicAuthenticityError(str(error)) from error
            except BoundedProcessError as error:
                raise PublicAuthenticityError(
                    f"PUBLIC_AUTH_VERIFIER_{error}"
                ) from error
            if result.returncode != 0:
                raise PublicAuthenticityError("PUBLIC_AUTH_VERIFICATION_FAILED")
            output = bytes(result.stdout)
            if not output or len(output) > MAX_VERIFIER_OUTPUT_BYTES:
                raise PublicAuthenticityError("PUBLIC_AUTH_VERIFIER_OUTPUT_INVALID")
            _validate_verifier_output(output, artifact_sha, policy)
    except OSError as error:
        raise PublicAuthenticityError("PUBLIC_AUTH_SNAPSHOT_UNAVAILABLE") from error

    return PublicAuthenticityObservation(
        artifact_sha256=f"sha256:{artifact_sha}",
        bundle_sha256=f"sha256:{bundle_sha}",
        trusted_root_sha256=f"sha256:{root_sha}",
        verifier_binary_sha256=f"sha256:{verifier_sha}",
        verifier_output_sha256=f"sha256:{hashlib.sha256(output).hexdigest()}",
        verifier_stderr_sha256=(
            f"sha256:{hashlib.sha256(bytes(result.stderr)).hexdigest()}"
        ),
        repository=policy.repository,
        signer_workflow=policy.signer_workflow,
        signer_digest=policy.signer_digest,
        source_digest=policy.source_digest,
        source_ref=policy.source_ref,
        predicate_type=policy.predicate_type,
        oidc_issuer=policy.oidc_issuer,
    )


def _command(
    *,
    artifact: Path,
    bundle: Path,
    gh_binary: Path,
    policy: PublicAuthenticityPolicy,
    trusted_root: Path,
) -> tuple[str, ...]:
    return (
        str(gh_binary),
        "attestation",
        "verify",
        str(artifact),
        "--repo",
        policy.repository,
        "--hostname",
        "github.com",
        "--bundle",
        str(bundle),
        "--custom-trusted-root",
        str(trusted_root),
        "--predicate-type",
        policy.predicate_type,
        "--digest-alg",
        "sha256",
        "--cert-oidc-issuer",
        policy.oidc_issuer,
        "--cert-identity",
        f"https://github.com/{policy.signer_workflow}@{policy.source_ref}",
        "--signer-digest",
        policy.signer_digest,
        "--source-digest",
        policy.source_digest,
        "--source-ref",
        policy.source_ref,
        "--deny-self-hosted-runners",
        "--format",
        "json",
    )


def _snapshot(
    path: Path,
    destination: Path,
    maximum: int,
    label: str,
    *,
    executable: bool = False,
) -> tuple[Path, str]:
    try:
        return snapshot_file(path, destination, maximum, label, executable=executable)
    except AuthenticityFileError as error:
        raise PublicAuthenticityError(str(error)) from error


def _require_digest(label: str, actual: str, expected: str) -> None:
    if actual != expected:
        raise PublicAuthenticityError(f"PUBLIC_AUTH_{label}_DIGEST_MISMATCH")


def _validate_verifier_output(
    output: bytes, artifact_sha256: str, policy: PublicAuthenticityPolicy
) -> None:
    try:
        document = json.loads(output)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise PublicAuthenticityError("PUBLIC_AUTH_VERIFIER_OUTPUT_INVALID") from error
    if not isinstance(document, list) or len(document) != 1:
        raise PublicAuthenticityError("PUBLIC_AUTH_VERIFIER_RESULT_COUNT_INVALID")
    entry = document[0]
    if not isinstance(entry, dict) or set(entry) != {
        "attestation",
        "verificationResult",
    }:
        raise PublicAuthenticityError("PUBLIC_AUTH_VERIFIER_RESULT_SHAPE_INVALID")
    result = entry["verificationResult"]
    if not isinstance(result, dict):
        raise PublicAuthenticityError("PUBLIC_AUTH_VERIFIER_RESULT_SHAPE_INVALID")
    signature = result.get("signature")
    certificate = signature.get("certificate") if isinstance(signature, dict) else None
    if not isinstance(certificate, dict) or not certificate:
        raise PublicAuthenticityError("PUBLIC_AUTH_VERIFIER_SIGNATURE_MISSING")
    timestamps = result.get("verifiedTimestamps")
    if not isinstance(timestamps, list) or not timestamps:
        raise PublicAuthenticityError("PUBLIC_AUTH_VERIFIER_TIMESTAMP_MISSING")
    if not any(
        isinstance(timestamp, dict)
        and timestamp.get("type") == "Tlog"
        and isinstance(timestamp.get("uri"), str)
        and bool(timestamp["uri"])
        and isinstance(timestamp.get("timestamp"), str)
        and bool(timestamp["timestamp"])
        for timestamp in timestamps
    ):
        raise PublicAuthenticityError("PUBLIC_AUTH_VERIFIER_TLOG_MISSING")
    statement = result.get("statement")
    if (
        not isinstance(statement, dict)
        or statement.get("predicateType") != PREDICATE_TYPE
    ):
        raise PublicAuthenticityError("PUBLIC_AUTH_VERIFIER_PREDICATE_MISMATCH")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise PublicAuthenticityError("PUBLIC_AUTH_VERIFIER_SUBJECT_INVALID")
    subject = subjects[0]
    if not isinstance(subject, dict) or subject.get("digest") != {
        "sha256": artifact_sha256
    }:
        raise PublicAuthenticityError("PUBLIC_AUTH_VERIFIER_SUBJECT_INVALID")
    expected_identity = (
        f"https://github.com/{policy.signer_workflow}@{policy.source_ref}"
    )
    expected_certificate = {
        "buildSignerDigest": policy.signer_digest,
        "issuer": policy.oidc_issuer,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryDigest": policy.source_digest,
        "sourceRepositoryOwnerURI": (
            f"https://github.com/{policy.repository.split('/', 1)[0]}"
        ),
        "sourceRepositoryRef": policy.source_ref,
        "sourceRepositoryURI": f"https://github.com/{policy.repository}",
        "subjectAlternativeName": expected_identity,
    }
    for field, expected in expected_certificate.items():
        if certificate.get(field) != expected:
            raise PublicAuthenticityError(
                "PUBLIC_AUTH_VERIFIER_CERTIFICATE_CLAIM_MISMATCH"
            )
    identity = result.get("verifiedIdentity")
    if not isinstance(identity, dict) or identity.get("subjectAlternativeName") != {
        "subjectAlternativeName": expected_identity
    }:
        raise PublicAuthenticityError("PUBLIC_AUTH_VERIFIER_IDENTITY_MISMATCH")
    if identity.get("issuer") != {"issuer": "", "regexp": ".*"}:
        raise PublicAuthenticityError("PUBLIC_AUTH_VERIFIER_POLICY_SHAPE_INVALID")
    if identity.get("runnerEnvironment") != "github-hosted":
        raise PublicAuthenticityError("PUBLIC_AUTH_VERIFIER_POLICY_SHAPE_INVALID")


def canonical_observation_bytes(observation: PublicAuthenticityObservation) -> bytes:
    """Return deterministic bytes without claiming public-closure activation."""
    return json.dumps(
        observation.as_dict(),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
