"""Single authoritative release-trust v2 identity codec.

Every language implementation consumes the golden vectors generated from this
module.  Callers cannot opt into legacy field aliases or project ordering.
"""

from __future__ import annotations

import re
from typing import Any

from tools.evidence.release_canonical import sha256_id

RELEASE_IDENTITY_DOMAIN = "dpone.release.identity.v2"
RELEASE_AUTHORITY_DOMAIN = "dpone.release.authority.v2"
CANDIDATE_DOMAIN = "dpone.release.candidate.v2"
ATTEMPT_DOMAIN = "dpone.release.attempt.v2"
TARGET_REPOSITORY_ID = 1_255_975_556
CONTROLLER_REPOSITORY_ID = 1_305_993_853
MAX_SAFE_INTEGER = 9_007_199_254_740_991
PROTECTED_BASE_REF = "refs/heads/master"
PROJECTS = (
    "apache-airflow-providers-dpone",
    "dpone",
    "dpone-airflow-pack",
    "dpone-native-accel",
)

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_RELEASE_RE = re.compile(
    r"v(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\Z"
)


class ReleaseIdentityError(ValueError):
    """A release identity input is non-canonical or outside its domain."""


def release_identity_payload(release: str) -> dict[str, Any]:
    """Return the exact release identity payload for the target repository."""

    _require_match(release, _RELEASE_RE, "release")
    return {
        "repository_id": TARGET_REPOSITORY_ID,
        "release": release,
        "projects": list(PROJECTS),
    }


def release_identity_id(release: str) -> str:
    """Derive the domain-separated identity of one stable release."""

    return sha256_id(RELEASE_IDENTITY_DOMAIN, release_identity_payload(release))


def release_authority_payload(
    *,
    release_identity_id: str,
    tag_object_sha: str,
    peeled_commit_sha: str,
    policy_sha256: str,
) -> dict[str, Any]:
    """Return the exact annotated-tag and frozen-policy authority payload."""

    _require_digest(release_identity_id, "release_identity_id")
    _require_match(tag_object_sha, _COMMIT_RE, "tag_object_sha")
    _require_match(peeled_commit_sha, _COMMIT_RE, "peeled_commit_sha")
    if tag_object_sha == peeled_commit_sha:
        raise ReleaseIdentityError(
            "annotated tag object must differ from peeled commit"
        )
    _require_digest(policy_sha256, "policy_sha256")
    return {
        "release_identity_id": release_identity_id,
        "tag_object_sha": tag_object_sha,
        "peeled_commit_sha": peeled_commit_sha,
        "policy_sha256": policy_sha256,
        "protected_base_ref": PROTECTED_BASE_REF,
    }


def release_authority_id(**values: str) -> str:
    """Derive the exact frozen release-authority identity."""

    return sha256_id(RELEASE_AUTHORITY_DOMAIN, release_authority_payload(**values))


def candidate_payload(
    *,
    release_authority_id: str,
    candidate_inventory_sha256: str,
) -> dict[str, Any]:
    """Return the exact raw-inventory-bound candidate payload."""

    _require_digest(release_authority_id, "release_authority_id")
    _require_digest(candidate_inventory_sha256, "candidate_inventory_sha256")
    return {
        "release_authority_id": release_authority_id,
        "candidate_inventory_sha256": candidate_inventory_sha256,
    }


def candidate_id(**values: str) -> str:
    """Derive one candidate identity from the raw inventory digest."""

    return sha256_id(CANDIDATE_DOMAIN, candidate_payload(**values))


def attempt_payload(
    *,
    release_authority_id: str,
    controller_workflow_id: int,
    controller_run_id: int,
    controller_run_attempt: int,
) -> dict[str, Any]:
    """Return the exact controller-run publication attempt payload."""

    _require_digest(release_authority_id, "release_authority_id")
    _require_positive_int(controller_workflow_id, "controller_workflow_id")
    _require_positive_int(controller_run_id, "controller_run_id")
    _require_positive_int(controller_run_attempt, "controller_run_attempt")
    return {
        "release_authority_id": release_authority_id,
        "controller_repository_id": CONTROLLER_REPOSITORY_ID,
        "controller_workflow_id": controller_workflow_id,
        "controller_run_id": controller_run_id,
        "controller_run_attempt": controller_run_attempt,
    }


def attempt_id(
    *,
    release_authority_id: str,
    controller_workflow_id: int,
    controller_run_id: int,
    controller_run_attempt: int,
) -> str:
    """Derive the publication attempt identity without legacy aliases."""

    return sha256_id(
        ATTEMPT_DOMAIN,
        attempt_payload(
            release_authority_id=release_authority_id,
            controller_workflow_id=controller_workflow_id,
            controller_run_id=controller_run_id,
            controller_run_attempt=controller_run_attempt,
        ),
    )


def _require_digest(value: str, name: str) -> None:
    _require_match(value, _DIGEST_RE, name)


def _require_match(value: str, pattern: re.Pattern[str], name: str) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ReleaseIdentityError(f"{name} is not canonical")


def _require_positive_int(value: int, name: str) -> None:
    if type(value) is not int or not 1 <= value <= MAX_SAFE_INTEGER:
        raise ReleaseIdentityError(f"{name} must be a positive JS-safe integer")
