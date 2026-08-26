"""Canonical executable inventory for the immutable controller Commit A.

GitHub resolves a JavaScript action from a Git commit, but a commit alone does
not explain which bytes constitute the reviewed executable surface.  This
contract closes that ambiguity: exactly three action metadata files and their
three bundled JavaScript entrypoints are inventoried in bytewise path order.
The document deliberately has no self-digest field; its canonical SHA-256 is
the ``controller_action_bundle_sha256`` persisted by A0/A1 and terminal proof.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from tools.evidence.release_canonical import canonical_json_bytes

SCHEMA = "dpone.release-controller-action-bundle.v1"
SCHEMA_VERSION = 1
REPOSITORY = "PaulKov/dpone-release-controller"
REPOSITORY_ID = 1_305_993_853
RUNTIME_CLOSURE_METADATA_PATH = "actions/runtime-closure/action.yml"
EXECUTABLE_PATHS = (
    "actions/broker-call/action.yml",
    "actions/broker-call/dist/index.js",
    "actions/lease-sentinel/action.yml",
    "actions/lease-sentinel/dist/index.js",
    RUNTIME_CLOSURE_METADATA_PATH,
    "actions/runtime-closure/dist/index.js",
)
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
CONTROLLER_ALLOWED_ACTION_PATTERNS = (
    "paulkov/dpone-release-controller@<A>",
    "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33",
)
TARGET_ALLOWED_ACTION_PATTERNS = (
    "anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610",
    "astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78",
    "azure/setup-helm@1a275c3b69536ee54be43f2070a358922e12c8d4",
    "docker/setup-buildx-action@b5ca514318bd6ebac0fb2aedd5d36ec1b5c232a2",
    "ossf/scorecard-action@4eaacf0543bb3f2c246792bd56e8cdeffafb205a",
    "paulkov/dpone-release-controller@<A>",
    "trufflesecurity/trufflehog@27b0417c16317ca9a472a9a8092acce143b49c55",
)


class ActionBundleError(ValueError):
    """Commit-A executable bytes are incomplete, mutable, or mismatched."""


def document(*, commit_sha: str, blobs: Mapping[str, bytes]) -> dict[str, Any]:
    """Build the sole canonical inventory from independently fetched Git blobs."""

    _git_sha(commit_sha, "controller action commit")
    _require_blob_set(blobs)
    members = [_member(path, blobs[path]) for path in EXECUTABLE_PATHS]
    result = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "commit_sha": commit_sha,
        "members": members,
    }
    verify(result, blobs=blobs)
    return result


def allowed_action_patterns(commit_sha: str, *, target: bool) -> tuple[str, ...]:
    """Resolve the sole selected-actions template to exact Commit A."""

    _git_sha(commit_sha, "controller action commit")
    template = (
        TARGET_ALLOWED_ACTION_PATTERNS if target else CONTROLLER_ALLOWED_ACTION_PATTERNS
    )
    resolved = tuple(value.replace("<A>", commit_sha) for value in template)
    if resolved != tuple(sorted(resolved, key=lambda item: item.encode("ascii"))):
        raise ActionBundleError("selected-action patterns are not bytewise sorted")
    if any(value.endswith("@*") for value in resolved):
        raise ActionBundleError("wildcard selected-action refs are forbidden")
    return resolved


def verify(value: Mapping[str, Any], *, blobs: Mapping[str, bytes]) -> None:
    """Verify closed inventory fields and recompute both Git and SHA-256 digests."""

    verify_inventory(value)
    _require_blob_set(blobs)
    members = value["members"]
    assert isinstance(members, list)
    for expected_path, observed in zip(EXECUTABLE_PATHS, members):
        expected = _member(expected_path, blobs[expected_path])
        if observed != expected:
            raise ActionBundleError(
                f"controller action member bytes mismatch: {expected_path}"
            )


def verify_inventory(value: Mapping[str, Any]) -> None:
    """Validate the closed A0 inventory when provider blob bytes are out-of-band.

    A0 creation independently recomputes every member from GitHub blob bytes.
    Consumers of the immutable A0 record can still validate its closed shape and
    canonical document digest without transporting executable bytes in a small
    activation response.
    """

    if not isinstance(value, dict):
        raise ActionBundleError("controller action bundle must be an object")
    expected_keys = {
        "schema",
        "schema_version",
        "repository",
        "repository_id",
        "commit_sha",
        "members",
    }
    if set(value) != expected_keys:
        raise ActionBundleError("controller action bundle keys are not exact")
    constants = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
    }
    if any(value[key] != expected for key, expected in constants.items()):
        raise ActionBundleError("controller action bundle constants mismatch")
    _git_sha(value["commit_sha"], "controller action commit")
    members = value["members"]
    if not isinstance(members, list) or len(members) != len(EXECUTABLE_PATHS):
        raise ActionBundleError("controller action member count mismatch")
    for expected_path, observed in zip(EXECUTABLE_PATHS, members):
        if not isinstance(observed, dict) or set(observed) != {
            "path",
            "mode",
            "size_bytes",
            "git_blob_sha",
            "sha256",
        }:
            raise ActionBundleError("controller action member keys are not exact")
        if observed["path"] != expected_path or observed["mode"] != "100644":
            raise ActionBundleError("controller action member identity mismatch")
        if (
            type(observed["size_bytes"]) is not int
            or not 1 <= observed["size_bytes"] <= MAX_MEMBER_BYTES
        ):
            raise ActionBundleError("controller action member size is invalid")
        _git_sha(observed["git_blob_sha"], "controller action member Git blob")
        _digest(observed["sha256"], "controller action member SHA-256")
    if sum(member["size_bytes"] for member in members) > MAX_TOTAL_BYTES:
        raise ActionBundleError("controller action bundle exceeds byte limit")


def inventory_sha256(value: Mapping[str, Any]) -> str:
    """Hash the canonical self-digest-free A0 inventory document."""

    verify_inventory(value)
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def inventory_runtime_metadata_blob_sha(value: Mapping[str, Any]) -> str:
    """Read the runtime action metadata blob from a validated A0 inventory."""

    verify_inventory(value)
    members = value["members"]
    assert isinstance(members, list)
    for member in members:
        if member["path"] == RUNTIME_CLOSURE_METADATA_PATH:
            return member["git_blob_sha"]
    raise ActionBundleError("runtime-closure metadata member is missing")


def encoded(value: Mapping[str, Any], *, blobs: Mapping[str, bytes]) -> bytes:
    """Return canonical manifest bytes after independent blob verification."""

    verify(value, blobs=blobs)
    return canonical_json_bytes(value)


def bundle_sha256(value: Mapping[str, Any], *, blobs: Mapping[str, bytes]) -> str:
    """Return the tagged digest stored as ``controller_action_bundle_sha256``."""

    encoded(value, blobs=blobs)
    return inventory_sha256(value)


def runtime_closure_metadata_blob_sha(
    value: Mapping[str, Any], *, blobs: Mapping[str, bytes]
) -> str:
    """Return the independently checked Git blob for the frozen runtime action."""

    verify(value, blobs=blobs)
    return inventory_runtime_metadata_blob_sha(value)


def _member(path: str, data: bytes) -> dict[str, Any]:
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_MEMBER_BYTES:
        raise ActionBundleError(f"controller action member size is invalid: {path}")
    return {
        "path": path,
        "mode": "100644",
        "size_bytes": len(data),
        "git_blob_sha": _git_blob_sha(data),
        "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
    }


def _require_blob_set(blobs: Mapping[str, bytes]) -> None:
    if not isinstance(blobs, Mapping) or set(blobs) != set(EXECUTABLE_PATHS):
        raise ActionBundleError("controller action executable path set mismatch")
    if tuple(sorted(blobs, key=lambda item: item.encode("ascii"))) != EXECUTABLE_PATHS:
        raise ActionBundleError("controller action paths are not bytewise ordered")
    if (
        sum(len(value) for value in blobs.values() if isinstance(value, bytes))
        > MAX_TOTAL_BYTES
    ):
        raise ActionBundleError("controller action bundle exceeds byte limit")


def _git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()


def _git_sha(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ActionBundleError(f"{name} must be a full lowercase Git SHA")
    return value


def _digest(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ActionBundleError(f"{name} must be a tagged lowercase SHA-256")
    return value
