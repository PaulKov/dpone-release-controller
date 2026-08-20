"""Strict fresh broker activation proof contract for controller admission."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from tools.evidence.release_canonical import MAX_SAFE_INTEGER, canonical_json_bytes
from tools.evidence import release_controller_activation_proof_types as proof_types

REQUEST_SCHEMA = "dpone.release-broker-activation-proof-request.v1"
RESPONSE_SCHEMA = "dpone.release-broker-activation-proof.v1"
AUDIENCE = "dpone-release-controller-ledger-write"
ENVIRONMENT = "release-attest"
PROOF_TTL = timedelta(seconds=60)
MAX_CLOCK_SKEW = timedelta(seconds=30)

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GIT_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
_TAG_REF_RE = re.compile(
    r"refs/tags/v(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\Z"
)
_OPAQUE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


ActivationProofError = proof_types.ActivationProofError
Clock = proof_types.Clock
SystemUtcClock = proof_types.SystemUtcClock
SYSTEM_UTC_CLOCK = proof_types.SYSTEM_UTC_CLOCK
BrokerActivationExchange = proof_types.BrokerActivationExchange
BrokerActivationClient = proof_types.BrokerActivationClient
ExpectedControllerRun = proof_types.ExpectedControllerRun
ActivationProof = proof_types.ActivationProof


def request_bytes() -> bytes:
    """Return the only accepted canonical activation proof request."""

    return canonical_json_bytes({"schema": REQUEST_SCHEMA, "schema_version": 1})


def parse_request(data: bytes) -> Mapping[str, Any]:
    """Parse the exact empty-selector activation request bytes."""

    raw = _load_canonical_object(data)
    _keys(raw, {"schema", "schema_version"}, "activation proof request")
    if raw != {"schema": REQUEST_SCHEMA, "schema_version": 1}:
        raise ActivationProofError("activation request schema/version mismatch")
    return raw


def reference_response_bytes(document: Mapping[str, Any]) -> bytes:
    """Encode broker fixture bytes; consumers must still call ``verify_exchange``."""

    encoded = canonical_json_bytes(document)
    raw = _load_canonical_object(encoded)
    if raw.get("schema") != RESPONSE_SCHEMA or raw.get("schema_version") != 1:
        raise ActivationProofError("activation response schema/version mismatch")
    return encoded


def verify_exchange(
    exchange: BrokerActivationExchange,
    *,
    expected: ExpectedControllerRun,
    clock: Clock = SYSTEM_UTC_CLOCK,
) -> ActivationProof:
    """Verify canonical response bytes, freshness, registry chain and run binding."""

    _opaque(exchange.request_id, "request_id")
    raw = _load_canonical_object(exchange.response_bytes)
    _keys(
        raw,
        {
            "schema",
            "schema_version",
            "request_id",
            "controller",
            "provisioned",
            "activated",
            "admitted_at",
            "expires_at",
            "proof_sha256",
        },
        "activation proof",
    )
    if raw["schema"] != RESPONSE_SCHEMA or raw["schema_version"] != 1:
        raise ActivationProofError("activation proof schema/version mismatch")
    if raw["request_id"] != exchange.request_id:
        raise ActivationProofError("activation proof request ID mismatch")

    controller = _mapping(raw["controller"], "controller")
    _keys(
        controller,
        {
            "repository_id",
            "workflow_id",
            "workflow_sha",
            "workflow_ref",
            "ref",
            "ref_type",
            "tag_object_sha",
            "run_id",
            "run_attempt",
            "default_branch_ref",
            "default_branch_workflow_blob_sha",
            "default_branch_workflow_observation_sha256",
        },
        "controller",
    )
    expected_controller = {
        "repository_id": expected.repository_id,
        "ref": expected.ref,
        "workflow_ref": expected.workflow_ref,
        "workflow_sha": expected.workflow_sha,
        "run_id": expected.run_id,
        "run_attempt": expected.run_attempt,
    }
    if any(
        controller[key] != value for key, value in expected_controller.items()
    ) or any(
        type(controller[key]) is not int or not 1 <= controller[key] <= MAX_SAFE_INTEGER
        for key in ("repository_id", "workflow_id", "run_id", "run_attempt")
    ):
        raise ActivationProofError("activation proof controller run mismatch")
    _git_sha(controller["workflow_sha"], "controller.workflow_sha")
    _git_sha(controller["tag_object_sha"], "controller.tag_object_sha")
    _git_sha(
        controller["default_branch_workflow_blob_sha"],
        "controller.default_branch_workflow_blob_sha",
    )
    _digest(
        controller["default_branch_workflow_observation_sha256"],
        "controller.default_branch_workflow_observation_sha256",
    )
    if (
        controller["ref_type"] != "tag"
        or controller["default_branch_ref"] != "refs/heads/master"
        or _TAG_REF_RE.fullmatch(controller["ref"]) is None
        or controller["tag_object_sha"] == controller["workflow_sha"]
    ):
        raise ActivationProofError("controller execution tag is not annotated")

    provisioned = _mapping(raw["provisioned"], "provisioned")
    _keys(
        provisioned,
        {
            "record_id",
            "digest",
            "worker_version_id",
            "worm_version_id",
            "controller_workflow_commit_sha",
            "controller_workflow_blob_sha",
            "controller_action_commit_sha",
            "controller_action_metadata_blob_sha",
            "controller_action_bundle_sha256",
            "controller_workflow_id",
            "controller_ref",
            "controller_ref_type",
            "controller_tag_object_sha",
            "controller_peeled_commit_sha",
        },
        "provisioned",
    )
    activated = _mapping(raw["activated"], "activated")
    _keys(
        activated,
        {
            "record_id",
            "digest",
            "previous",
            "target_policy_commit_sha",
            "target_policy_sha256",
            "target_policy_blob_sha",
            "controller_action_commit_sha",
            "controller_action_metadata_blob_sha",
            "controller_action_bundle_sha256",
            "worm_version_id",
        },
        "activated",
    )
    for owner, key in (
        (provisioned, "record_id"),
        (provisioned, "digest"),
        (activated, "record_id"),
        (activated, "digest"),
        (activated, "previous"),
        (activated, "target_policy_sha256"),
    ):
        _digest(owner[key], key)
    _git_sha(
        provisioned["controller_workflow_commit_sha"],
        "controller_workflow_commit_sha",
    )
    _git_sha(
        provisioned["controller_workflow_blob_sha"],
        "controller_workflow_blob_sha",
    )
    _git_sha(
        provisioned["controller_action_commit_sha"],
        "controller_action_commit_sha",
    )
    _git_sha(
        provisioned["controller_action_metadata_blob_sha"],
        "controller_action_metadata_blob_sha",
    )
    _digest(
        provisioned["controller_action_bundle_sha256"],
        "controller_action_bundle_sha256",
    )
    if (
        type(provisioned["controller_workflow_id"]) is not int
        or not 1 <= provisioned["controller_workflow_id"] <= MAX_SAFE_INTEGER
    ):
        raise ActivationProofError("provisioned controller workflow ID is invalid")
    _git_sha(provisioned["controller_tag_object_sha"], "controller_tag_object_sha")
    _git_sha(
        provisioned["controller_peeled_commit_sha"],
        "controller_peeled_commit_sha",
    )
    _git_sha(activated["target_policy_commit_sha"], "target_policy_commit_sha")
    _git_sha(activated["target_policy_blob_sha"], "target_policy_blob_sha")
    _git_sha(activated["controller_action_commit_sha"], "controller_action_commit_sha")
    _git_sha(
        activated["controller_action_metadata_blob_sha"],
        "controller_action_metadata_blob_sha",
    )
    _digest(
        activated["controller_action_bundle_sha256"],
        "controller_action_bundle_sha256",
    )
    for owner, key in (
        (provisioned, "worker_version_id"),
        (provisioned, "worm_version_id"),
        (activated, "worm_version_id"),
    ):
        _opaque(owner[key], key)
    if (
        controller["workflow_id"] != provisioned["controller_workflow_id"]
        or controller["workflow_sha"] != provisioned["controller_workflow_commit_sha"]
        or controller["workflow_sha"] != provisioned["controller_peeled_commit_sha"]
        or controller["ref"] != provisioned["controller_ref"]
        or controller["ref_type"] != provisioned["controller_ref_type"]
        or controller["tag_object_sha"] != provisioned["controller_tag_object_sha"]
        or controller["default_branch_workflow_blob_sha"]
        != provisioned["controller_workflow_blob_sha"]
        or provisioned["controller_action_commit_sha"]
        == provisioned["controller_workflow_commit_sha"]
        or activated["controller_action_commit_sha"]
        != provisioned["controller_action_commit_sha"]
        or activated["controller_action_metadata_blob_sha"]
        != provisioned["controller_action_metadata_blob_sha"]
        or activated["controller_action_bundle_sha256"]
        != provisioned["controller_action_bundle_sha256"]
        or activated["previous"] != provisioned["record_id"]
        or activated["record_id"] == provisioned["record_id"]
    ):
        raise ActivationProofError("activation registry A0/A1 chain mismatch")

    admitted = _timestamp(raw["admitted_at"], "admitted_at")
    expires = _timestamp(raw["expires_at"], "expires_at")
    now = _utc_now(clock.now())
    if (
        expires - admitted != PROOF_TTL
        or admitted > now + MAX_CLOCK_SKEW
        or expires <= now
    ):
        raise ActivationProofError("activation proof is stale or has invalid TTL")

    proof_digest = raw["proof_sha256"]
    _digest(proof_digest, "proof_sha256")
    body = dict(raw)
    del body["proof_sha256"]
    actual = "sha256:" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    if proof_digest != actual:
        raise ActivationProofError("activation proof digest mismatch")
    return ActivationProof(
        request_id=exchange.request_id,
        controller_workflow_id=controller["workflow_id"],
        controller_ref=controller["ref"],
        controller_tag_object_sha=controller["tag_object_sha"],
        provisioned_record_id=provisioned["record_id"],
        provisioned_digest=provisioned["digest"],
        worker_version_id=provisioned["worker_version_id"],
        provisioned_worm_version_id=provisioned["worm_version_id"],
        controller_workflow_commit_sha=provisioned["controller_workflow_commit_sha"],
        controller_workflow_blob_sha=provisioned["controller_workflow_blob_sha"],
        controller_action_commit_sha=provisioned["controller_action_commit_sha"],
        controller_action_metadata_blob_sha=provisioned[
            "controller_action_metadata_blob_sha"
        ],
        controller_action_bundle_sha256=provisioned["controller_action_bundle_sha256"],
        activated_record_id=activated["record_id"],
        activated_digest=activated["digest"],
        activated_worm_version_id=activated["worm_version_id"],
        target_policy_commit_sha=activated["target_policy_commit_sha"],
        target_policy_sha256=activated["target_policy_sha256"],
        target_policy_blob_sha=activated["target_policy_blob_sha"],
        proof_sha256=proof_digest,
        admitted_at=raw["admitted_at"],
        expires_at=raw["expires_at"],
    )


def _load_canonical_object(data: bytes) -> Mapping[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ActivationProofError(f"duplicate activation proof key: {key!r}")
            result[key] = value
        return result

    try:
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ActivationProofError(f"invalid activation proof JSON: {exc}") from exc
    raw = _mapping(raw, "activation proof")
    if data != canonical_json_bytes(raw):
        raise ActivationProofError("activation proof response is not canonical JSON")
    return raw


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ActivationProofError(f"{name} must be an object")
    return value


def _keys(raw: Mapping[str, Any], expected: set[str], name: str) -> None:
    if set(raw) != expected:
        raise ActivationProofError(f"{name} keys are not exact")


def _digest(value: Any, name: str) -> None:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ActivationProofError(f"{name} must be a tagged SHA-256 digest")


def _git_sha(value: Any, name: str) -> None:
    if not isinstance(value, str) or _GIT_SHA_RE.fullmatch(value) is None:
        raise ActivationProofError(f"{name} must be a full lowercase Git SHA")


def _opaque(value: Any, name: str) -> None:
    if not isinstance(value, str) or _OPAQUE_ID_RE.fullmatch(value) is None:
        raise ActivationProofError(f"{name} is not a safe opaque identifier")


def _timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        raise ActivationProofError(f"{name} must be canonical UTC seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ActivationProofError(f"{name} is not a real timestamp") from exc


def _utc_now(value: datetime) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ActivationProofError("activation proof clock must return UTC")
    return value.astimezone(timezone.utc)
