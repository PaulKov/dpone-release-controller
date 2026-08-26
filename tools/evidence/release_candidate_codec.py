"""Strict JSON and identity codec for release candidate handoff v2."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any, Mapping

from tools.evidence import release_candidate_contract as contract
from tools.evidence import release_candidate_json as candidate_json
from tools.evidence import release_candidate_outer_binding as outer_binding
from tools.evidence import release_distribution_contract
from tools.evidence import release_identity

_HEX_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def load_unique_json(data: bytes, name: str) -> Mapping[str, Any]:
    """Decode UTF-8 JSON while rejecting duplicate keys and non-object roots."""

    return candidate_json.load_unique_json(data, name)


def manifest_canonical_sha256(raw_without_digest: Mapping[str, Any]) -> str:
    """Return plain SHA-256 of the canonical manifest body without recursion."""

    return candidate_json.manifest_canonical_sha256(raw_without_digest)


def parse_manifest(raw: Mapping[str, Any]) -> contract.CandidateManifest:
    """Parse and rederive every identity in the closed producer manifest."""

    expected_keys = {
        "schema",
        "schema_version",
        "repository",
        "release",
        "tag_object_sha",
        "peeled_commit_sha",
        "policy",
        "workflow",
        "release_identity_id",
        "release_authority_id",
        "candidate_inventory_sha256",
        "candidate_id",
        "members",
        "supplemental_unsigned_members",
        "manifest_sha256",
    }
    contract.require_exact_keys(raw, expected_keys, "manifest")
    if (
        raw["schema"] != contract.SCHEMA
        or raw["schema_version"] != contract.SCHEMA_VERSION
    ):
        raise contract.CandidateHandoffError(
            "candidate manifest schema/version mismatch"
        )

    manifest_digest = contract.require_digest_value(
        raw["manifest_sha256"], "manifest_sha256"
    )
    body = dict(raw)
    del body["manifest_sha256"]
    if manifest_digest != manifest_canonical_sha256(body):
        raise contract.CandidateHandoffError(
            "manifest_sha256 does not match canonical body"
        )

    repository = contract.require_mapping(raw["repository"], "repository")
    contract.require_exact_keys(
        repository, {"name_with_owner", "repository_id"}, "repository"
    )
    if repository != {
        "name_with_owner": contract.TARGET_REPOSITORY,
        "repository_id": contract.TARGET_REPOSITORY_ID,
    }:
        raise contract.CandidateHandoffError("target repository identity mismatch")

    release = contract.require_string(raw["release"], "release")
    contract.require_release(release)
    tag_object_sha = contract.require_string(raw["tag_object_sha"], "tag_object_sha")
    peeled_commit_sha = contract.require_string(
        raw["peeled_commit_sha"], "peeled_commit_sha"
    )
    contract.require_commit(tag_object_sha, "tag_object_sha")
    contract.require_commit(peeled_commit_sha, "peeled_commit_sha")
    if tag_object_sha == peeled_commit_sha:
        raise contract.CandidateHandoffError(
            "annotated tag object must differ from peeled commit"
        )

    policy = contract.require_mapping(raw["policy"], "policy")
    contract.require_exact_keys(policy, {"path", "sha256"}, "policy")
    if policy["path"] != contract.POLICY_PATH:
        raise contract.CandidateHandoffError(
            f"policy.path must be {contract.POLICY_PATH!r}"
        )
    policy_sha256 = contract.require_digest_value(policy["sha256"], "policy.sha256")

    workflow = contract.require_mapping(raw["workflow"], "workflow")
    contract.require_exact_keys(workflow, {"path", "run_id", "run_attempt"}, "workflow")
    if workflow["path"] != contract.CANDIDATE_WORKFLOW_PATH:
        raise contract.CandidateHandoffError("candidate workflow path mismatch")
    run_id = contract.require_positive_int(workflow["run_id"], "workflow.run_id")
    run_attempt = contract.require_positive_int(
        workflow["run_attempt"], "workflow.run_attempt"
    )
    members = tuple(
        _parse_member(item) for item in contract.require_list(raw["members"], "members")
    )
    _validate_members(members)
    supplemental = tuple(
        contract.require_string(item, "supplemental_unsigned_members item")
        for item in contract.require_list(
            raw["supplemental_unsigned_members"],
            "supplemental_unsigned_members",
        )
    )
    if supplemental != contract.SUPPLEMENTAL_UNSIGNED_MEMBERS:
        raise contract.CandidateHandoffError(
            "supplemental unsigned member classification mismatch"
        )

    release_identity_id = contract.require_digest_value(
        raw["release_identity_id"], "release_identity_id"
    )
    expected_release_id = release_identity.release_identity_id(release)
    if release_identity_id != expected_release_id:
        raise contract.CandidateHandoffError(
            "release_identity_id does not match manifest identity"
        )

    release_authority_id = contract.require_digest_value(
        raw["release_authority_id"], "release_authority_id"
    )
    expected_authority_id = release_identity.release_authority_id(
        release_identity_id=release_identity_id,
        tag_object_sha=tag_object_sha,
        peeled_commit_sha=peeled_commit_sha,
        policy_sha256=policy_sha256,
    )
    if release_authority_id != expected_authority_id:
        raise contract.CandidateHandoffError(
            "release_authority_id does not match frozen authority"
        )

    inventory_digest = contract.require_digest_value(
        raw["candidate_inventory_sha256"], "candidate_inventory_sha256"
    )
    candidate_id = contract.require_digest_value(raw["candidate_id"], "candidate_id")
    expected_candidate_id = release_identity.candidate_id(
        release_authority_id=release_authority_id,
        candidate_inventory_sha256=inventory_digest,
    )
    if candidate_id != expected_candidate_id:
        raise contract.CandidateHandoffError(
            "candidate_id does not match frozen inventory"
        )
    return contract.CandidateManifest(
        release=release,
        tag_object_sha=tag_object_sha,
        peeled_commit_sha=peeled_commit_sha,
        policy_sha256=policy_sha256,
        run_id=run_id,
        run_attempt=run_attempt,
        release_identity_id=release_identity_id,
        release_authority_id=release_authority_id,
        candidate_inventory_sha256=inventory_digest,
        candidate_id=candidate_id,
        manifest_sha256=manifest_digest,
        members=members,
        supplemental_unsigned_members=supplemental,
    )


def parse_candidate_inventory(
    data: bytes,
    *,
    release: str,
    records: Mapping[str, contract.FileRecord],
) -> tuple[contract.DistributionRecord, ...]:
    """Bind the producer's exact eight-file inventory to manifest records."""

    raw = load_unique_json(data, "candidate inventory")
    contract.require_exact_keys(
        raw,
        {
            "artifacts",
            "blockers",
            "decision",
            "expected_version",
            "schema_version",
            "status",
            "summary",
        },
        "candidate inventory",
    )
    version = release.removeprefix("v")
    summary = contract.require_mapping(raw["summary"], "candidate inventory summary")
    expected_summary = {
        "artifact_count": 8,
        "distribution_count": 4,
        "expected_artifact_count": 8,
        "expected_distribution_count": 4,
    }
    contract.require_exact_keys(
        summary, set(expected_summary), "candidate inventory summary"
    )
    if (
        type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
        or raw["status"] != "passed"
        or raw["decision"] != "GO"
        or raw["blockers"] != []
        or raw["expected_version"] != version
        or summary != expected_summary
        or any(type(value) is not int for value in summary.values())
    ):
        raise contract.CandidateHandoffError(
            "candidate inventory is not an exact GO inventory"
        )
    artifacts = contract.require_list(raw["artifacts"], "candidate inventory artifacts")
    if len(artifacts) != 8:
        raise contract.CandidateHandoffError(
            "candidate inventory must contain eight artifacts"
        )
    parsed = tuple(
        _parse_inventory_artifact(item, version=version, records=records)
        for item in artifacts
    )
    filenames = tuple(item.filename for item in parsed)
    if filenames != tuple(sorted(filenames, key=lambda value: value.encode("utf-8"))):
        raise contract.CandidateHandoffError(
            "candidate inventory filenames are not bytewise sorted"
        )
    if len(set(filenames)) != 8 or len({item.path for item in parsed}) != 8:
        raise contract.CandidateHandoffError(
            "candidate inventory contains duplicate archives"
        )
    expected_pairs = {
        (project, artifact_type)
        for project in contract.PROJECTS
        for artifact_type in ("sdist", "wheel")
    }
    if {(item.package, item.artifact_type) for item in parsed} != expected_pairs:
        raise contract.CandidateHandoffError(
            "candidate inventory must contain one wheel and sdist per project"
        )
    contract.require_distribution_inventory_sizes(parsed)
    return parsed


def distribution_checksum_bytes(
    records: tuple[contract.DistributionRecord, ...],
) -> bytes:
    """Return exact checksum bytes through the stable codec facade."""

    return outer_binding.distribution_checksum_bytes(records)


def require_outer_binding(
    manifest: contract.CandidateManifest,
    binding: contract.ArtifactBinding,
) -> None:
    """Require immutable selectors through the stable codec facade."""

    outer_binding.require_outer_binding(manifest, binding)


def _parse_member(value: Any) -> contract.FileRecord:
    raw = contract.require_mapping(value, "member")
    contract.require_exact_keys(raw, {"path", "size_bytes", "sha256"}, "member")
    path = contract.require_safe_path(raw["path"], "member.path")
    return contract.FileRecord(
        path=path,
        size_bytes=contract.require_file_size(raw["size_bytes"], path),
        sha256=contract.require_digest_value(raw["sha256"], f"member {path}"),
    )


def _validate_members(members: tuple[contract.FileRecord, ...]) -> None:
    if (
        len(members) != contract.EXPECTED_DECLARED_MEMBER_COUNT
        or len(members) + 1 != contract.EXPECTED_PROVIDER_FILE_COUNT
    ):
        raise contract.CandidateHandoffError(
            "candidate must declare exactly 24 members"
        )
    paths = tuple(item.path for item in members)
    if paths != tuple(sorted(paths, key=lambda value: value.encode("utf-8"))):
        raise contract.CandidateHandoffError(
            "candidate members must be in bytewise path order"
        )
    if len(set(paths)) != len(paths):
        raise contract.CandidateHandoffError(
            "candidate members contain duplicate paths"
        )
    support = {path for path in paths if not path.startswith("dist/")}
    distributions = {path for path in paths if path.startswith("dist/")}
    if support != set(contract.SUPPORT_MEMBERS) or len(distributions) != 8:
        raise contract.CandidateHandoffError(
            "candidate member set must contain eight dist files and exact support files"
        )


def _parse_inventory_artifact(
    value: Any,
    *,
    version: str,
    records: Mapping[str, contract.FileRecord],
) -> contract.DistributionRecord:
    raw = contract.require_mapping(value, "candidate inventory artifact")
    contract.require_exact_keys(
        raw,
        {"artifact_type", "filename", "package", "sha256", "size_bytes", "version"},
        "candidate inventory artifact",
    )
    package = contract.require_string(raw["package"], "artifact.package")
    if package not in contract.PROJECTS:
        raise contract.CandidateHandoffError(
            f"unexpected candidate package: {package!r}"
        )
    artifact_type = contract.require_string(
        raw["artifact_type"], "artifact.artifact_type"
    )
    if artifact_type not in {"sdist", "wheel"}:
        raise contract.CandidateHandoffError("artifact_type must be sdist or wheel")
    if raw["version"] != version:
        raise contract.CandidateHandoffError(
            "candidate artifact version does not match release"
        )
    filename = contract.require_string(raw["filename"], "artifact.filename")
    if PurePosixPath(filename).name != filename:
        raise contract.CandidateHandoffError("candidate filename must be a basename")
    _validate_archive_filename(
        filename, package=package, version=version, artifact_type=artifact_type
    )
    path = f"dist/{filename}"
    record = records.get(path)
    if record is None:
        raise contract.CandidateHandoffError(
            f"inventory archive is absent from manifest: {path}"
        )
    size = contract.require_distribution_size(raw["size_bytes"], path)
    bare_digest = contract.require_string(raw["sha256"], "artifact.sha256")
    if _HEX_SHA256_RE.fullmatch(bare_digest) is None:
        raise contract.CandidateHandoffError("artifact.sha256 must be 64 lowercase hex")
    if record.size_bytes != size or record.sha256 != f"sha256:{bare_digest}":
        raise contract.CandidateHandoffError(
            "candidate inventory and manifest archive differ"
        )
    return contract.DistributionRecord(
        path=path,
        size_bytes=size,
        sha256=record.sha256,
        package=package,
        filename=filename,
        artifact_type=artifact_type,
        version=version,
    )


def _validate_archive_filename(
    filename: str,
    *,
    package: str,
    version: str,
    artifact_type: str,
) -> None:
    try:
        expected = release_distribution_contract.filename(
            package, version, artifact_type
        )
    except release_distribution_contract.DistributionContractError as exc:
        raise contract.CandidateHandoffError(str(exc)) from exc
    if filename != expected:
        raise contract.CandidateHandoffError(
            f"{artifact_type} filename is not the frozen release filename"
        )
