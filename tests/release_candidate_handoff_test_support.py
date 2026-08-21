"""Shared filesystem builders for release-candidate handoff tests."""

from __future__ import annotations

import hashlib
import gzip
import io
import json
import tarfile
import tempfile
import zipfile
from pathlib import Path

from tools.evidence import release_candidate_codec as candidate_codec
from tools.evidence import release_candidate_contract as candidate_contract
from tools.evidence import release_distribution_contract
from tools.evidence.release_candidate_handoff import (
    ArtifactBinding,
    CANDIDATE_INVENTORY_PATH,
    CHECKSUM_PATH,
    PROJECTS,
    SUPPORT_MEMBERS,
    SUPPLEMENTAL_UNSIGNED_MEMBERS,
    manifest_canonical_sha256,
)
from tools.evidence.release_canonical import sha256_id

TAG = "v0.74.0"
VERSION = "0.74.0"
TAG_OBJECT_SHA = "1" * 40
COMMIT_SHA = "2" * 40
POLICY_SHA256 = "sha256:" + ("4" * 64)
RUN_ID = 31_900_000_001
RUN_ATTEMPT = 1
ARTIFACT_ID = 9_300_000_001
ARTIFACT_DIGEST = "sha256:" + ("5" * 64)
PRODUCER_SCHEMA = Path("docs/schemas/release/release-candidate-handoff-v2.schema.json")
PRODUCER_GOLDEN = Path("tests/fixtures/release-candidate-handoff-v2-golden.json")


def _binding() -> ArtifactBinding:
    return ArtifactBinding.from_strings(
        run_id=str(RUN_ID),
        run_attempt=str(RUN_ATTEMPT),
        artifact_id=str(ARTIFACT_ID),
        artifact_digest=ARTIFACT_DIGEST,
        expected_tag=TAG,
        expected_peeled_commit_sha=COMMIT_SHA,
    )


def _parse_candidate_inventory_with_sizes(
    sizes: list[int],
) -> tuple[candidate_contract.DistributionRecord, ...]:
    """Exercise semantic admission with declared sizes and no large allocation."""

    if len(sizes) != 8:
        raise AssertionError("test inventory must contain exactly eight sizes")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        manifest = write_candidate(root)
        candidate_inventory = json.loads((root / CANDIDATE_INVENTORY_PATH).read_text())
        records = {
            item["path"]: candidate_contract.FileRecord(
                path=item["path"],
                size_bytes=item["size_bytes"],
                sha256=item["sha256"],
            )
            for item in manifest["members"]
        }
        for artifact, size in zip(candidate_inventory["artifacts"], sizes):
            artifact["size_bytes"] = size
            path = f"dist/{artifact['filename']}"
            previous = records[path]
            records[path] = candidate_contract.FileRecord(
                path=path,
                size_bytes=size,
                sha256=previous.sha256,
            )
        return candidate_codec.parse_candidate_inventory(
            json.dumps(candidate_inventory).encode(),
            release=TAG,
            records=records,
        )


def write_candidate(
    root: Path,
    *,
    filename_overrides: dict[tuple[str, str], str] | None = None,
    metadata_name_overrides: dict[tuple[str, str], str] | None = None,
) -> dict[str, object]:
    filename_overrides = filename_overrides or {}
    metadata_name_overrides = metadata_name_overrides or {}
    artifacts: list[dict[str, object]] = []
    for package in PROJECTS:
        defaults = {
            artifact_type: release_distribution_contract.filename(
                package, VERSION, artifact_type
            )
            for artifact_type in release_distribution_contract.ARTIFACT_TYPES
        }
        for artifact_type in ("wheel", "sdist"):
            filename = filename_overrides.get(
                (package, artifact_type), defaults[artifact_type]
            )
            metadata_name = metadata_name_overrides.get(
                (package, artifact_type), package
            )
            data = (
                _wheel_bytes(package, metadata_name)
                if artifact_type == "wheel"
                else _sdist_bytes(filename, metadata_name)
            )
            _write_bytes(root / "dist" / filename, data)
            artifacts.append(
                {
                    "artifact_type": artifact_type,
                    "filename": filename,
                    "package": package,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size_bytes": len(data),
                    "version": VERSION,
                }
            )
    artifacts.sort(key=lambda item: str(item["filename"]).encode("utf-8"))
    inventory = {
        "artifacts": artifacts,
        "blockers": [],
        "decision": "GO",
        "expected_version": VERSION,
        "schema_version": 1,
        "status": "passed",
        "summary": {
            "artifact_count": 8,
            "distribution_count": 4,
            "expected_artifact_count": 8,
            "expected_distribution_count": 4,
        },
    }
    _write_json(root / CANDIDATE_INVENTORY_PATH, inventory)
    checksum_bytes = "".join(
        f"{item['sha256']}  {item['filename']}\n" for item in artifacts
    ).encode("ascii")
    for relative in SUPPORT_MEMBERS:
        if relative == CANDIDATE_INVENTORY_PATH:
            continue
        data = (
            checksum_bytes
            if relative == CHECKSUM_PATH
            else f"evidence:{relative}".encode()
        )
        _write_bytes(root / relative, data)

    member_paths = [
        *(f"dist/{item['filename']}" for item in artifacts),
        *SUPPORT_MEMBERS,
    ]
    members = [
        _file_record(root, relative)
        for relative in sorted(member_paths, key=lambda value: value.encode("utf-8"))
    ]
    inventory_sha256 = _digest((root / CANDIDATE_INVENTORY_PATH).read_bytes())
    release_identity_id = sha256_id(
        "dpone.release.identity.v2",
        {"repository_id": 1_255_975_556, "release": TAG, "projects": list(PROJECTS)},
    )
    release_authority_id = sha256_id(
        "dpone.release.authority.v2",
        {
            "release_identity_id": release_identity_id,
            "tag_object_sha": TAG_OBJECT_SHA,
            "peeled_commit_sha": COMMIT_SHA,
            "policy_sha256": POLICY_SHA256,
            "protected_base_ref": "refs/heads/master",
        },
    )
    candidate_id = sha256_id(
        "dpone.release.candidate.v2",
        {
            "release_authority_id": release_authority_id,
            "candidate_inventory_sha256": inventory_sha256,
        },
    )
    manifest: dict[str, object] = {
        "schema": "dpone.release-candidate-handoff.v2",
        "schema_version": 2,
        "repository": {
            "name_with_owner": "PaulKov/dpone",
            "repository_id": 1_255_975_556,
        },
        "release": TAG,
        "tag_object_sha": TAG_OBJECT_SHA,
        "peeled_commit_sha": COMMIT_SHA,
        "policy": {
            "path": ".agents/policy/github-branch-protection.yml",
            "sha256": POLICY_SHA256,
        },
        "workflow": {
            "path": ".github/workflows/release.yml",
            "run_id": RUN_ID,
            "run_attempt": RUN_ATTEMPT,
        },
        "release_identity_id": release_identity_id,
        "release_authority_id": release_authority_id,
        "candidate_inventory_sha256": inventory_sha256,
        "candidate_id": candidate_id,
        "supplemental_unsigned_members": list(SUPPLEMENTAL_UNSIGNED_MEMBERS),
        "members": members,
    }
    _seal_manifest(root, manifest)
    return manifest


def _wheel_bytes(package: str, metadata_name: str) -> bytes:
    data = io.BytesIO()
    metadata_path = f"{package.replace('-', '_')}-{VERSION}.dist-info/METADATA"
    with zipfile.ZipFile(data, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo(metadata_path)
        info.create_system = 3
        info.external_attr = 0o100644 << 16
        archive.writestr(
            info,
            f"Metadata-Version: 2.3\nName: {metadata_name}\nVersion: {VERSION}\n\n",
            compress_type=zipfile.ZIP_DEFLATED,
        )
    return data.getvalue()


def _sdist_bytes(filename: str, metadata_name: str) -> bytes:
    data = io.BytesIO()
    root_name = filename[: -len(".tar.gz")]
    metadata = (
        f"Metadata-Version: 2.3\nName: {metadata_name}\nVersion: {VERSION}\n\n".encode()
    )
    with gzip.GzipFile(filename="", mode="wb", fileobj=data, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            directory = tarfile.TarInfo(root_name)
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            directory.mtime = 0
            archive.addfile(directory)
            info = tarfile.TarInfo(f"{root_name}/PKG-INFO")
            info.size = len(metadata)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(metadata))
    return data.getvalue()


def _file_record(root: Path, relative: str) -> dict[str, object]:
    data = (root / relative).read_bytes()
    return {"path": relative, "size_bytes": len(data), "sha256": _digest(data)}


def _rebind_candidate_inventory(root: Path, manifest: dict[str, object]) -> None:
    replacement = _file_record(root, CANDIDATE_INVENTORY_PATH)
    manifest["members"] = [
        replacement if item["path"] == CANDIDATE_INVENTORY_PATH else item
        for item in manifest["members"]
    ]
    inventory_sha256 = replacement["sha256"]
    manifest["candidate_inventory_sha256"] = inventory_sha256
    manifest["candidate_id"] = sha256_id(
        "dpone.release.candidate.v2",
        {
            "release_authority_id": manifest["release_authority_id"],
            "candidate_inventory_sha256": inventory_sha256,
        },
    )
    _seal_manifest(root, manifest)


def _rebind_member(root: Path, manifest: dict[str, object], path: str) -> None:
    replacement = _file_record(root, path)
    manifest["members"] = [
        replacement if item["path"] == path else item for item in manifest["members"]
    ]
    _seal_manifest(root, manifest)


def _seal_manifest(root: Path, manifest: dict[str, object]) -> None:
    manifest.pop("manifest_sha256", None)
    manifest["manifest_sha256"] = manifest_canonical_sha256(manifest)
    _write_json(root / "candidate-handoff-v2.json", manifest)


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()
