"""Provider ZIP boundary tests for release candidate import."""

from __future__ import annotations

import hashlib
import io
import stat
import tempfile
import unittest
import zipfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from tests.release_candidate_handoff_test_support import (
    ARTIFACT_ID,
    COMMIT_SHA,
    POLICY_SHA256,
    RUN_ATTEMPT,
    RUN_ID,
    TAG,
    TAG_OBJECT_SHA,
    write_candidate,
)
from tools.evidence.release_candidate_handoff import (
    ArtifactBinding,
    CandidateHandoffError,
    ProviderArtifactObservation,
    import_provider_candidate,
)
from tools.evidence.release_canonical import MAX_SAFE_INTEGER

PROVIDER_RESPONSE_DIGEST = "sha256:" + ("8" * 64)
FROZEN_NOW = datetime(2026, 8, 15, 0, 0, 30, tzinfo=timezone.utc)


class FrozenClock:
    """Deterministic UTC provider-boundary clock."""

    def now(self) -> datetime:
        return FROZEN_NOW


FROZEN_CLOCK = FrozenClock()


class MemorySource:
    """One-shot DI source used instead of a live broker URL."""

    def __init__(self, data: bytes, *, empty_chunk: bool = False) -> None:
        self._data = data
        self._empty_chunk = empty_chunk

    def chunks(self, *, maximum_bytes: int):
        if self._empty_chunk:
            yield b""
        for offset in range(0, len(self._data), 97):
            yield self._data[offset : offset + 97]


class CandidateProviderTests(unittest.TestCase):
    def test_raw_provider_zip_and_observation_bind_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            producer = workspace / "producer"
            producer.mkdir()
            write_candidate(producer)
            raw_zip = _zip_tree(producer)
            binding = _binding(raw_zip)
            observation = _observation(raw_zip)

            imported = _import_provider_candidate(
                MemorySource(raw_zip), observation, binding, workspace / "candidate"
            )

        receipt = imported.receipt_payload()
        self.assertEqual(receipt["candidate_artifact_digest"], _digest(raw_zip))
        self.assertEqual(receipt["candidate_artifact_raw_zip_sha256"], _digest(raw_zip))
        self.assertEqual(
            receipt["candidate_artifact_provider_response_sha256"],
            PROVIDER_RESPONSE_DIGEST,
        )
        self.assertEqual(receipt["candidate_artifact_file_count"], 25)

    def test_each_provider_selector_mismatch_fails_before_download(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "producer"
            root.mkdir()
            write_candidate(root)
            raw_zip = _zip_tree(root)
            binding = _binding(raw_zip)
            base = _observation(raw_zip)
            mutations = {
                "provider_api_version": "2022-11-28",
                "workflow_path": ".github/workflows/other.yml",
                "event": "workflow_dispatch",
                "head_sha": "9" * 40,
                "run_attempt": 2,
                "artifact_id": ARTIFACT_ID + 1,
                "artifact_name": "latest",
                "artifact_expired": True,
                "conclusion": "failure",
            }
            for field, value in mutations.items():
                with self.subTest(field=field):
                    source = MemorySource(raw_zip, empty_chunk=True)
                    with self.assertRaisesRegex(
                        CandidateHandoffError, "provider candidate"
                    ):
                        _import_provider_candidate(
                            source,
                            replace(base, **{field: value}),
                            binding,
                            Path(directory) / f"out-{field}",
                        )

    def test_raw_zip_digest_mismatch_is_not_replaced_by_extracted_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "producer"
            root.mkdir()
            write_candidate(root)
            raw_zip = _zip_tree(root)
            tampered = raw_zip[:-1] + bytes([raw_zip[-1] ^ 1])

            with self.assertRaisesRegex(
                CandidateHandoffError, "raw provider ZIP digest"
            ):
                _import_provider_candidate(
                    MemorySource(tampered),
                    replace(_observation(raw_zip), artifact_size_bytes=len(tampered)),
                    _binding(raw_zip),
                    Path(directory) / "out",
                )

    def test_bool_numeric_request_id_and_expiry_confusion_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "producer"
            root.mkdir()
            write_candidate(root)
            raw_zip = _zip_tree(root)
            cases = (
                {"schema_version": True},
                {"repository_id": True},
                {"run_id": MAX_SAFE_INTEGER + 1},
                {"artifact_size_bytes": MAX_SAFE_INTEGER + 1},
                {"artifact_expired": 0},
                {"broker_request_id": "request/unsafe"},
                {"source_url_expires_at": "2020-01-01T00:00:00Z"},
                {"source_url_expires_at": "2026-08-15T00:01:31Z"},
                {"artifact_created_at": "2026-08-15T00:01:01Z"},
            )
            for index, replacement in enumerate(cases):
                with self.subTest(replacement=replacement):
                    with self.assertRaises(CandidateHandoffError):
                        _import_provider_candidate(
                            MemorySource(raw_zip),
                            replace(_observation(raw_zip), **replacement),
                            _binding(raw_zip),
                            Path(directory) / f"invalid-{index}",
                        )

    def test_provider_clock_must_be_timezone_aware_utc(self) -> None:
        class NaiveClock:
            def now(self) -> datetime:
                return datetime(2026, 8, 15, 0, 0, 30)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "producer"
            root.mkdir()
            write_candidate(root)
            raw_zip = _zip_tree(root)
            with self.assertRaisesRegex(CandidateHandoffError, "timezone-aware UTC"):
                import_provider_candidate(
                    MemorySource(raw_zip),
                    _observation(raw_zip),
                    _binding(raw_zip),
                    Path(directory) / "out",
                    clock=NaiveClock(),
                )

    def test_fresh_provider_tag_and_policy_must_match_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "producer"
            root.mkdir()
            write_candidate(root)
            raw_zip = _zip_tree(root)
            with self.assertRaisesRegex(CandidateHandoffError, "tag/policy authority"):
                _import_provider_candidate(
                    MemorySource(raw_zip),
                    replace(
                        _observation(raw_zip), policy_sha256="sha256:" + ("f" * 64)
                    ),
                    _binding(raw_zip),
                    Path(directory) / "out",
                )

    def test_duplicate_and_unsafe_provider_zip_members_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "producer"
            root.mkdir()
            write_candidate(root)
            with self.assertWarnsRegex(UserWarning, "Duplicate name"):
                duplicate = _zip_tree(root, duplicate=True)
            cases = {
                "duplicate": duplicate,
                "symlink": _zip_tree(root, symlink=True),
                "traversal": _zip_tree(root, unsafe_name="../escape.txt"),
                "drive": _zip_tree(root, unsafe_name="C:escape.txt"),
            }
            for name, raw_zip in cases.items():
                with self.subTest(name=name):
                    with self.assertRaises(CandidateHandoffError):
                        _import_provider_candidate(
                            MemorySource(raw_zip),
                            _observation(raw_zip),
                            _binding(raw_zip),
                            Path(directory) / f"out-{name}",
                        )

    def test_empty_source_chunk_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "producer"
            root.mkdir()
            write_candidate(root)
            raw_zip = _zip_tree(root)
            with self.assertRaisesRegex(CandidateHandoffError, "invalid chunk"):
                _import_provider_candidate(
                    MemorySource(raw_zip, empty_chunk=True),
                    _observation(raw_zip),
                    _binding(raw_zip),
                    Path(directory) / "out",
                )

    def test_symlink_destination_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            producer = workspace / "producer"
            producer.mkdir()
            write_candidate(producer)
            raw_zip = _zip_tree(producer)
            real_parent = workspace / "real-parent"
            real_parent.mkdir()
            linked_parent = workspace / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)

            with self.assertRaisesRegex(
                CandidateHandoffError, "non-symlink|following a link"
            ):
                _import_provider_candidate(
                    MemorySource(raw_zip),
                    _observation(raw_zip),
                    _binding(raw_zip),
                    linked_parent / "out",
                )


def _binding(raw_zip: bytes) -> ArtifactBinding:
    return ArtifactBinding.from_strings(
        run_id=str(RUN_ID),
        run_attempt=str(RUN_ATTEMPT),
        artifact_id=str(ARTIFACT_ID),
        artifact_digest=_digest(raw_zip),
        expected_tag=TAG,
        expected_peeled_commit_sha=COMMIT_SHA,
    )


def _observation(raw_zip: bytes) -> ProviderArtifactObservation:
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
        head_branch=TAG,
        head_sha=COMMIT_SHA,
        run_id=RUN_ID,
        run_attempt=RUN_ATTEMPT,
        conclusion="success",
        artifact_id=ARTIFACT_ID,
        artifact_name="release-candidates",
        artifact_digest=_digest(raw_zip),
        artifact_size_bytes=len(raw_zip),
        artifact_expired=False,
        artifact_created_at="2026-08-15T00:00:00Z",
        artifact_expires_at="2026-08-16T00:00:00Z",
        source_url_sha256="sha256:" + ("7" * 64),
        source_url_expires_at="2026-08-15T00:01:00Z",
        tag_ref=f"refs/tags/{TAG}",
        tag_object_type="tag",
        tag_object_sha=TAG_OBJECT_SHA,
        policy_path=".agents/policy/github-branch-protection.yml",
        policy_source_commit_sha=COMMIT_SHA,
        policy_blob_sha="6" * 40,
        policy_sha256=POLICY_SHA256,
        provider_response_sha256=PROVIDER_RESPONSE_DIGEST,
        broker_request_id="request-01HXDPONE",
        candidate_reader_service_identity=(
            "cloudflare-worker:account-01/dpone-release-candidate-reader@candidate-reader-version-01"
        ),
        candidate_reader_service_version_id="candidate-reader-version-01",
        candidate_reader_deployment_observation_record_id=("sha256:" + ("8" * 64)),
        candidate_reader_deployment_observation_record_sha256=("sha256:" + ("9" * 64)),
    )


def _zip_tree(
    root: Path,
    *,
    duplicate: bool = False,
    symlink: bool = False,
    unsafe_name: str | None = None,
) -> bytes:
    data = io.BytesIO()
    paths = sorted(path for path in root.rglob("*") if path.is_file())
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for index, path in enumerate(paths):
            relative = path.relative_to(root).as_posix()
            info = zipfile.ZipInfo(relative)
            info.create_system = 3
            info.external_attr = (
                stat.S_IFLNK if symlink and index == 0 else stat.S_IFREG
            ) << 16
            archive.writestr(info, path.read_bytes())
        if duplicate:
            archive.writestr(paths[0].relative_to(root).as_posix(), b"duplicate")
        if unsafe_name is not None:
            archive.writestr(unsafe_name, b"unsafe")
    return data.getvalue()


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _import_provider_candidate(*args):
    return import_provider_candidate(*args, clock=FROZEN_CLOCK)


if __name__ == "__main__":
    unittest.main()
