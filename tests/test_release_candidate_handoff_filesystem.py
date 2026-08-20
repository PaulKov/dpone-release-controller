"""Adversarial tests for the closed release-candidate handoff."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.evidence import release_candidate_codec as candidate_codec
from tools.evidence import release_candidate_files as candidate_files
from tools.evidence.release_candidate_handoff import (
    ArtifactBinding,
    CANDIDATE_INVENTORY_PATH,
    CHECKSUM_PATH,
    CandidateHandoffError,
    verify_candidate_artifact,
)
from tests.release_candidate_handoff_test_support import (
    ARTIFACT_DIGEST,
    ARTIFACT_ID,
    COMMIT_SHA,
    RUN_ATTEMPT,
    RUN_ID,
    TAG,
    _binding,
    _file_record,
    _parse_candidate_inventory_with_sizes,
    _rebind_candidate_inventory,
    _rebind_member,
    _seal_manifest,
    write_candidate,
    _write_json,
)


class CandidateHandoffFilesystemTests(unittest.TestCase):
    def test_extra_missing_and_tampered_members_fail_closed(self) -> None:
        mutations = {
            "extra": lambda root: (root / "unexpected.txt").write_text("x"),
            "missing": lambda root: (
                root / "evidence/candidate/package-smoke.txt"
            ).unlink(),
            "tampered": lambda root: (
                root / "evidence/candidate/package-smoke.txt"
            ).write_text("changed"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_candidate(root)
                mutate(root)
                with self.assertRaises(CandidateHandoffError):
                    verify_candidate_artifact(root, _binding())

    def test_symbolic_link_is_never_followed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_candidate(root)
            target = root / "evidence/candidate/package-smoke.txt"
            target.unlink()
            target.symlink_to(root / "release_notes.md")

            with self.assertRaisesRegex(CandidateHandoffError, "symbolic links"):
                verify_candidate_artifact(root, _binding())

    def test_fifo_is_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_candidate(root)
            target = root / "evidence/candidate/package-smoke.txt"
            target.unlink()
            os.mkfifo(target)

            with self.assertRaisesRegex(CandidateHandoffError, "non-regular"):
                verify_candidate_artifact(root, _binding())

    def test_fstat_identity_change_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_candidate(root)
            real_fstat = os.fstat
            calls = 0

            def racing_fstat(descriptor: int) -> os.stat_result:
                nonlocal calls
                result = real_fstat(descriptor)
                calls += 1
                if calls == 2:
                    values = list(result)
                    values[6] += 1
                    return os.stat_result(values)
                return result

            with patch(
                "tools.evidence.release_candidate_files.os.fstat",
                side_effect=racing_fstat,
            ):
                with self.assertRaisesRegex(CandidateHandoffError, "identity changed"):
                    verify_candidate_artifact(root, _binding())

    def test_untrusted_dispatch_selector_mismatch_is_rejected(self) -> None:
        selectors = {
            "run_id": ArtifactBinding(
                RUN_ID + 1, RUN_ATTEMPT, ARTIFACT_ID, ARTIFACT_DIGEST, TAG, COMMIT_SHA
            ),
            "run_attempt": ArtifactBinding(
                RUN_ID, 2, ARTIFACT_ID, ARTIFACT_DIGEST, TAG, COMMIT_SHA
            ),
            "release": ArtifactBinding(
                RUN_ID, RUN_ATTEMPT, ARTIFACT_ID, ARTIFACT_DIGEST, "v0.74.1", COMMIT_SHA
            ),
            "commit": ArtifactBinding(
                RUN_ID, RUN_ATTEMPT, ARTIFACT_ID, ARTIFACT_DIGEST, TAG, "9" * 40
            ),
        }
        for name, binding in selectors.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_candidate(root)
                with self.assertRaisesRegex(CandidateHandoffError, "outer artifact"):
                    verify_candidate_artifact(root, binding)

    def test_dispatch_numeric_tag_and_digest_syntax_is_strict(self) -> None:
        invalid = (
            {"run_id": "0"},
            {"run_id": "+1"},
            {"run_id": "١"},
            {"run_id": "9007199254740992"},
            {"run_attempt": "0"},
            {"artifact_id": "9007199254740992"},
            {"artifact_id": "1.0"},
            {"artifact_digest": "5" * 64},
            {"expected_tag": "v0.74.0+local"},
            {"expected_peeled_commit_sha": "A" * 40},
        )
        defaults = {
            "run_id": str(RUN_ID),
            "run_attempt": str(RUN_ATTEMPT),
            "artifact_id": str(ARTIFACT_ID),
            "artifact_digest": ARTIFACT_DIGEST,
            "expected_tag": TAG,
            "expected_peeled_commit_sha": COMMIT_SHA,
        }
        for replacement in invalid:
            with self.subTest(replacement=replacement):
                with self.assertRaises(CandidateHandoffError):
                    ArtifactBinding.from_strings(**{**defaults, **replacement})

    def test_manifest_workflow_numbers_are_positive_js_safe_integers(self) -> None:
        for field in ("run_id", "run_attempt"):
            for value in (False, True, 0):
                with (
                    self.subTest(field=field, value=value),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    manifest = write_candidate(root)
                    manifest["workflow"][field] = value
                    _seal_manifest(root, manifest)

                    with self.assertRaisesRegex(
                        CandidateHandoffError, "positive JS-safe integer"
                    ):
                        verify_candidate_artifact(root, _binding())
            for value in (9_007_199_254_740_992, 1.0):
                with (
                    self.subTest(field=field, value=value),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    manifest = write_candidate(root)
                    manifest["workflow"][field] = value

                    with self.assertRaisesRegex(
                        CandidateHandoffError, "canonical JSON domain"
                    ):
                        candidate_codec.parse_manifest(manifest)

    def test_manifest_identities_are_recomputed_not_trusted(self) -> None:
        for field in ("release_identity_id", "release_authority_id", "candidate_id"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = write_candidate(root)
                manifest[field] = "sha256:" + ("f" * 64)
                _seal_manifest(root, manifest)
                with self.assertRaisesRegex(CandidateHandoffError, field):
                    verify_candidate_artifact(root, _binding())

    def test_manifest_self_digest_is_plain_canonical_body_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = write_candidate(root)
            manifest["release"] = "v0.74.1"
            _write_json(root / "candidate-handoff-v2.json", manifest)

            with self.assertRaisesRegex(CandidateHandoffError, "manifest_sha256"):
                verify_candidate_artifact(root, _binding())

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_candidate(root)
            manifest_path = root / "candidate-handoff-v2.json"
            original = manifest_path.read_text()
            manifest_path.write_text(
                original.replace(
                    '"schema": "dpone.release-candidate-handoff.v2",',
                    '"schema": "dpone.release-candidate-handoff.v2",\n  "schema": "dpone.release-candidate-handoff.v2",',
                    1,
                )
            )
            with self.assertRaisesRegex(CandidateHandoffError, "duplicate JSON key"):
                verify_candidate_artifact(root, _binding())

    def test_raw_candidate_inventory_bytes_are_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = write_candidate(root)
            inventory_path = root / CANDIDATE_INVENTORY_PATH
            inventory = json.loads(inventory_path.read_text())
            inventory_path.write_text(
                json.dumps(inventory, sort_keys=True, separators=(",", ":"))
            )
            replacement = _file_record(root, CANDIDATE_INVENTORY_PATH)
            manifest["members"] = [
                replacement if item["path"] == CANDIDATE_INVENTORY_PATH else item
                for item in manifest["members"]
            ]
            _seal_manifest(root, manifest)

            with self.assertRaisesRegex(CandidateHandoffError, "raw inventory"):
                verify_candidate_artifact(root, _binding())

    def test_candidate_inventory_artifact_order_is_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = write_candidate(root)
            inventory_path = root / CANDIDATE_INVENTORY_PATH
            candidate_inventory = json.loads(inventory_path.read_text())
            candidate_inventory["artifacts"] = list(
                reversed(candidate_inventory["artifacts"])
            )
            _write_json(inventory_path, candidate_inventory)
            _rebind_candidate_inventory(root, manifest)

            with self.assertRaisesRegex(CandidateHandoffError, "bytewise sorted"):
                verify_candidate_artifact(root, _binding())

    def test_checksum_asset_grammar_inventory_and_order_are_authoritative(self) -> None:
        for mutation in (
            "digest",
            "order",
            "duplicate",
            "one-space",
            "dist-prefix",
            "missing-line",
            "extra-line",
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                manifest = write_candidate(root)
                path = root / CHECKSUM_PATH
                lines = path.read_text(encoding="ascii").splitlines(keepends=True)
                if mutation == "digest":
                    lines[0] = ("f" * 64) + lines[0][64:]
                elif mutation == "order":
                    lines.reverse()
                elif mutation == "duplicate":
                    lines[1] = lines[0]
                elif mutation == "one-space":
                    lines[0] = lines[0].replace("  ", " ", 1)
                elif mutation == "dist-prefix":
                    lines[0] = lines[0].replace("  ", "  dist/", 1)
                elif mutation == "missing-line":
                    lines.pop()
                else:
                    lines.append(lines[-1])
                path.write_text("".join(lines), encoding="ascii")
                _rebind_member(root, manifest, CHECKSUM_PATH)

                with self.assertRaisesRegex(CandidateHandoffError, "checksum asset"):
                    verify_candidate_artifact(root, _binding())

    def test_checksum_asset_is_rechecked_after_semantic_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_candidate(root)
            real_hash_regular = candidate_files.hash_regular

            def racing_hash(candidate_root: Path, relative: str) -> tuple[int, str]:
                if relative == CHECKSUM_PATH:
                    (candidate_root / relative).write_bytes(b"changed\n")
                return real_hash_regular(candidate_root, relative)

            with patch(
                "tools.evidence.release_candidate_handoff.files.hash_regular",
                side_effect=racing_hash,
            ):
                with self.assertRaisesRegex(
                    CandidateHandoffError, "member size mismatch"
                ):
                    verify_candidate_artifact(root, _binding())

    def test_pypi_file_limit_is_enforced_by_semantic_importer(self) -> None:
        sizes = [100_000_001, *([1] * 7)]
        with self.assertRaisesRegex(CandidateHandoffError, "100000000-byte file"):
            _parse_candidate_inventory_with_sizes(sizes)

    def test_pypi_aggregate_limit_is_enforced_without_large_files(self) -> None:
        sizes = [67_108_865, *([67_108_864] * 7)]
        self.assertEqual(sum(sizes), 536_870_913)
        with self.assertRaisesRegex(CandidateHandoffError, "aggregate limit"):
            _parse_candidate_inventory_with_sizes(sizes)

    def test_near_prefix_and_non_numeric_wheel_build_tag_are_rejected(self) -> None:
        invalid_names = (
            "dpone-0.74.0evil-py3-none-any.whl",
            "dpone-0.74.0-abc-py3-none-any.whl",
        )
        for filename in invalid_names:
            with (
                self.subTest(filename=filename),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                write_candidate(root, filename_overrides={("dpone", "wheel"): filename})
                with self.assertRaisesRegex(CandidateHandoffError, "wheel"):
                    verify_candidate_artifact(root, _binding())

    def test_archive_metadata_name_is_revalidated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_candidate(
                root, metadata_name_overrides={("dpone", "wheel"): "not-dpone"}
            )

            with self.assertRaisesRegex(CandidateHandoffError, "metadata Name/Version"):
                verify_candidate_artifact(root, _binding())
