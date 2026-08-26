"""Contract tests for the read-only historical PyPI verifier."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from tools import retro_pypi_verification as verifier
from tools import retro_pypi_install as installer


VERSION = "0.74.27"
TAG = f"v{VERSION}"
COMMIT = "62f1631d5088d26ad4da9ab67156e61c0456b866"
RUN_ID = 32963303606
ARTIFACT_ID = 9604709818


class RetroPyPIVerificationTests(unittest.TestCase):
    """Keep the evidence boundary closed and deterministic."""

    def test_verifies_closed_artifact_against_tag_and_public_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "artifact.zip"
            expected = _write_artifact(artifact)
            artifact_digest = _sha256(artifact)

            result = verifier.verify(
                verifier.VerificationRequest(
                    tag=TAG,
                    commit_sha=COMMIT,
                    controller_run_id=RUN_ID,
                    artifact_id=ARTIFACT_ID,
                    artifact_zip=artifact,
                    artifact_sha256=artifact_digest,
                ),
                fetch_json=_fetcher(expected, artifact_digest, artifact.stat().st_size),
                observed_at="2026-08-26T12:30:00Z",
            )

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["subject"]["commit_sha"], COMMIT)
        self.assertEqual(result["artifact"]["sha256"], artifact_digest)
        self.assertEqual(len(result["projects"]), 4)
        self.assertTrue(all(entry["status"] == "PASS" for entry in result["projects"]))

    def test_rejects_extra_archive_before_public_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "artifact.zip"
            _write_artifact(artifact, extra=("surprise.whl", b"unexpected"))

            result = verifier.verify(
                _request(artifact), fetch_json=lambda _: self.fail("must not fetch")
            )

        self.assertEqual(result["status"], "FAIL")
        self.assertIn("inventory", result["failures"][0])

    def test_reports_unverified_when_public_observation_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "artifact.zip"
            _write_artifact(artifact)

            def unavailable(_: str) -> object:
                raise TimeoutError("offline")

            result = verifier.verify(_request(artifact), fetch_json=unavailable)

        self.assertEqual(result["status"], "UNVERIFIED")
        self.assertIn("unavailable", result["failures"][0])

    def test_rejects_yanked_or_hash_mismatched_public_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "artifact.zip"
            expected = _write_artifact(artifact)
            fetch_json = _fetcher(
                expected, _sha256(artifact), artifact.stat().st_size, yanked=True
            )

            result = verifier.verify(_request(artifact), fetch_json=fetch_json)

        self.assertEqual(result["status"], "FAIL")
        self.assertIn("public inventory", result["failures"][0])

    def test_writes_receipt_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact.zip"
            expected = _write_artifact(artifact)
            output = root / "nested" / "receipt.json"
            result = verifier.verify(
                _request(artifact),
                _fetcher(expected, _sha256(artifact), artifact.stat().st_size),
            )

            verifier.write_receipt(output, result)

            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), result)
            self.assertFalse(list(output.parent.glob("*.tmp")))

    def test_rejects_controller_run_outside_pypi_publisher_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "artifact.zip"
            expected = _write_artifact(artifact)
            result = verifier.verify(
                _request(artifact),
                _fetcher(
                    expected,
                    _sha256(artifact),
                    artifact.stat().st_size,
                    run_conclusion="failure",
                ),
            )

        self.assertEqual(result["status"], "FAIL")
        self.assertIn("successful PyPI publisher", result["failures"][0])

    def test_cli_rejects_invalid_subject_before_network(self) -> None:
        self.assertEqual(verifier.main(["--tag", "release-0.74.27"]), 2)

    def test_isolated_install_transcript_is_produced_by_the_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact.zip"
            archives = _write_wheels(artifact)
            transcript = root / "fresh_install.log"
            with patch.object(
                installer,
                "_run",
                return_value=("No broken requirements found.\nusage: dpone\n", 0),
            ):
                evidence = installer.create_isolated_install_evidence(
                    artifact, archives, transcript
                )

            self.assertEqual(evidence["transcript"], "fresh_install.log")
            self.assertEqual(
                evidence["sha256"], hashlib.sha256(transcript.read_bytes()).hexdigest()
            )

    def test_isolated_install_failure_still_writes_its_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact.zip"
            archives = _write_wheels(artifact)
            transcript = root / "fresh_install.log"
            with patch.object(installer, "_run", return_value=("failed\n", 1)):
                with self.assertRaises(installer.IsolatedInstallFailure):
                    installer.create_isolated_install_evidence(
                        artifact, archives, transcript
                    )

            self.assertEqual(transcript.read_text(encoding="utf-8"), "failed\n")

    def test_isolated_install_rejects_wheel_bytes_changed_after_verification(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact.zip"
            archives = _write_wheels(artifact)
            _write_wheels(artifact, payload=b"changed")
            with self.assertRaises(installer.IsolatedInstallFailure):
                installer.create_isolated_install_evidence(
                    artifact, archives, root / "fresh_install.log"
                )


def _request(artifact: Path) -> verifier.VerificationRequest:
    return verifier.VerificationRequest(
        tag=TAG,
        commit_sha=COMMIT,
        controller_run_id=RUN_ID,
        artifact_id=ARTIFACT_ID,
        artifact_zip=artifact,
        artifact_sha256=_sha256(artifact),
    )


def _write_artifact(
    artifact: Path, extra: tuple[str, bytes] | None = None
) -> dict[str, dict[str, dict[str, object]]]:
    expected: dict[str, dict[str, dict[str, object]]] = {}
    with zipfile.ZipFile(artifact, "w") as archive:
        for project, distribution in verifier.PROJECT_DISTRIBUTIONS.items():
            files: dict[str, dict[str, object]] = {}
            for suffix in verifier.DISTRIBUTION_SUFFIXES:
                filename = f"{distribution}-{VERSION}{suffix}"
                payload = f"{project}/{filename}".encode()
                archive.writestr(filename, payload)
                files[filename] = {
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            expected[project] = files
        if extra:
            archive.writestr(*extra)
    return expected


def _write_wheels(artifact: Path, payload: bytes = b"wheel") -> list[dict[str, object]]:
    archives = []
    with zipfile.ZipFile(artifact, "w") as archive:
        for distribution in verifier.PROJECT_DISTRIBUTIONS.values():
            filename = f"{distribution}-{VERSION}-py3-none-any.whl"
            archive.writestr(filename, payload)
            archives.append(
                {
                    "filename": filename,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            )
    return archives


def _fetcher(
    expected: dict[str, dict[str, dict[str, object]]],
    artifact_digest: str,
    artifact_size: int,
    yanked: bool = False,
    run_conclusion: str = "success",
):
    def fetch(url: str) -> object:
        if url.endswith(f"/git/ref/tags/{TAG}"):
            return {"object": {"type": "tag", "sha": "a" * 40}}
        if url.endswith(f"/git/tags/{'a' * 40}"):
            return {"object": {"type": "commit", "sha": COMMIT}}
        if url.endswith(f"/actions/runs/{RUN_ID}"):
            return {
                "conclusion": run_conclusion,
                "event": "workflow_dispatch",
                "path": ".github/workflows/pypi-release.yml",
                "repository": {"full_name": verifier.CONTROLLER_REPOSITORY},
            }
        if url.endswith(f"/actions/runs/{RUN_ID}/artifacts"):
            return {
                "artifacts": [
                    {
                        "id": ARTIFACT_ID,
                        "name": f"dpone-pypi-{VERSION}",
                        "size_in_bytes": artifact_size,
                        "digest": f"sha256:{artifact_digest}",
                        "expired": False,
                    }
                ]
            }
        for project, files in expected.items():
            if url.endswith(f"/pypi/{project}/{VERSION}/json"):
                return {
                    "urls": [
                        {
                            "filename": filename,
                            "digests": {"sha256": data["sha256"]},
                            "size": data["size"],
                            "yanked": yanked,
                        }
                        for filename, data in files.items()
                    ]
                }
        raise AssertionError(f"unexpected URL: {url}")

    return fetch


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
