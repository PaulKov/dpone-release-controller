"""Create a read-only integrity receipt for a historical dpone PyPI release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from tools.retro_pypi_inventory import (
    DISTRIBUTION_SUFFIXES,  # noqa: F401 - re-exported for verification callers.
    PROJECT_DISTRIBUTIONS,  # noqa: F401 - re-exported for verification callers.
    InventoryFailure,
    read_artifact_inventory,
    require_mapping as _require_mapping,
    verify_public_inventory,
)
from tools.retro_pypi_install import (
    IsolatedInstallFailure,
    create_isolated_install_evidence,
)

GITHUB_API = "https://api.github.com"
DPONE_REPOSITORY = "PaulKov/dpone"
CONTROLLER_REPOSITORY = "PaulKov/dpone-release-controller"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")


class InputError(ValueError):
    """Raised when the caller provides an invalid evidence subject."""


class VerificationFailure(ValueError):
    """Raised when an immutable or public observation disagrees."""


class ObservationUnavailable(RuntimeError):
    """Raised only when an observation cannot be obtained conclusively."""


class _ArgumentParser(argparse.ArgumentParser):
    """Translate argparse failures into the verifier's public input outcome."""

    def error(self, message: str) -> None:
        raise InputError(message)


@dataclass(frozen=True)
class VerificationRequest:
    """Immutable input identifying one historical release publication."""

    tag: str
    commit_sha: str
    controller_run_id: int
    artifact_id: int
    artifact_zip: Path
    artifact_sha256: str

    @property
    def version(self) -> str:
        """Return the semantic version encoded in the validated tag."""

        return self.tag.removeprefix("v")


JsonFetcher = Callable[[str], object]


def verify(
    request: VerificationRequest,
    fetch_json: JsonFetcher,
    observed_at: str | None = None,
) -> dict[str, object]:
    """Return a fail-closed receipt from immutable artifact and public bytes."""

    _validate_request(request)
    timestamp = observed_at or datetime.now(UTC).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    receipt = _base_receipt(request, timestamp)
    try:
        inventory = read_artifact_inventory(request.artifact_zip, request.version)
        receipt["artifact"]["archives"] = inventory
        _verify_tag(request, fetch_json, receipt)
        _verify_artifact_metadata(request, fetch_json, receipt)
        projects = verify_public_inventory(request.version, inventory, fetch_json)
        receipt["projects"] = projects
    except (ObservationUnavailable, TimeoutError, URLError, OSError) as error:
        receipt["status"] = "UNVERIFIED"
        receipt["failures"] = [f"observation unavailable: {error}"]
    except (VerificationFailure, InventoryFailure) as error:
        receipt["status"] = "FAIL"
        receipt["failures"] = [str(error)]
    else:
        receipt["status"] = "PASS"
        receipt["failures"] = []
    return receipt


def write_receipt(output: Path, receipt: dict[str, object]) -> None:
    """Atomically write a canonical JSON receipt without replacing on failure."""

    output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=output.parent, delete=False, suffix=".tmp"
    ) as temporary:
        temporary.write(payload)
        temporary.flush()
        os.fsync(temporary.fileno())
        temporary_path = Path(temporary.name)
    temporary_path.replace(output)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse the narrow, immutable historical-publication subject."""

    parser = _ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--controller-run-id", type=int, required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--artifact-zip", type=Path, required=True)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    _validate_request(
        VerificationRequest(
            tag=arguments.tag,
            commit_sha=arguments.commit_sha,
            controller_run_id=arguments.controller_run_id,
            artifact_id=arguments.artifact_id,
            artifact_zip=arguments.artifact_zip,
            artifact_sha256=arguments.artifact_sha256,
        )
    )
    return arguments


def main(argv: list[str] | None = None) -> int:
    """Verify one historical publication and write its evidence receipt."""

    try:
        arguments = parse_args(argv)
    except InputError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    request = VerificationRequest(
        tag=arguments.tag,
        commit_sha=arguments.commit_sha,
        controller_run_id=arguments.controller_run_id,
        artifact_id=arguments.artifact_id,
        artifact_zip=arguments.artifact_zip,
        artifact_sha256=arguments.artifact_sha256,
    )
    receipt = verify(request, _live_fetch_json)
    if receipt["status"] == "PASS":
        try:
            receipt["isolated_install"] = create_isolated_install_evidence(
                request.artifact_zip,
                receipt["artifact"]["archives"],
                arguments.output.with_name("fresh_install.log"),
            )
        except IsolatedInstallFailure as error:
            receipt["status"] = "FAIL"
            receipt["failures"] = [*receipt["failures"], str(error)]
    write_receipt(arguments.output, receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


def _validate_request(request: VerificationRequest) -> None:
    if not _TAG.fullmatch(request.tag):
        raise InputError("tag must be an exact vMAJOR.MINOR.PATCH tag")
    if not _COMMIT.fullmatch(request.commit_sha):
        raise InputError(
            "commit SHA must contain exactly 40 lowercase hexadecimal characters"
        )
    if request.controller_run_id <= 0 or request.artifact_id <= 0:
        raise InputError("controller run id and artifact id must be positive")
    if not _SHA256.fullmatch(request.artifact_sha256):
        raise InputError(
            "artifact SHA-256 must contain exactly 64 lowercase hexadecimal characters"
        )
    if not request.artifact_zip.is_file():
        raise InputError("artifact ZIP must be an existing regular file")


def _base_receipt(request: VerificationRequest, observed_at: str) -> dict[str, object]:
    return {
        "schema": "dpone.retro-pypi-verification.v1",
        "status": "UNVERIFIED",
        "observed_at": observed_at,
        "subject": {
            "tag": request.tag,
            "version": request.version,
            "commit_sha": request.commit_sha,
            "controller_run_id": request.controller_run_id,
        },
        "artifact": {
            "id": request.artifact_id,
            "name": f"dpone-pypi-{request.version}",
            "sha256": request.artifact_sha256,
            "local_size": request.artifact_zip.stat().st_size,
            "archives": [],
        },
        "projects": [],
        "failures": [],
    }


def _verify_tag(
    request: VerificationRequest, fetch_json: JsonFetcher, receipt: dict[str, object]
) -> None:
    reference = _require_mapping(
        fetch_json(f"{GITHUB_API}/repos/{DPONE_REPOSITORY}/git/ref/tags/{request.tag}"),
        "tag reference",
    )
    tag_object = _require_mapping(reference.get("object"), "tag reference object")
    if tag_object.get("type") != "tag":
        raise VerificationFailure("release reference is not an annotated tag")
    tag_sha = _require_sha(tag_object.get("sha"), "annotated tag SHA")
    tag = _require_mapping(
        fetch_json(f"{GITHUB_API}/repos/{DPONE_REPOSITORY}/git/tags/{tag_sha}"),
        "annotated tag",
    )
    commit = _require_mapping(tag.get("object"), "annotated tag commit")
    if commit.get("type") != "commit" or commit.get("sha") != request.commit_sha:
        raise VerificationFailure(
            "annotated tag does not resolve to the declared commit"
        )
    receipt["subject"]["annotated_tag_sha"] = tag_sha


def _verify_artifact_metadata(
    request: VerificationRequest, fetch_json: JsonFetcher, receipt: dict[str, object]
) -> None:
    run = _require_mapping(
        fetch_json(
            f"{GITHUB_API}/repos/{CONTROLLER_REPOSITORY}/actions/runs/"
            f"{request.controller_run_id}"
        ),
        "controller run",
    )
    repository = _require_mapping(run.get("repository"), "controller run repository")
    if (
        run.get("conclusion") != "success"
        or run.get("event") != "workflow_dispatch"
        or run.get("path") != ".github/workflows/pypi-release.yml"
        or repository.get("full_name") != CONTROLLER_REPOSITORY
    ):
        raise VerificationFailure("controller run is not the successful PyPI publisher")
    payload = _require_mapping(
        fetch_json(
            f"{GITHUB_API}/repos/{CONTROLLER_REPOSITORY}/actions/runs/"
            f"{request.controller_run_id}/artifacts"
        ),
        "controller artifact list",
    )
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        raise VerificationFailure("controller artifact list is malformed")
    matches = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict) and artifact.get("id") == request.artifact_id
    ]
    if len(matches) != 1:
        raise VerificationFailure("controller artifact id is absent or ambiguous")
    artifact = matches[0]
    expected_digest = f"sha256:{request.artifact_sha256}"
    if (
        artifact.get("name") != f"dpone-pypi-{request.version}"
        or artifact.get("digest") != expected_digest
        or artifact.get("expired") is not False
        or artifact.get("size_in_bytes") != request.artifact_zip.stat().st_size
    ):
        raise VerificationFailure(
            "controller artifact metadata does not match local ZIP"
        )
    if _sha256_file(request.artifact_zip) != request.artifact_sha256:
        raise VerificationFailure(
            "local artifact ZIP SHA-256 differs from declared digest"
        )
    receipt["artifact"]["provider_size"] = artifact["size_in_bytes"]
    receipt["subject"]["controller_workflow_path"] = run["path"]


def _http_fetch_json(url: str) -> object:
    for attempt in range(3):
        try:
            with urlopen(url, timeout=20) as response:  # noqa: S310 - fixed HTTPS endpoints.
                return json.load(response)
        except HTTPError as error:
            if error.code not in {403, 408, 429, 500, 502, 503, 504}:
                raise VerificationFailure(
                    f"HTTP {error.code} while observing {url}"
                ) from error
        except (URLError, TimeoutError, OSError) as error:
            last_error = error
        if attempt < 2:
            time.sleep(2)
    raise ObservationUnavailable(
        f"bounded request retries exhausted for {url}"
    ) from locals().get("last_error")


def _live_fetch_json(url: str) -> object:
    """Observe fixed GitHub endpoints through gh and PyPI through HTTPS."""

    if not url.startswith(GITHUB_API + "/repos/"):
        return _http_fetch_json(url)
    endpoint = url.removeprefix(GITHUB_API + "/")
    failure = ""
    for attempt in range(3):
        try:
            result = subprocess.run(
                ["gh", "api", endpoint], check=False, capture_output=True, text=True
            )
        except OSError as error:
            failure = str(error)
        else:
            if not result.returncode:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError as error:
                    raise ObservationUnavailable(
                        "GitHub observation was not JSON"
                    ) from error
            failure = result.stderr.strip()
        if attempt < 2:
            time.sleep(2)
    raise ObservationUnavailable(f"GitHub observation failed after retries: {failure}")


def _require_sha(value: object, subject: str) -> str:
    if not isinstance(value, str) or not _COMMIT.fullmatch(value):
        raise VerificationFailure(f"{subject} is malformed")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
