"""Closed archive and public-index comparison for retro PyPI receipts."""

from __future__ import annotations

import hashlib
import re
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

PYPI_API = "https://pypi.org/pypi"
PROJECT_DISTRIBUTIONS = {
    "dpone": "dpone",
    "dpone-native-accel": "dpone_native_accel",
    "dpone-airflow-pack": "dpone_airflow_pack",
    "apache-airflow-providers-dpone": "apache_airflow_providers_dpone",
}
DISTRIBUTION_SUFFIXES = (".tar.gz", "-py3-none-any.whl")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class InventoryFailure(ValueError):
    """Raised when immutable archives or public package metadata disagree."""


def read_artifact_inventory(
    artifact_zip: Path, version: str
) -> list[dict[str, object]]:
    """Read the exact expected release files without extracting the ZIP."""

    expected = expected_archives(version)
    try:
        with zipfile.ZipFile(artifact_zip) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise InventoryFailure(
                    "artifact inventory contains duplicate archive names"
                )
            if any(info.is_dir() or is_symlink(info) for info in infos):
                raise InventoryFailure(
                    "artifact inventory contains a directory or symlink"
                )
            if set(names) != set(expected):
                raise InventoryFailure(
                    f"artifact inventory differs: expected={sorted(expected)!r} actual={sorted(names)!r}"
                )
            files = []
            for name in sorted(names):
                payload = archive.read(name)
                files.append(
                    {
                        "project": expected[name],
                        "filename": name,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "size": len(payload),
                    }
                )
            return files
    except zipfile.BadZipFile as error:
        raise InventoryFailure("artifact ZIP is malformed") from error


def verify_public_inventory(
    version: str,
    inventory: list[dict[str, object]],
    fetch_json: Callable[[str], object],
) -> list[dict[str, object]]:
    """Require public non-yanked files to equal immutable artifact bytes."""

    expected_by_project: dict[str, dict[str, dict[str, object]]] = {}
    for entry in inventory:
        project = str(entry["project"])
        expected_by_project.setdefault(project, {})[str(entry["filename"])] = {
            "sha256": entry["sha256"],
            "size": entry["size"],
        }
    results = []
    for project in PROJECT_DISTRIBUTIONS:
        payload = require_mapping(
            fetch_json(f"{PYPI_API}/{project}/{version}/json"),
            f"{project} PyPI payload",
        )
        urls = payload.get("urls")
        if not isinstance(urls, list):
            raise InventoryFailure(f"{project}: public PyPI payload has no URL list")
        actual: dict[str, dict[str, object]] = {}
        for item in urls:
            if not isinstance(item, dict):
                raise InventoryFailure(f"{project}: public PyPI URL entry is malformed")
            filename = item.get("filename")
            digest = require_mapping(item.get("digests"), f"{project}: public digest")
            if not isinstance(filename, str) or not _SHA256.fullmatch(
                str(digest.get("sha256", ""))
            ):
                raise InventoryFailure(f"{project}: public PyPI file is malformed")
            actual[filename] = {
                "sha256": digest["sha256"],
                "size": item.get("size"),
                "yanked": item.get("yanked") is True,
            }
        normalized_actual = {
            filename: {"sha256": data["sha256"], "size": data["size"]}
            for filename, data in actual.items()
            if data["yanked"] is False
        }
        if normalized_actual != expected_by_project[project] or any(
            data["yanked"] for data in actual.values()
        ):
            raise InventoryFailure(
                f"{project}: public inventory differs from immutable artifact"
            )
        results.append({"project": project, "status": "PASS", "files": actual})
    return results


def expected_archives(version: str) -> dict[str, str]:
    """Return the closed four-project/two-file inventory for a version."""

    return {
        f"{distribution}-{version}{suffix}": project
        for project, distribution in PROJECT_DISTRIBUTIONS.items()
        for suffix in DISTRIBUTION_SUFFIXES
    }


def require_mapping(value: object, subject: str) -> dict[str, Any]:
    """Return a JSON object or fail closed."""

    if not isinstance(value, dict):
        raise InventoryFailure(f"{subject} is malformed")
    return value


def is_symlink(info: zipfile.ZipInfo) -> bool:
    """Return whether a ZIP entry carries a Unix symbolic-link mode."""

    return (info.external_attr >> 16) & 0o170000 == 0o120000
