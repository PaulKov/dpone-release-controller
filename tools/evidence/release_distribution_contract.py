"""Canonical eight-file release distribution naming and ordering."""

from __future__ import annotations

import re

PROJECTS = (
    "apache-airflow-providers-dpone",
    "dpone",
    "dpone-airflow-pack",
    "dpone-native-accel",
)
ARTIFACT_TYPES = ("wheel", "sdist")
_VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


class DistributionContractError(ValueError):
    """A distribution name is outside the frozen release matrix."""


def filename(project: str, version: str, artifact_type: str) -> str:
    """Return the sole filename for one project/type in a release candidate."""

    if project not in PROJECTS:
        raise DistributionContractError("distribution project is not frozen")
    if not isinstance(version, str) or _VERSION_RE.fullmatch(version) is None:
        raise DistributionContractError("distribution version is not stable")
    if artifact_type not in ARTIFACT_TYPES:
        raise DistributionContractError("distribution artifact type is invalid")
    stem = project.replace("-", "_")
    suffix = "-py3-none-any.whl" if artifact_type == "wheel" else ".tar.gz"
    return f"{stem}-{version}{suffix}"


def matrix(version: str) -> tuple[tuple[str, str, str], ...]:
    """Return exact project/type/name rows in authoritative receipt order."""

    return tuple(
        (project, artifact_type, filename(project, version, artifact_type))
        for project in PROJECTS
        for artifact_type in ARTIFACT_TYPES
    )
