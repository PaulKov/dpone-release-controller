"""Bounded wheel/sdist metadata verification for release candidates."""

from __future__ import annotations

import email.policy
import io
import stat
import tarfile
import zipfile
from email.parser import BytesParser

from tools.evidence import release_candidate_contract as contract

MAX_ARCHIVE_ENTRIES = 4_096
MAX_ARCHIVE_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024


def verify(
    data: bytes,
    distribution: contract.DistributionRecord,
    release: str,
) -> None:
    """Require package metadata to repeat the exact inventory Name/Version."""

    metadata = (
        _read_wheel_metadata(data, distribution)
        if distribution.artifact_type == "wheel"
        else _read_sdist_metadata(data, distribution)
    )
    parsed = BytesParser(policy=email.policy.compat32).parsebytes(metadata)
    names = parsed.get_all("Name", [])
    versions = parsed.get_all("Version", [])
    expected_version = release.removeprefix("v")
    if (
        len(names) != 1
        or contract.normalize_project(str(names[0])) != distribution.package
        or versions != [expected_version]
    ):
        raise contract.CandidateHandoffError(
            f"archive metadata Name/Version mismatch: {distribution.filename}"
        )


def _read_wheel_metadata(
    data: bytes,
    distribution: contract.DistributionRecord,
) -> bytes:
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                raise contract.CandidateHandoffError(
                    "wheel archive has too many entries"
                )
            names: set[str] = set()
            expanded = 0
            metadata_infos: list[zipfile.ZipInfo] = []
            expected = (
                distribution.package.replace("-", "_")
                + "-"
                + distribution.version
                + ".dist-info/METADATA"
            )
            for info in infos:
                path = contract.require_safe_path(
                    info.filename.rstrip("/"), "wheel member"
                )
                if path in names:
                    raise contract.CandidateHandoffError(
                        "wheel contains duplicate member names"
                    )
                names.add(path)
                if info.flag_bits & 0x1:
                    raise contract.CandidateHandoffError(
                        "encrypted wheel members are forbidden"
                    )
                mode = (info.external_attr >> 16) & 0xFFFF
                if mode and stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise contract.CandidateHandoffError(
                        "non-regular wheel members are forbidden"
                    )
                expanded += info.file_size
                if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
                    raise contract.CandidateHandoffError(
                        "wheel expanded size exceeds limit"
                    )
                if path == expected:
                    metadata_infos.append(info)
            if len(metadata_infos) != 1:
                raise contract.CandidateHandoffError(
                    "wheel must contain one exact METADATA member"
                )
            for candidate in infos:
                if candidate.is_dir():
                    continue
                observed = 0
                with archive.open(candidate, "r") as stream:
                    while chunk := stream.read(1024 * 1024):
                        observed += len(chunk)
                        if observed > candidate.file_size:
                            raise contract.CandidateHandoffError(
                                "wheel member expands beyond its declared size"
                            )
                if observed != candidate.file_size:
                    raise contract.CandidateHandoffError(
                        "wheel member size or CRC validation failed"
                    )
            info = metadata_infos[0]
            if info.file_size <= 0 or info.file_size > MAX_METADATA_BYTES:
                raise contract.CandidateHandoffError(
                    "wheel METADATA size is outside limits"
                )
            metadata = archive.read(info)
    except contract.CandidateHandoffError:
        raise
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        raise contract.CandidateHandoffError(f"invalid wheel archive: {exc}") from exc
    if len(metadata) != info.file_size:
        raise contract.CandidateHandoffError("wheel METADATA changed while reading")
    return metadata


def _read_sdist_metadata(
    data: bytes,
    distribution: contract.DistributionRecord,
) -> bytes:
    expected_root = distribution.filename[: -len(".tar.gz")]
    expected = f"{expected_root}/PKG-INFO"
    metadata_members: list[tarfile.TarInfo] = []
    names: set[str] = set()
    expanded = 0
    count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive:
                count += 1
                if count > MAX_ARCHIVE_ENTRIES:
                    raise contract.CandidateHandoffError(
                        "sdist archive has too many entries"
                    )
                path = contract.require_safe_path(
                    member.name.rstrip("/"), "sdist member"
                )
                if path in names:
                    raise contract.CandidateHandoffError(
                        "sdist contains duplicate member names"
                    )
                names.add(path)
                if not (member.isfile() or member.isdir()):
                    raise contract.CandidateHandoffError(
                        "non-regular sdist members are forbidden"
                    )
                expanded += member.size
                if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
                    raise contract.CandidateHandoffError(
                        "sdist expanded size exceeds limit"
                    )
                if path == expected:
                    metadata_members.append(member)
            if len(metadata_members) != 1:
                raise contract.CandidateHandoffError(
                    "sdist must contain one exact PKG-INFO member"
                )
            member = metadata_members[0]
            if member.size <= 0 or member.size > MAX_METADATA_BYTES:
                raise contract.CandidateHandoffError(
                    "sdist PKG-INFO size is outside limits"
                )
            stream = archive.extractfile(member)
            if stream is None:
                raise contract.CandidateHandoffError("sdist PKG-INFO is not readable")
            metadata = stream.read(MAX_METADATA_BYTES + 1)
    except contract.CandidateHandoffError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise contract.CandidateHandoffError(f"invalid sdist archive: {exc}") from exc
    if len(metadata) != member.size or len(metadata) > MAX_METADATA_BYTES:
        raise contract.CandidateHandoffError("sdist PKG-INFO size mismatch")
    return metadata
