"""Application facade for provider-bound dpone candidate import.

Callers importing already extracted test fixtures use
``verify_candidate_artifact``. Production callers must use
``import_provider_candidate`` so the raw provider ZIP digest and authenticated
provider observation are bound before the extracted-tree checks run.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from tools.evidence import release_candidate_codec as codec
from tools.evidence import release_candidate_contract as contract
from tools.evidence import release_candidate_files as files
from tools.evidence import release_candidate_provider as provider


@dataclass(frozen=True, slots=True)
class ProviderBoundCandidate:
    """One provider ZIP proof paired with its exact semantic candidate."""

    provider_archive: provider.VerifiedProviderArchive
    candidate: contract.VerifiedCandidate

    def receipt_payload(self) -> dict[str, Any]:
        """Return the complete provider-bound ``CANDIDATE_HANDOFF`` payload."""

        return {
            **self.candidate.receipt_payload(),
            **self.provider_archive.receipt_payload(),
        }


def import_provider_candidate(
    source: provider.CandidateArchiveSource,
    observation: provider.ProviderArtifactObservation,
    binding: contract.ArtifactBinding,
    destination: Path,
    *,
    clock: provider.Clock = provider.SYSTEM_UTC_CLOCK,
) -> ProviderBoundCandidate:
    """Verify raw provider bytes, atomically extract, then verify the candidate."""

    provider_archive = provider.verify_and_extract_provider_archive(
        source, observation, binding, destination, clock=clock
    )
    candidate = verify_candidate_artifact(destination, binding)
    observation.require_manifest_authority(candidate.manifest)
    return ProviderBoundCandidate(provider_archive, candidate)


def verify_candidate_artifact(
    root: Path,
    binding: contract.ArtifactBinding,
) -> contract.VerifiedCandidate:
    """Verify one closed extracted tree with no-follow reads and archive metadata."""

    root = files.require_root(root)
    manifest_bytes, _ = files.read_regular(root, contract.MANIFEST_PATH)
    manifest = codec.parse_manifest(
        codec.load_unique_json(manifest_bytes, "candidate manifest")
    )
    codec.require_outer_binding(manifest, binding)

    expected_paths = {record.path for record in manifest.members}
    expected_paths.add(contract.MANIFEST_PATH)
    observed_paths = files.enumerate_closed_members(root)
    if observed_paths != expected_paths:
        missing = sorted(expected_paths - observed_paths)
        unexpected = sorted(observed_paths - expected_paths)
        raise contract.CandidateHandoffError(
            f"closed candidate member mismatch: missing={missing}, unexpected={unexpected}"
        )

    records = {record.path: record for record in manifest.members}
    inventory_record = records[contract.CANDIDATE_INVENTORY_PATH]
    inventory_bytes, inventory_digest = files.read_regular(
        root, contract.CANDIDATE_INVENTORY_PATH
    )
    files.require_file_match(inventory_record, len(inventory_bytes), inventory_digest)
    if inventory_digest != manifest.candidate_inventory_sha256:
        raise contract.CandidateHandoffError(
            "candidate_inventory_sha256 must equal the raw inventory member digest"
        )
    distributions = codec.parse_candidate_inventory(
        inventory_bytes, release=manifest.release, records=records
    )
    distributions_by_path = {item.path: item for item in distributions}
    checksum_record = records[contract.CHECKSUM_PATH]
    checksum_bytes, checksum_digest = files.read_regular(root, contract.CHECKSUM_PATH)
    files.require_file_match(checksum_record, len(checksum_bytes), checksum_digest)
    if checksum_bytes != codec.distribution_checksum_bytes(distributions):
        raise contract.CandidateHandoffError(
            "candidate checksum asset does not match distribution inventory"
        )

    total_bytes = len(manifest_bytes)
    for record in manifest.members:
        if record.path == contract.CANDIDATE_INVENTORY_PATH:
            size, digest = len(inventory_bytes), inventory_digest
        elif record.path.startswith("dist/"):
            data, digest = files.read_regular(root, record.path)
            size = len(data)
            files.verify_archive_metadata(
                data, distributions_by_path[record.path], manifest.release
            )
        else:
            size, digest = files.hash_regular(root, record.path)
        files.require_file_match(record, size, digest)
        total_bytes += size
        if total_bytes > contract.MAX_TOTAL_BYTES:
            raise contract.CandidateHandoffError(
                "candidate artifact exceeds total byte limit"
            )
    return contract.VerifiedCandidate(
        binding=binding,
        manifest=replace(manifest, distributions=distributions),
        total_bytes=total_bytes,
        file_count=len(manifest.members) + 1,
    )


ArtifactBinding = contract.ArtifactBinding
CANDIDATE_INVENTORY_PATH = contract.CANDIDATE_INVENTORY_PATH
CHECKSUM_PATH = contract.CHECKSUM_PATH
CandidateHandoffError = contract.CandidateHandoffError
CandidateManifest = contract.CandidateManifest
DistributionRecord = contract.DistributionRecord
MANIFEST_PATH = contract.MANIFEST_PATH
PROJECTS = contract.PROJECTS
SCHEMA = contract.SCHEMA
SCHEMA_VERSION = contract.SCHEMA_VERSION
SUPPORT_MEMBERS = contract.SUPPORT_MEMBERS
SUPPLEMENTAL_UNSIGNED_MEMBERS = contract.SUPPLEMENTAL_UNSIGNED_MEMBERS
VerifiedCandidate = contract.VerifiedCandidate
ProviderArtifactObservation = provider.ProviderArtifactObservation
Clock = provider.Clock
manifest_canonical_sha256 = codec.manifest_canonical_sha256

__all__ = [
    "ArtifactBinding",
    "CANDIDATE_INVENTORY_PATH",
    "CHECKSUM_PATH",
    "CandidateHandoffError",
    "CandidateManifest",
    "Clock",
    "DistributionRecord",
    "MANIFEST_PATH",
    "PROJECTS",
    "ProviderArtifactObservation",
    "ProviderBoundCandidate",
    "SCHEMA",
    "SCHEMA_VERSION",
    "SUPPORT_MEMBERS",
    "SUPPLEMENTAL_UNSIGNED_MEMBERS",
    "VerifiedCandidate",
    "import_provider_candidate",
    "manifest_canonical_sha256",
    "verify_candidate_artifact",
]
