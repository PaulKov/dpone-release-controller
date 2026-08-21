"""Candidate checksum bytes and immutable outer-selector binding."""

from tools.evidence import release_candidate_contract as contract


def distribution_checksum_bytes(
    records: tuple[contract.DistributionRecord, ...],
) -> bytes:
    """Return the exact GNU-compatible checksum asset for eight archives."""

    if len(records) != 8:
        raise contract.CandidateHandoffError(
            "candidate checksum asset requires eight distributions"
        )
    try:
        return "".join(
            f"{record.sha256.removeprefix('sha256:')}  {record.filename}\n"
            for record in records
        ).encode("ascii")
    except UnicodeEncodeError as exc:
        raise contract.CandidateHandoffError(
            "candidate checksum filenames must be ASCII"
        ) from exc


def require_outer_binding(
    manifest: contract.CandidateManifest,
    binding: contract.ArtifactBinding,
) -> None:
    """Require dispatch selectors to match the independently parsed manifest."""

    mismatches = []
    if manifest.run_id != binding.run_id:
        mismatches.append("run_id")
    if manifest.run_attempt != binding.run_attempt:
        mismatches.append("run_attempt")
    if manifest.release != binding.expected_release:
        mismatches.append("release")
    if manifest.peeled_commit_sha != binding.expected_peeled_commit_sha:
        mismatches.append("peeled_commit_sha")
    if mismatches:
        raise contract.CandidateHandoffError(
            f"outer artifact binding mismatch: {sorted(mismatches)}"
        )
