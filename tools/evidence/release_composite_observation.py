"""Canonical aggregate digest for independent GitHub and PyPI observations."""

from __future__ import annotations

import hashlib

from tools.evidence import release_receipt_contract as contract
from tools.evidence.release_canonical import canonical_json_bytes

SCHEMA = "dpone.release-composite-provider-observation.v1"


def digest(github_sha256: str, pypi_sha256: str) -> str:
    """Bind two independently authenticated provider observations."""

    contract.digest(github_sha256, "github_provider_observation_sha256")
    contract.digest(pypi_sha256, "pypi_provider_observation_sha256")
    raw = canonical_json_bytes(
        {
            "github_provider_observation_sha256": github_sha256,
            "pypi_provider_observation_sha256": pypi_sha256,
            "schema": SCHEMA,
            "schema_version": 1,
        }
    )
    return "sha256:" + hashlib.sha256(raw).hexdigest()
