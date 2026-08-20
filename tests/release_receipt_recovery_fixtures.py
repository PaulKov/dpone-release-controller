"""Recovery payload fixtures for receipt v2."""

from __future__ import annotations

from typing import Any

from tests import release_receipt_fixtures as base

from tests.release_receipt_fixtures import (
    RECOVERY_ATTEMPT_ID,
    AUTHORIZATION_ID,
    CANDIDATE_ID,
    RECOVERY_ID,
    digest,
)
from tools.evidence import release_receipt_inventory as inventory
from tools.evidence import release_composite_observation as composite_observation


def recovery(*, file_count: int = 4, github_state: str = "DRAFT") -> dict[str, Any]:
    files = base._distributions()[:file_count]
    github: dict[str, Any] = {
        "state": github_state,
        "provider_observation_sha256": digest(f"recovery GitHub {github_state}"),
    }
    if github_state != "NONE":
        github.update(
            release_id=5_000_000_001,
            release_body_sha256=digest("body"),
            asset_inventory_sha256=inventory.inventory_sha256(
                inventory.GITHUB_ASSET_SCHEMA, base._release_assets()
            ),
            asset_count=17,
            draft=github_state == "DRAFT",
            immutable=github_state == "PUBLISHED",
        )
    action = (
        "CLOSE_EXACT"
        if file_count == 8 and github_state == "PUBLISHED"
        else "RESUME_ORIGINAL_CANDIDATE"
    )
    pypi_observation = digest(f"recovery PyPI/{file_count}")
    payload = {
        "kind": "RECOVERY_OBSERVATION",
        "state": "RECOVERY_RECONCILED",
        "recovery_id": RECOVERY_ID,
        "candidate_id": CANDIDATE_ID,
        "attempt_id": RECOVERY_ATTEMPT_ID,
        "observation_sha256": composite_observation.digest(
            github["provider_observation_sha256"], pypi_observation
        ),
        "github_provider_observation_sha256": github["provider_observation_sha256"],
        "github_provider_api_version": "2026-03-10",
        "pypi_provider_observation_sha256": pypi_observation,
        "pypi_provider_api_version": "pypi-integrity-v1",
        "observed_at": "2026-08-15T00:06:03Z",
        "pypi_exact_file_count": file_count,
        "pypi_exact_file_inventory": files,
        "pypi_exact_file_inventory_sha256": inventory.inventory_sha256(
            inventory.DISTRIBUTION_SCHEMA, files
        ),
        "github_release": github,
        "next_action": action,
    }
    if file_count > 0 or github_state != "NONE":
        payload["authorization_id"] = AUTHORIZATION_ID
    return payload


def recovery_resumed(*, file_count: int = 4) -> dict[str, Any]:
    payload = {
        "kind": "RECOVERY_RESUMED",
        "state": "RECOVERY_RESUMED",
        "recovery_id": RECOVERY_ID,
        "candidate_id": CANDIDATE_ID,
        "attempt_id": RECOVERY_ATTEMPT_ID,
        "observation_receipt_id": digest("recovery observation receipt"),
        "observation_sha256": recovery(
            file_count=file_count,
            github_state="NONE" if file_count == 0 else "DRAFT",
        )["observation_sha256"],
        "resume_phase": (
            "LEASED_RESTART"
            if file_count == 0
            else "PYPI_VERIFIED"
            if file_count == 8
            else "PYPI_RECOVERY"
        ),
        "resumed_at": "2026-08-15T00:06:05Z",
    }
    if file_count > 0:
        payload["authorization_id"] = AUTHORIZATION_ID
    return payload


def recovery_closed_exact() -> dict[str, Any]:
    return {
        "kind": "RECOVERY_CLOSED_EXACT",
        "state": "RECOVERY_CLOSED_EXACT",
        "recovery_id": RECOVERY_ID,
        "candidate_id": CANDIDATE_ID,
        "authorization_id": AUTHORIZATION_ID,
        "attempt_id": RECOVERY_ATTEMPT_ID,
        "observation_receipt_id": digest("recovery observation receipt"),
        "observation_sha256": recovery(file_count=8, github_state="PUBLISHED")[
            "observation_sha256"
        ],
        "pypi_inventory_sha256": inventory.inventory_sha256(
            inventory.DISTRIBUTION_SCHEMA, base._distributions()
        ),
        "github_release_inventory_sha256": inventory.inventory_sha256(
            inventory.GITHUB_ASSET_SCHEMA, base._release_assets()
        ),
        "release_id": 5_000_000_001,
        "closed_exact_at": "2026-08-15T00:06:05Z",
    }


def hold() -> dict[str, Any]:
    return {
        "kind": "INCIDENT_HOLD",
        "state": "INCIDENT_HOLD",
        "hold_id": digest("hold"),
        "recovery_id": RECOVERY_ID,
        "reason_code": "PYPI_CONFLICT",
        "incident_record_sha256": digest("incident"),
        "provider_actor_id": 1001,
        "started_at": "2026-08-15T00:20:00Z",
        "retention_floor_days": 2_557,
    }


def hold_released() -> dict[str, Any]:
    return {
        "kind": "INCIDENT_HOLD_RELEASED",
        "state": "RECOVERY_REQUIRED",
        "hold_id": digest("hold"),
        "recovery_id": RECOVERY_ID,
        "release_record_sha256": digest("release hold approval"),
        "provider_actor_id": 1001,
        "released_at": "2026-08-15T00:30:00Z",
        "next_state": "RECOVERY_REQUIRED",
    }
