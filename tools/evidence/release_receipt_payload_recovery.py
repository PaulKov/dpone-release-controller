"""Closed cancellation, recovery, incident-hold, and final closure payloads."""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_inventory as inventory
from tools.evidence import release_composite_observation as composite_observation
from tools.evidence import release_receipt_payload_recovery_terminal as terminal

_SERVICE = frozenset({"trusted_controller_service"})
_CANCELLATION_REASONS = {
    "GOVERNANCE_DRIFT",
    "LEASE_LOST",
    "PROCESS_LOSS",
    "PROVIDER_ERROR",
    "SUPERSEDED",
    "USER_REQUESTED",
}


def validate_cancellation(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    external = contract.boolean(
        payload.get("external_commit_observed"), "external_commit_observed"
    )
    expected_keys = {
        "kind",
        "state",
        "cancellation_id",
        "reason_code",
        "external_commit_observed",
        "cancelled_at",
        "github_provider_observation_sha256",
        "github_provider_api_version",
        "pypi_provider_observation_sha256",
        "pypi_provider_api_version",
        "provider_observation_sha256",
        "external_commit_provider",
    }
    if external:
        expected_keys.add("recovery_id")
    contract.exact_keys(payload, expected_keys, "CANCELLATION payload")
    _constant(payload, "kind", "CANCELLATION")
    contract.digest(payload["cancellation_id"], "cancellation_id")
    contract.digest_fields(
        payload,
        "github_provider_observation_sha256",
        "pypi_provider_observation_sha256",
        "provider_observation_sha256",
    )
    if (
        payload["github_provider_api_version"] != contract.GITHUB_API_VERSION
        or payload["pypi_provider_api_version"] != "pypi-integrity-v1"
        or payload["provider_observation_sha256"]
        != composite_observation.digest(
            payload["github_provider_observation_sha256"],
            payload["pypi_provider_observation_sha256"],
        )
    ):
        raise contract.ReceiptValidationError("cancellation provider evidence mismatch")
    external_provider = contract.enum(
        payload["external_commit_provider"],
        {"BOTH", "GITHUB", "NONE", "PYPI"},
        "external_commit_provider",
    )
    if external != (external_provider != "NONE"):
        raise contract.ReceiptValidationError("cancellation external provider mismatch")
    contract.enum(payload["reason_code"], _CANCELLATION_REASONS, "reason_code")
    contract.timestamp(payload["cancelled_at"], "cancelled_at")
    if external:
        _constant(payload, "state", "RECOVERY_REQUIRED")
        contract.digest(payload["recovery_id"], "recovery_id")
        scope = "recovery"
    else:
        _constant(payload, "state", "CANCELLED")
        scope = "release"
    return contract.PayloadSemantics(scope, True, _SERVICE)


def validate_recovery(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    count = contract.bounded_int(
        payload.get("pypi_exact_file_count"), 0, 8, "pypi_exact_file_count"
    )
    github_state = _github_release(payload.get("github_release"))
    authority_keys = (
        {"authorization_id"} if count > 0 or github_state != "NONE" else set()
    )
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "recovery_id",
            "candidate_id",
            "attempt_id",
            "observation_sha256",
            "github_provider_observation_sha256",
            "github_provider_api_version",
            "pypi_provider_observation_sha256",
            "pypi_provider_api_version",
            "observed_at",
            "pypi_exact_file_count",
            "pypi_exact_file_inventory",
            "pypi_exact_file_inventory_sha256",
            "github_release",
            "next_action",
            *authority_keys,
        },
        "RECOVERY_OBSERVATION payload",
    )
    _constant(payload, "kind", "RECOVERY_OBSERVATION")
    _constant(payload, "state", "RECOVERY_RECONCILED")
    digest_keys = [
        "recovery_id",
        "candidate_id",
        "attempt_id",
        "observation_sha256",
        "pypi_exact_file_inventory_sha256",
    ]
    if authority_keys:
        digest_keys.append("authorization_id")
    contract.digest_fields(
        payload,
        *digest_keys,
    )
    contract.digest_fields(
        payload,
        "github_provider_observation_sha256",
        "pypi_provider_observation_sha256",
    )
    if (
        payload["github_provider_api_version"] != contract.GITHUB_API_VERSION
        or payload["pypi_provider_api_version"] != "pypi-integrity-v1"
        or payload["github_provider_observation_sha256"]
        != payload["github_release"]["provider_observation_sha256"]
        or payload["observation_sha256"]
        != composite_observation.digest(
            payload["github_provider_observation_sha256"],
            payload["pypi_provider_observation_sha256"],
        )
    ):
        raise contract.ReceiptValidationError("recovery provider evidence mismatch")
    contract.timestamp(payload["observed_at"], "observed_at")
    files = inventory.distribution_subset_inventory(
        payload["pypi_exact_file_inventory"]
    )
    if len(files) != count:
        raise contract.ReceiptValidationError("recovery PyPI file count mismatch")
    inventory.require_digest(
        payload["pypi_exact_file_inventory_sha256"],
        inventory.DISTRIBUTION_SCHEMA,
        files,
        "pypi_exact_file_inventory_sha256",
    )
    action = contract.enum(
        payload["next_action"],
        {
            "CLOSE_EXACT",
            "INCIDENT_HOLD",
            "RESUME_ORIGINAL_CANDIDATE",
        },
        "next_action",
    )
    if action == "CLOSE_EXACT" and (count != 8 or github_state != "PUBLISHED"):
        raise contract.ReceiptValidationError("recovery is not exact enough to close")
    if action == "RESUME_ORIGINAL_CANDIDATE" and not (
        github_state == "DRAFT" or (github_state == "NONE" and count == 0)
    ):
        raise contract.ReceiptValidationError("recovery resume requires exact draft")
    return contract.PayloadSemantics("recovery", True, _SERVICE)


def validate_resumed(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Validate the explicit edge back into the original publication graph."""

    resume_phase = contract.enum(
        payload.get("resume_phase"),
        {"LEASED_RESTART", "PYPI_RECOVERY", "PYPI_VERIFIED"},
        "resume_phase",
    )
    authority_keys = set() if resume_phase == "LEASED_RESTART" else {"authorization_id"}
    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "recovery_id",
            "candidate_id",
            "attempt_id",
            "observation_receipt_id",
            "observation_sha256",
            "resume_phase",
            "resumed_at",
            *authority_keys,
        },
        "RECOVERY_RESUMED payload",
    )
    _constant(payload, "kind", "RECOVERY_RESUMED")
    _constant(payload, "state", "RECOVERY_RESUMED")
    digest_keys = [
        "recovery_id",
        "candidate_id",
        "attempt_id",
        "observation_receipt_id",
        "observation_sha256",
    ]
    if authority_keys:
        digest_keys.append("authorization_id")
    contract.digest_fields(
        payload,
        *digest_keys,
    )
    contract.timestamp(payload["resumed_at"], "resumed_at")
    return contract.PayloadSemantics("recovery", True, _SERVICE)


def validate_closed_exact(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Validate a provider-exact published release before Governance C/CLOSED."""

    contract.exact_keys(
        payload,
        {
            "kind",
            "state",
            "recovery_id",
            "candidate_id",
            "authorization_id",
            "attempt_id",
            "observation_receipt_id",
            "observation_sha256",
            "pypi_inventory_sha256",
            "github_release_inventory_sha256",
            "release_id",
            "closed_exact_at",
        },
        "RECOVERY_CLOSED_EXACT payload",
    )
    _constant(payload, "kind", "RECOVERY_CLOSED_EXACT")
    _constant(payload, "state", "RECOVERY_CLOSED_EXACT")
    contract.digest_fields(
        payload,
        "recovery_id",
        "candidate_id",
        "authorization_id",
        "attempt_id",
        "observation_receipt_id",
        "observation_sha256",
        "pypi_inventory_sha256",
        "github_release_inventory_sha256",
    )
    contract.positive_int(payload["release_id"], "release_id")
    contract.timestamp(payload["closed_exact_at"], "closed_exact_at")
    return contract.PayloadSemantics("recovery", True, _SERVICE)


def _github_release(value: Any) -> str:
    release = contract.mapping(value, "github_release")
    state = contract.enum(
        release.get("state"), {"NONE", "DRAFT", "PUBLISHED"}, "github_release.state"
    )
    if state == "NONE":
        contract.exact_keys(
            release, {"state", "provider_observation_sha256"}, "github_release"
        )
    else:
        contract.exact_keys(
            release,
            {
                "state",
                "release_id",
                "release_body_sha256",
                "asset_inventory_sha256",
                "asset_count",
                "draft",
                "immutable",
                "provider_observation_sha256",
            },
            "github_release",
        )
        contract.positive_fields(release, "release_id", "asset_count")
        contract.digest_fields(
            release,
            "release_body_sha256",
            "asset_inventory_sha256",
            "provider_observation_sha256",
        )
        expected = (state == "DRAFT", state == "PUBLISHED")
        if (
            contract.boolean(release["draft"], "github_release.draft"),
            contract.boolean(release["immutable"], "github_release.immutable"),
        ) != expected:
            raise contract.ReceiptValidationError("recovery GitHub state mismatch")
    contract.digest(
        release["provider_observation_sha256"],
        "github_release.provider_observation_sha256",
    )
    return state


def validate_hold(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Validate durable hold through the stable recovery facade."""

    return terminal.validate_hold(payload)


def validate_hold_released(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Validate hold release through the stable recovery facade."""

    return terminal.validate_hold_released(payload)


def validate_closed(payload: Mapping[str, Any]) -> contract.PayloadSemantics:
    """Validate CLOSED through the stable recovery facade."""

    return terminal.validate_closed(payload)


def _constant(payload: Mapping[str, Any], key: str, expected: Any) -> None:
    if payload[key] != expected or type(payload[key]) is not type(expected):
        raise contract.ReceiptValidationError(f"{key} must be exactly {expected!r}")
