"""Shared closed primitives for release receipt envelope v2.

The broker is the sole committer.  Requesters may supply observations, but
cannot choose stream ordering, commit timestamps, or broker identity fields.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

SCHEMA = "dpone.release-receipt-envelope.v2"
SCHEMA_VERSION = 2
PAYLOAD_DOMAIN = "dpone.release.payload.v2"
RECEIPT_DOMAIN = "dpone.release.receipt.v2"
GENESIS = "GENESIS"
CONTROLLER_REPOSITORY_ID = 1_305_993_853
CONTROLLER_WORKFLOW_PATH = ".github/workflows/release-controller.yml"
CONTROLLER_REPOSITORY = "PaulKov/dpone-release-controller"
TARGET_REPOSITORY = "PaulKov/dpone"
MAX_PENDING_ATTEMPTS = 32
LEASE_TTL_SECONDS = 300
LEASE_RENEW_INTERVAL_SECONDS = 45
CAPABILITY_TTL_SECONDS = 60
WORM_RETENTION_DAYS = 2_557
MAX_SAFE_INTEGER = 9_007_199_254_740_991
GITHUB_API_VERSION = "2026-03-10"
PROJECTS = (
    "apache-airflow-providers-dpone",
    "dpone",
    "dpone-airflow-pack",
    "dpone-native-accel",
)
HISTORICAL_EVENT_TIMESTAMP_FIELDS = frozenset(
    {
        "acquired_at",
        "authority_guard_accepted_at",
        "authority_guard_observed_at",
        "ambiguity_observed_at",
        "approved_at",
        "cancelled_at",
        "candidate_artifact_created_at",
        "closed_exact_at",
        "completed_at",
        "consumed_at",
        "expired_at",
        "observed_at",
        "reconciled_at",
        "rejected_at",
        "released_at",
        "renewed_at",
        "requested_at",
        "resumed_at",
        "started_at",
    }
)
FUTURE_EVENT_TIMESTAMP_FIELDS = frozenset(
    {
        "authority_guard_expires_at",
        "candidate_artifact_expires_at",
        "candidate_artifact_source_url_expires_at",
        "expires_at",
        "previous_expires_at",
    }
)

PRE_LEASE_KINDS = frozenset({"REQUEST_ENQUEUED", "CANDIDATE_HANDOFF"})
PAYLOAD_KINDS = frozenset(
    {
        "REQUEST_ENQUEUED",
        "GOVERNANCE_SNAPSHOT",
        "CANDIDATE_HANDOFF",
        "LEASE_ACQUIRED",
        "LEASE_RENEWED",
        "LEASE_RELEASED",
        "LEASE_EXPIRED",
        "TENANT_HYGIENE_VERIFIED",
        "MUTATION_INTENT",
        "MUTATION_INTENT_CONSUMED",
        "ATTESTATION_VERIFIED",
        "PUBLIC_BUNDLE_VERIFIED",
        "DRAFT_TRANSITION",
        "AUTHORIZED",
        "PYPI_FILE_TRANSITION",
        "PYPI_UPLOAD_SET_OBSERVED",
        "PYPI_GATE_REQUESTED",
        "PYPI_GATE_APPROVED",
        "PYPI_GATE_REJECTED",
        "PYPI_GATE_CALLBACK_AMBIGUOUS",
        "PYPI_GATE_RECONCILED",
        "GITHUB_RELEASE_TRANSITION",
        "CANCELLATION",
        "RECOVERY_OBSERVATION",
        "RECOVERY_RESUMED",
        "RECOVERY_CLOSED_EXACT",
        "INCIDENT_HOLD",
        "INCIDENT_HOLD_RELEASED",
        "CLOSED",
    }
)

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GIT_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
_PATH_RE = re.compile(r"[A-Za-z0-9._/-]{1,240}\Z", re.ASCII)
_OPAQUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}\Z", re.ASCII)
_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z", re.ASCII)
_TAG_RE = re.compile(
    r"v(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\Z"
)
_VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\Z"
)
_FILENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,239}\Z", re.ASCII)
_TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


class ReceiptValidationError(ValueError):
    """A receipt violates the closed byte or semantic contract."""


@dataclass(frozen=True, slots=True)
class PayloadSemantics:
    """Envelope constraints selected by one validated payload variant."""

    scope_kind: str
    lease_required: bool
    allowed_producers: frozenset[str] = frozenset({"github_actions_job"})


def mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ReceiptValidationError(f"{name} must be an object")
    return value


def exact_keys(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ReceiptValidationError(
            f"{name} keys mismatch: missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )


def string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReceiptValidationError(f"{name} must be a non-empty string")
    return value


def enum(value: Any, allowed: set[str] | frozenset[str], name: str) -> str:
    selected = string(value, name)
    if selected not in allowed:
        raise ReceiptValidationError(f"{name} is outside the closed enum")
    return selected


def boolean(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise ReceiptValidationError(f"{name} must be a boolean")
    return value


def positive_int(value: Any, name: str) -> int:
    if type(value) is not int or not 0 < value <= MAX_SAFE_INTEGER:
        raise ReceiptValidationError(f"{name} must be a positive integer")
    return value


def nonnegative_int(value: Any, name: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise ReceiptValidationError(f"{name} must be a non-negative integer")
    return value


def bounded_int(value: Any, minimum: int, maximum: int, name: str) -> int:
    if type(value) is not int or not minimum <= value <= min(maximum, MAX_SAFE_INTEGER):
        raise ReceiptValidationError(
            f"{name} must be an integer in [{minimum}, {maximum}]"
        )
    return value


def digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ReceiptValidationError(f"{name} must be a tagged SHA-256 digest")
    return value


def git_sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or _GIT_SHA_RE.fullmatch(value) is None:
        raise ReceiptValidationError(f"{name} must be a full lowercase Git SHA")
    return value


def safe_path(value: Any, name: str) -> str:
    path = string(value, name)
    if (
        _PATH_RE.fullmatch(path) is None
        or path.startswith("/")
        or "//" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise ReceiptValidationError(f"{name} must be a canonical relative path")
    return path


def opaque(value: Any, name: str) -> str:
    if not isinstance(value, str) or _OPAQUE_RE.fullmatch(value) is None:
        raise ReceiptValidationError(f"{name} must be a safe opaque identifier")
    return value


def request_id(value: Any, name: str = "request_id") -> str:
    if not isinstance(value, str) or _REQUEST_ID_RE.fullmatch(value) is None:
        raise ReceiptValidationError(f"{name} must be a safe request identifier")
    return value


def stable_tag(value: Any, name: str = "tag") -> str:
    if not isinstance(value, str) or _TAG_RE.fullmatch(value) is None:
        raise ReceiptValidationError(f"{name} must be canonical stable SemVer")
    return value


def stable_version(value: Any, name: str = "version") -> str:
    if not isinstance(value, str) or _VERSION_RE.fullmatch(value) is None:
        raise ReceiptValidationError(f"{name} must be canonical stable version")
    return value


def filename(value: Any, name: str = "filename") -> str:
    if not isinstance(value, str) or _FILENAME_RE.fullmatch(value) is None:
        raise ReceiptValidationError(f"{name} must be a canonical basename")
    return value


def timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        raise ReceiptValidationError(f"{name} must be canonical UTC seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ReceiptValidationError(f"{name} must be a real timestamp") from exc


def ordered_timestamps(
    earlier: Any,
    later: Any,
    earlier_name: str,
    later_name: str,
    *,
    exact_delta: timedelta | None = None,
) -> None:
    start = timestamp(earlier, earlier_name)
    end = timestamp(later, later_name)
    if end < start or (exact_delta is not None and end - start != exact_delta):
        raise ReceiptValidationError(f"{earlier_name}/{later_name} ordering mismatch")


def require_historical_event_timestamps(
    payload: Mapping[str, Any], timestamps: Mapping[str, Any]
) -> None:
    """Reject a receipt committed before any historical event it claims."""

    observed = timestamp(timestamps["observed_at"], "timestamps.observed_at")
    committed = timestamp(timestamps["committed_at"], "timestamps.committed_at")
    for key in sorted(HISTORICAL_EVENT_TIMESTAMP_FIELDS & set(payload)):
        event = timestamp(payload[key], key)
        if event > observed or event > committed:
            raise ReceiptValidationError(
                f"historical event timestamp {key} follows receipt"
            )


def empty_list(value: Any, name: str) -> None:
    if not isinstance(value, list) or value:
        raise ReceiptValidationError(f"{name} must be an exact empty array")


def digest_fields(value: Mapping[str, Any], *names: str) -> None:
    for name in names:
        digest(value[name], name)


def positive_fields(value: Mapping[str, Any], *names: str) -> None:
    for name in names:
        positive_int(value[name], name)
