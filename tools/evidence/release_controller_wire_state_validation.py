"""Semantic validators shared by the closed controller state codecs."""

from __future__ import annotations

import re
from typing import Any, Mapping

from tools.evidence.release_canonical import MAX_SAFE_INTEGER
from tools.evidence.release_controller_wire_codecs import (
    WireCodecError,
    _digest,
    _positive,
    _selector,
)

TIMESTAMP_PATTERN = (
    "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{3})?Z$"
)
_TIMESTAMP_RE = re.compile(TIMESTAMP_PATTERN, re.ASCII)


def validate_lease_response(value: Mapping[str, Any]) -> None:
    _head(value)
    _digest(value["lease_id"])
    _positive(value["fencing_token"], "fencing_token")
    status = value["status"]
    targets = {
        "ACTIVE": "LEASED_ACTIVE",
        "RELEASED": "TERMINAL",
        "EXPIRED": "RECOVERY_REQUIRED",
        "HOLD": "INCIDENT_HOLD",
        "ABORTED": "ABORTED",
    }
    if status not in targets or value["durable_state"] != targets[status]:
        raise WireCodecError("lease sentinel status/state mismatch")
    renewal = value["renewal"]
    if status != "ACTIVE":
        if renewal is not None:
            raise WireCodecError("terminal lease response fabricates a renewal")
        return
    _exact(renewal, {"expires_at", "receipt_id", "receipt_sha256", "sequence"})
    _digest(renewal["receipt_id"])
    _digest(renewal["receipt_sha256"])
    _timestamp(renewal["expires_at"], "renewal.expires_at")
    _nonnegative(renewal["sequence"], "renewal.sequence")
    if (
        renewal["receipt_id"] != value["head_receipt_id"]
        or renewal["receipt_sha256"] != value["head_receipt_sha256"]
        or renewal["sequence"] != value["head_sequence"]
    ):
        raise WireCodecError("active renewal/head projection mismatch")


def validate_recovery_response(value: Mapping[str, Any]) -> None:
    _head(value)
    for key in (
        "batch_sha256",
        "first_receipt_id",
        "first_receipt_sha256",
        "lease_id",
        "attempt_id",
    ):
        _digest(value[key])
    _positive(value["fencing_token"], "fencing_token")
    _nonnegative(value["first_sequence"], "first_sequence")
    if (
        value["append_count"] != 2
        or value["head_sequence"] != value["first_sequence"] + 1
    ):
        raise WireCodecError("recovery decision batch is not exact two-receipt append")
    classification = value["classification"]
    if classification == "RESUME_ORIGINAL_CANDIDATE":
        resume = value["resume_phase"]
        state_by_resume = {
            "LEASED_RESTART": "LEASED",
            "PYPI_RECOVERY": "PYPI_RECOVERY",
            "PYPI_VERIFIED": "PYPI_VERIFIED",
        }
        if resume not in state_by_resume:
            raise WireCodecError("recovery resume phase is invalid")
        expected = ("RECOVERY_RESUMED", state_by_resume[resume], "CONTINUE")
    elif classification == "CLOSE_EXACT":
        if value["resume_phase"] != "GITHUB_IMMUTABLE":
            raise WireCodecError("closed-exact recovery resume hint is invalid")
        expected = ("RECOVERY_CLOSED_EXACT", "GITHUB_IMMUTABLE", "CONTINUE")
    elif classification == "INCIDENT_HOLD":
        if value["resume_phase"] is not None:
            raise WireCodecError("incident hold must not expose a resume phase")
        expected = ("INCIDENT_HOLD", "INCIDENT_HOLD", "HOLD")
    else:
        raise WireCodecError("recovery classification is not closed")
    derived, state, outcome = expected
    if (
        value["appended_selectors"] != ["RECOVERY_OBSERVATION", derived]
        or value["resulting_state"] != state
        or value["workflow_outcome"] != outcome
    ):
        raise WireCodecError("recovery decision/result binding mismatch")


def validate_pypi_response(value: Mapping[str, Any]) -> None:
    _head(value)
    for key in ("batch_sha256", "first_receipt_id", "first_receipt_sha256"):
        _digest(value[key])
    _nonnegative(value["first_sequence"], "first_sequence")
    _nonnegative(value["verified_file_count"], "verified_file_count", maximum=8)
    selectors = value["appended_selectors"]
    if not isinstance(selectors, list) or not selectors:
        raise WireCodecError("PyPI appended selector sequence is empty")
    if value["append_count"] != len(selectors) or value["head_sequence"] != (
        value["first_sequence"] + value["append_count"] - 1
    ):
        raise WireCodecError("PyPI outcome batch multiplicity mismatch")
    classification = value["classification"]
    if classification == "COMPLETE":
        expected = ["PYPI_UPLOAD_SET_OBSERVED"] + [
            "PYPI_FILE_TRANSITION:INTEGRITY_VERIFIED"
        ] * 8
        valid = (
            value["verified_file_count"] == 8
            and value["resulting_state"] == "PYPI_VERIFIED"
        )
    elif classification in {"PARTIAL_EXACT", "AMBIGUOUS"}:
        expected = ["PYPI_UPLOAD_SET_OBSERVED"]
        valid = (
            value["verified_file_count"] == 0
            and value["resulting_state"] == "RECOVERY_REQUIRED"
        )
    elif classification == "CONFLICT":
        expected = ["PYPI_UPLOAD_SET_OBSERVED", "PYPI_FILE_TRANSITION:CONFLICT"]
        valid = (
            value["verified_file_count"] == 0
            and value["resulting_state"] == "RECOVERY_REQUIRED"
        )
    elif classification == "ALREADY_PUBLISHED_EXACT":
        expected = ["PYPI_FILE_TRANSITION:ALREADY_PUBLISHED_EXACT"]
        count = value["verified_file_count"]
        valid = 1 <= count <= 8 and value["resulting_state"] == (
            "PYPI_VERIFIED" if count == 8 else "PYPI_RECOVERY"
        )
    else:
        raise WireCodecError("PyPI classification is not closed")
    if selectors != expected or not valid:
        raise WireCodecError("PyPI outcome classification/result mismatch")


def validate_cancellation_response(value: Mapping[str, Any]) -> None:
    _head(value)
    for key in ("batch_sha256", "first_receipt_id", "first_receipt_sha256"):
        _digest(value[key])
    _nonnegative(value["first_sequence"], "first_sequence")
    if (
        value["append_count"] != 2
        or value["head_sequence"] != value["first_sequence"] + 1
    ):
        raise WireCodecError("cancellation batch multiplicity mismatch")
    external = value["external_commit_observed"]
    if not isinstance(external, bool):
        raise WireCodecError("cancellation observation flag is invalid")
    reason = "RECOVERY_REQUIRED" if external else "CANCELLED"
    state = "RECOVERY_REQUIRED" if external else "ABORTED"
    recovery_id = value["recovery_id"]
    if external:
        _digest(recovery_id)
    elif recovery_id is not None:
        raise WireCodecError("clean cancellation must not carry recovery authority")
    if (
        value["appended_selectors"] != ["CANCELLATION", f"LEASE_RELEASED:{reason}"]
        or value["resulting_state"] != state
    ):
        raise WireCodecError("cancellation outcome binding mismatch")


def validate_terminal_response(value: Mapping[str, Any]) -> None:
    _head(value)
    mapping = {
        "TERMINAL": ("SUCCESS", "RELEASED"),
        "ABORTED": ("FAIL", "ABORTED"),
        "INCIDENT_HOLD": ("FAIL", "HOLD"),
        "RECOVERY_REQUIRED": ("FAIL", "EXPIRED"),
        "ACTIVE": ("FAIL", "ACTIVE"),
    }
    expected = mapping.get(value["durable_state"])
    if (
        expected is None
        or (value["action_outcome"], value["sentinel_status"]) != expected
    ):
        raise WireCodecError("terminal assertion status mismatch")


def _head(value: Mapping[str, Any]) -> None:
    _selector(value)
    _digest(value["head_receipt_id"])
    _digest(value["head_receipt_sha256"])
    _nonnegative(value["head_sequence"], "head_sequence")


def _exact(value: Any, keys: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        raise WireCodecError("nested wire object keys are not exact")


def _timestamp(value: Any, name: str) -> None:
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        raise WireCodecError(f"{name} is not a canonical timestamp")


def _nonnegative(value: Any, name: str, *, maximum: int = MAX_SAFE_INTEGER) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        raise WireCodecError(f"{name} is not a bounded nonnegative integer")
