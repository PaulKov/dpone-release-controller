"""Injected UTC clock and canonical timestamp parsing for candidate reads."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol

from tools.evidence import release_candidate_contract as contract

_TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


class Clock(Protocol):
    """UTC clock injected at the provider authorization boundary."""

    def now(self) -> datetime:
        """Return one timezone-aware UTC instant."""


@dataclass(frozen=True, slots=True)
class SystemUtcClock:
    """Production clock implementation; tests inject a deterministic clock."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


SYSTEM_UTC_CLOCK = SystemUtcClock()


def timestamp(value: str, name: str) -> datetime:
    """Parse exact RFC3339 UTC seconds."""

    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        raise contract.CandidateHandoffError(f"{name} must be canonical UTC seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise contract.CandidateHandoffError(f"{name} is not a real timestamp") from exc


def utc_now(value: datetime) -> datetime:
    """Require and normalize a timezone-aware UTC instant."""

    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise contract.CandidateHandoffError(
            "provider clock must return timezone-aware UTC"
        )
    return value.astimezone(timezone.utc)
