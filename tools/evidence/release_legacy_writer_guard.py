"""Fail-closed quarantine for the retired pre-broker release graph."""

from __future__ import annotations

from typing import Never


class LegacyReleaseWriterDisabled(RuntimeError):
    """A caller attempted to use the retired direct-write release graph."""


def disabled(component: str) -> Never:
    """Stop before credentials, provider mutation, or evidence-store writes."""

    raise LegacyReleaseWriterDisabled(
        f"{component} is quarantined; use the activation-bound broker v2 protocol"
    )
