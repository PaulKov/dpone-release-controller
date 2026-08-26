"""Single fail-closed boundary for the unfrozen public closure contract.

The private receipt ledger remains an internal controller concern. No public
archive, marker, provider projection, or runtime promotion gate may be built or
verified until a separately reviewed public allowlist and authenticity anchor
are frozen. Callers receive one stable reason code instead of accidentally
falling back to an older raw-ledger projection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Never

STATUS = "HOLD"
REASON_CODE = "PUBLIC_CLOSURE_CONTRACT_NOT_FROZEN"
REASON = (
    "Public closure projection and runtime promotion are disabled until an "
    "approved allowlisted projection and authenticity anchor are frozen."
)
PUBLIC_PROJECTION_ENABLED = False
RUNTIME_GATE_ENABLED = False


class PublicClosureContractHoldError(RuntimeError):
    """A caller attempted to use the intentionally unavailable public contract."""


@dataclass(frozen=True, slots=True)
class PublicClosureHold:
    """Machine-readable state safe to expose in configuration and diagnostics."""

    status: str = STATUS
    reason_code: str = REASON_CODE
    public_projection_enabled: bool = PUBLIC_PROJECTION_ENABLED
    runtime_gate_enabled: bool = RUNTIME_GATE_ENABLED


def contract() -> PublicClosureHold:
    """Return the inert public contract state without exposing private data."""

    return PublicClosureHold()


def reject(*_args: object, **_kwargs: object) -> Never:
    """Fail closed at every former public closure or runtime entrypoint."""

    raise PublicClosureContractHoldError(f"{REASON_CODE}: {REASON}")
