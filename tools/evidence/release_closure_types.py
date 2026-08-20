"""Public types for the intentionally disabled closure contract."""

from tools.evidence.release_public_closure_hold import (
    PublicClosureContractHoldError,
    PublicClosureHold,
)

ClosureBundleError = PublicClosureContractHoldError
ClosureExpectation = PublicClosureHold

__all__ = ["ClosureBundleError", "ClosureExpectation"]
