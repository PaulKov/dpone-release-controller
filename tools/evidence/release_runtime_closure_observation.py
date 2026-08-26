"""Disabled public runtime provider-observation verifier."""

from tools.evidence.release_public_closure_hold import (
    REASON,
    REASON_CODE,
    STATUS,
    PublicClosureContractHoldError,
    contract,
    reject,
)

verify_observation = reject

__all__ = [
    "REASON",
    "REASON_CODE",
    "STATUS",
    "PublicClosureContractHoldError",
    "contract",
    "verify_observation",
]
