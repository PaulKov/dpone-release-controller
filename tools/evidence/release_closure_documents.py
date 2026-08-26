"""Disabled public closure document projection."""

from tools.evidence.release_public_closure_hold import (
    REASON,
    REASON_CODE,
    STATUS,
    PublicClosureContractHoldError,
    contract,
    reject,
)

build = reject
verify = reject

__all__ = [
    "REASON",
    "REASON_CODE",
    "STATUS",
    "PublicClosureContractHoldError",
    "build",
    "contract",
    "verify",
]
