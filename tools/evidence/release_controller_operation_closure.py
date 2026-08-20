"""Compatibility surface proving public closure operations are on HOLD."""

from tools.evidence.release_public_closure_hold import (
    REASON,
    REASON_CODE,
    STATUS,
    PublicClosureContractHoldError,
    contract,
)

OPERATIONS: tuple[()] = ()


def codecs() -> tuple[()]:
    """Return no executable workflow codecs while the public contract is held."""

    return ()


__all__ = [
    "OPERATIONS",
    "REASON",
    "REASON_CODE",
    "STATUS",
    "PublicClosureContractHoldError",
    "codecs",
    "contract",
]
