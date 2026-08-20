"""Disabled public CLOSED marker boundary.

No public marker schema is frozen. The historical marker remains private to
the receipt ledger and is intentionally unavailable through this module.
"""

from tools.evidence.release_public_closure_hold import (
    REASON,
    REASON_CODE,
    STATUS,
    PublicClosureContractHoldError,
    contract,
    reject,
)

build = reject
decode_summary = reject
encode = reject
sha256 = reject
summary = reject
verify = reject

__all__ = [
    "REASON",
    "REASON_CODE",
    "STATUS",
    "PublicClosureContractHoldError",
    "build",
    "contract",
    "decode_summary",
    "encode",
    "sha256",
    "summary",
    "verify",
]
