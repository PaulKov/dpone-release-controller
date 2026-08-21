"""Disabled public runtime closure contract."""

from tools.evidence.release_public_closure_hold import (
    REASON,
    REASON_CODE,
    STATUS,
    PublicClosureContractHoldError,
    PublicClosureHold,
    contract,
    reject,
)

RuntimeClosureError = PublicClosureContractHoldError
RuntimeInvocation = PublicClosureHold
bounded = reject
constants = reject
digest = reject
exact = reject
git_sha = reject
mapping = reject
nonnegative = reject
positive = reject
safe_name = reject
timestamp = reject
utc = reject

__all__ = [
    "REASON",
    "REASON_CODE",
    "STATUS",
    "RuntimeClosureError",
    "RuntimeInvocation",
    "bounded",
    "constants",
    "contract",
    "digest",
    "exact",
    "git_sha",
    "mapping",
    "nonnegative",
    "positive",
    "safe_name",
    "timestamp",
    "utc",
]
