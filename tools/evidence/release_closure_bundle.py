"""Disabled public closure bundle builder and verifier."""

from tools.evidence.release_public_closure_hold import (
    REASON,
    REASON_CODE,
    STATUS,
    PublicClosureContractHoldError,
    PublicClosureHold,
    contract,
    reject,
)

ClosureBundleError = PublicClosureContractHoldError
ClosureExpectation = PublicClosureHold
build = reject
verify = reject
verify_zip = reject
write_zip = reject
zip_bytes = reject

__all__ = [
    "REASON",
    "REASON_CODE",
    "STATUS",
    "ClosureBundleError",
    "ClosureExpectation",
    "build",
    "contract",
    "verify",
    "verify_zip",
    "write_zip",
    "zip_bytes",
]
