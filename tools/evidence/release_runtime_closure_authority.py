"""Disabled public runtime authority verifier."""

from tools.evidence.release_public_closure_hold import (
    REASON,
    REASON_CODE,
    STATUS,
    PublicClosureContractHoldError,
    contract,
    reject,
)

verify_activation = reject
verify_ledger = reject
verify_runtime = reject
verify_runtime_source = reject
verify_target_lineage = reject

__all__ = [
    "REASON",
    "REASON_CODE",
    "STATUS",
    "PublicClosureContractHoldError",
    "contract",
    "verify_activation",
    "verify_ledger",
    "verify_runtime",
    "verify_runtime_source",
    "verify_target_lineage",
]
