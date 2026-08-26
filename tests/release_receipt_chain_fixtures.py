"""Public facade for deterministic receipt-v2 stream fixtures."""

from tests.release_receipt_chain_builder_fixtures import append_receipt
from tests.release_receipt_chain_happy_fixtures import successful_chain
from tests.release_receipt_chain_scenario_fixtures import (
    gate_decision_chain,
    gate_retry_chain,
    long_hold_reacquire_chain,
    no_external_retry_chain,
    partial_pypi_recovery_chain,
    published_github_recovery_chain,
    stale_intent_recovery_chain,
    terminal_no_external_retry_chain,
    terminal_partial_pypi_recovery_chain,
    terminal_published_github_recovery_chain,
    terminal_stale_intent_recovery_chain,
)

# Temporary compatibility for tests that deliberately construct invalid stream
# edges. New fixtures should use append_receipt explicitly.
_append = append_receipt

__all__ = [
    "append_receipt",
    "gate_decision_chain",
    "gate_retry_chain",
    "long_hold_reacquire_chain",
    "no_external_retry_chain",
    "partial_pypi_recovery_chain",
    "published_github_recovery_chain",
    "stale_intent_recovery_chain",
    "successful_chain",
    "terminal_no_external_retry_chain",
    "terminal_partial_pypi_recovery_chain",
    "terminal_published_github_recovery_chain",
    "terminal_stale_intent_recovery_chain",
]
