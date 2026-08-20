"""Closed schema identifiers shared by operation profiles and codecs.

The path and pinned action select the operation.  Common selector and receipt
schemas therefore describe a deliberately small wire surface without turning
the request body into an operation selector.
"""

SELECTOR_REQUEST = "dpone.release-controller-selector-request.v1"
RECEIPT_PROJECTION = "dpone.release-controller-receipt-projection-response.v1"
RECEIPT_BATCH_PROJECTION = (
    "dpone.release-controller-receipt-batch-projection-response.v1"
)
PROVIDER_MUTATION_RESULT = "dpone.release-controller-provider-mutation-result.v1"
EXTERNAL_ACTION_RESULT = "dpone.release-controller-external-action-result.v1"
DRAFT_ADVANCE_RESPONSE = "dpone.release-controller-draft-advance-response.v1"
LEASE_RENEW_REQUEST = "dpone.release-controller-lease-renew-request.v1"
LEASE_RENEW_RESPONSE = "dpone.release-controller-lease-renew-response.v1"
RECOVERY_DECISION_RESPONSE = "dpone.release-controller-recovery-decision-response.v1"
PYPI_OUTCOME_RESPONSE = "dpone.release-controller-pypi-outcome-response.v1"
CANCELLATION_OUTCOME_RESPONSE = (
    "dpone.release-controller-cancellation-outcome-response.v1"
)
TERMINAL_ASSERT_RESPONSE = "dpone.release-controller-terminal-assert-response.v1"
PYPI_MATERIALIZATION_PROOF = "dpone.release-controller-pypi-materialization-proof.v1"
ERROR_RESPONSE = "dpone.release-controller-error-response.v1"
