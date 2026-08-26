"""Candidate and attestation admission operation profiles."""

from tools.evidence import release_candidate_stream as candidate_stream
from tools.evidence import release_controller_exchange as exchange
from tools.evidence import release_controller_schema_ids as schema_ids
from tools.evidence.release_controller_operation_contract import (
    LEDGER_TX,
    LOCAL_VERIFY,
    PROVIDER_MUTATION,
    READ,
    OperationProfile,
)
from tools.evidence.release_controller_operation_factory import (
    CANDIDATE_ADMIT_PATH,
    LOCAL_CANDIDATE_VERIFIER,
    once,
)
from tools.evidence.release_controller_route_contract import ATTEST, CANDIDATE, LEDGER

CANDIDATE_IMPORT = OperationProfile(
    operation_id="candidate-import",
    job_name="candidate-import",
    environment="release-attest",
    ordered_calls=(
        once(
            "CANDIDATE_SOURCE_STREAM",
            candidate_stream.METHOD,
            candidate_stream.PATH,
            CANDIDATE,
            candidate_stream.REQUEST_SCHEMA,
            candidate_stream.RESPONSE_SCHEMA,
            READ,
            authority_selectors=("CANDIDATE_SOURCE",),
        ),
        once(
            "CANDIDATE_DEEP_VERIFY",
            "LOCAL",
            LOCAL_CANDIDATE_VERIFIER,
            None,
            candidate_stream.RESPONSE_SCHEMA,
            exchange.CANDIDATE_ADMIT_REQUEST_SCHEMA,
            LOCAL_VERIFY,
        ),
        once(
            "CANDIDATE_ADMIT",
            "POST",
            CANDIDATE_ADMIT_PATH,
            LEDGER,
            exchange.CANDIDATE_ADMIT_REQUEST_SCHEMA,
            exchange.CANDIDATE_ADMIT_RESPONSE_SCHEMA,
            LEDGER_TX,
            exchange.CANDIDATE_RECEIPT_KIND,
            receipt_selectors=("CANDIDATE_HANDOFF",),
            receipt_states=("CANDIDATE_HANDOFF",),
        ),
    ),
    absolute_timeout_seconds=900,
)

ATTEST_CREATE = OperationProfile(
    operation_id="attest-create",
    job_name="attest-create",
    environment="release-attest",
    ordered_calls=(
        once(
            "ATTESTATION_INTENT_ISSUE",
            "POST",
            "/v1/releases/intents/attestation-create/issue",
            ATTEST,
            schema_ids.SELECTOR_REQUEST,
            schema_ids.RECEIPT_PROJECTION,
            LEDGER_TX,
            "MUTATION_INTENT",
            receipt_selectors=("MUTATION_INTENT:ATTESTATION_CREATE",),
            receipt_states=("MUTATION_INTENT_RECORDED",),
        ),
        once(
            "ATTESTATION_INTENT_CONSUME",
            "POST",
            "/v1/releases/intents/attestation-create/consume",
            ATTEST,
            schema_ids.SELECTOR_REQUEST,
            schema_ids.RECEIPT_PROJECTION,
            LEDGER_TX,
            "MUTATION_INTENT_CONSUMED",
            receipt_selectors=("MUTATION_INTENT_CONSUMED:ATTESTATION_CREATE",),
            receipt_states=("MUTATION_INTENT_CONSUMED",),
        ),
        once(
            "ATTESTATION_PROVIDER_CREATE",
            "POST",
            "/v1/releases/attestation/create",
            ATTEST,
            schema_ids.SELECTOR_REQUEST,
            schema_ids.PROVIDER_MUTATION_RESULT,
            PROVIDER_MUTATION,
        ),
    ),
    absolute_timeout_seconds=900,
)
