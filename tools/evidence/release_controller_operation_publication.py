"""PyPI and GitHub publication operation profiles and exact file tables."""

from tools.evidence import release_candidate_stream as candidate_stream
from tools.evidence import release_distribution_contract as distribution_contract
from tools.evidence import release_controller_schema_ids as schema_ids
from tools.evidence.release_controller_operation_contract import (
    LEDGER_TX,
    LOCAL_VERIFY,
    PROVIDER_MUTATION,
    READ,
    SERVER_REQUERY_LEDGER_TX,
    ActionCodec,
    OperationProfile,
    PublicationAlternative,
    PublicationFilePlan,
    PublicationPlan,
)
from tools.evidence.release_controller_operation_factory import (
    PYPI_ACTION,
    PYPI_ACTION_REF,
    action_input,
    once,
    selector_codec,
    server_transaction,
)
from tools.evidence.release_controller_route_contract import GITHUB, LEDGER, PYPI
from tools.evidence.release_controller_route_paths import operation_path

FILE_ROWS = tuple(
    sorted(
        distribution_contract.matrix("0.0.0"),
        key=lambda row: row[2].encode("ascii"),
    )
)
PUBLICATION_PLAN = PublicationPlan(
    ordering="BYTEWISE_FILENAME_ASCENDING",
    files=tuple(
        PublicationFilePlan(
            ordinal=index,
            project=project,
            artifact_type=artifact_type,
            inventory_selector=f"candidate.distributions[{index - 1:02d}]",
            prepare_transitions=("PENDING_UPLOAD", "SEALED_FOR_UPLOAD"),
            observe_transition="INTEGRITY_VERIFIED",
            observed_verified_count=index,
        )
        for index, (project, artifact_type, _filename) in enumerate(FILE_ROWS, start=1)
    ),
    prepare_atomic_ledger_batch=True,
    prepare_provider_io_allowed=False,
    upload_intent_selector="MUTATION_INTENT:PYPI_FILE_UPLOAD_SET",
    observe_prefix_selector="PYPI_UPLOAD_SET_OBSERVED",
    complete_state="PYPI_VERIFIED",
    alternatives=(
        PublicationAlternative("COMPLETE", "PYPI_VERIFIED", True, False),
        PublicationAlternative("PARTIAL_EXACT", "RECOVERY_REQUIRED", False, False),
        PublicationAlternative("CONFLICT", "PYPI_CONFLICT", True, False),
        PublicationAlternative("ALREADY_PUBLISHED_EXACT", "PYPI_VERIFIED", True, False),
        PublicationAlternative("AMBIGUOUS", "RECOVERY_REQUIRED", False, False),
    ),
)

PYPI_PREPARE = OperationProfile(
    "pypi-prepare",
    "pypi-prepare",
    "release-attest",
    (
        once(
            "PYPI_PREPARE_AND_SEAL",
            "POST",
            "/v1/releases/pypi/prepare",
            LEDGER,
            schema_ids.SELECTOR_REQUEST,
            schema_ids.RECEIPT_BATCH_PROJECTION,
            LEDGER_TX,
            "MUTATION_INTENT",
            "PYPI_FILE_TRANSITION",
            receipt_selectors=(
                "MUTATION_INTENT:PYPI_FILE_UPLOAD_SET",
                "PYPI_FILE_TRANSITION:PENDING_UPLOAD",
                "PYPI_FILE_TRANSITION:SEALED_FOR_UPLOAD",
            ),
            receipt_states=("MUTATION_INTENT_RECORDED", "PYPI_PUBLISHING"),
        ),
    ),
    900,
    publication_plan=PUBLICATION_PLAN,
)

PYPI_PUBLISH = OperationProfile(
    "pypi-publish",
    "pypi-publish",
    "pypi",
    (
        once(
            "CANDIDATE_REMATERIALIZE_STREAM",
            "POST",
            "/v1/releases/pypi/candidate",
            PYPI,
            schema_ids.SELECTOR_REQUEST,
            candidate_stream.RESPONSE_SCHEMA,
            READ,
        ),
        once(
            "PYPI_EXACT_UPLOAD_SET_VERIFY",
            "LOCAL",
            "local:release-pypi-eight-file-verification",
            None,
            candidate_stream.RESPONSE_SCHEMA,
            schema_ids.PYPI_MATERIALIZATION_PROOF,
            LOCAL_VERIFY,
        ),
        once(
            "PYPI_UPLOAD_INTENT_CONSUME",
            "POST",
            operation_path(
                "MUTATION_INTENT_CONSUMED:PYPI_FILE_UPLOAD_SET",
                "pypi-publish",
            ),
            PYPI,
            schema_ids.PYPI_MATERIALIZATION_PROOF,
            schema_ids.RECEIPT_PROJECTION,
            LEDGER_TX,
            "MUTATION_INTENT_CONSUMED",
            receipt_selectors=("MUTATION_INTENT_CONSUMED:PYPI_FILE_UPLOAD_SET",),
            receipt_states=("MUTATION_INTENT_CONSUMED",),
        ),
        once(
            "PYPI_TRUSTED_PUBLISHER_UPLOAD",
            "ACTION",
            PYPI_ACTION,
            None,
            schema_ids.PYPI_MATERIALIZATION_PROOF,
            schema_ids.EXTERNAL_ACTION_RESULT,
            PROVIDER_MUTATION,
            response_mode="NONE",
        ),
    ),
    3600,
)

_PYPI_OBSERVE_CALL = once(
    "PYPI_PROVIDER_REQUERY_AND_OUTCOME_ADMIT",
    "POST",
    "/v1/releases/pypi/admit",
    LEDGER,
    schema_ids.SELECTOR_REQUEST,
    schema_ids.PYPI_OUTCOME_RESPONSE,
    SERVER_REQUERY_LEDGER_TX,
    "PYPI_FILE_TRANSITION",
    "PYPI_UPLOAD_SET_OBSERVED",
    receipt_selectors=(
        "PYPI_UPLOAD_SET_OBSERVED",
        "PYPI_FILE_TRANSITION:INTEGRITY_VERIFIED",
        "PYPI_FILE_TRANSITION:CONFLICT",
    ),
    receipt_states=(
        "PYPI_UPLOAD_SET_COMPLETE",
        "RECOVERY_REQUIRED",
        "PYPI_PARTIAL_EXACT",
        "PYPI_VERIFIED",
        "PYPI_CONFLICT",
    ),
    server_service_role="pypi_reader",
)

PYPI_OBSERVE = OperationProfile(
    "pypi-observe",
    "pypi-observe",
    "release-attest",
    (_PYPI_OBSERVE_CALL,),
    300,
    publication_plan=PUBLICATION_PLAN,
    server_transactions=(
        server_transaction(_PYPI_OBSERVE_CALL, "PYPI_PROJECT_FILE_REQUERY"),
    ),
)

GITHUB_PUBLISH = OperationProfile(
    "github-publish",
    "github-publish",
    "github-release",
    (
        once(
            "GITHUB_PUBLISH_INTENT_CONSUME",
            "POST",
            "/v1/releases/intents/github-release-publish/consume",
            GITHUB,
            schema_ids.SELECTOR_REQUEST,
            schema_ids.RECEIPT_PROJECTION,
            LEDGER_TX,
            "MUTATION_INTENT_CONSUMED",
            receipt_selectors=("MUTATION_INTENT_CONSUMED:GITHUB_RELEASE_PUBLISH",),
            receipt_states=("MUTATION_INTENT_CONSUMED",),
        ),
        once(
            "GITHUB_RELEASE_PROVIDER_PUBLISH",
            "POST",
            "/v1/releases/github/publish",
            GITHUB,
            schema_ids.SELECTOR_REQUEST,
            schema_ids.PROVIDER_MUTATION_RESULT,
            PROVIDER_MUTATION,
        ),
    ),
    900,
)


def codecs() -> tuple[ActionCodec, ...]:
    """Return exact publication workflow step executors."""

    return (
        selector_codec("pypi-prepare", "pypi-prepare", ("PYPI_PREPARE_AND_SEAL",)),
        selector_codec(
            "pypi-publish",
            "prepare",
            tuple(call.phase for call in PYPI_PUBLISH.ordered_calls[:3]),
        ),
        ActionCodec(
            "pypi-publish",
            "publish",
            ("PYPI_TRUSTED_PUBLISHER_UPLOAD",),
            PYPI_ACTION_REF,
            (
                action_input(
                    "packages-dir",
                    "PACKAGE_DIRECTORY",
                    "WORKFLOW_LITERAL",
                    "release-controller-pypi/dist",
                ),
            ),
            (),
            "NONE",
        ),
        selector_codec(
            "pypi-observe",
            "pypi-observe",
            tuple(call.phase for call in PYPI_OBSERVE.ordered_calls),
        ),
        selector_codec(
            "github-publish",
            "github-publish",
            tuple(call.phase for call in GITHUB_PUBLISH.ordered_calls),
        ),
    )
