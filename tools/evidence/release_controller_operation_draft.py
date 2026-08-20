"""Executable durable GitHub draft state machine and recovery table."""

from tools.evidence import release_candidate_stream as candidate_stream
from tools.evidence import release_controller_schema_ids as schema_ids
from tools.evidence.release_controller_operation_contract import (
    DURABLE_STATE_MACHINE,
    DurableCandidateSource,
    DurableCycle,
    DurableRecoveryBranch,
    DurableStateMachine,
    DurableTerminalVerification,
    OperationProfile,
    OrderedCall,
)
from tools.evidence.release_controller_route_contract import GITHUB

_CYCLE_SUBSTEPS = (
    "EXPECTED_SUBJECT_BINDING_DERIVE",
    "INTERNAL_PINNED_CANDIDATE_SOURCE_STREAM",
    "SAFE_EXACT_MEMBER_EXTRACTION",
    "EXPECTED_SUBJECT_BYTES_VERIFY",
    "INTENT_DURABLE_COMMIT",
    "CAPABILITY_DURABLE_CONSUME",
    "ISOLATED_PROVIDER_EFFECT",
    "READ_ONLY_PROVIDER_REQUERY",
    "PROVIDER_RESULT_CLASSIFY",
    "OUTCOME_DURABLE_COMMIT",
    "NEXT_CYCLE_GATE",
)


def _cycle(
    ordinal: int,
    cycle_id: str,
    subject: str,
    operation: str,
    transition: str,
    state: str,
    byte_binding_fields: tuple[str, ...],
) -> DurableCycle:
    return DurableCycle(
        ordinal=ordinal,
        cycle_id=cycle_id,
        subject=subject,
        intent_selector=f"MUTATION_INTENT:{operation}",
        consumed_selector=f"MUTATION_INTENT_CONSUMED:{operation}",
        outcome_selector=f"DRAFT_TRANSITION:{transition}",
        outcome_state=state,
        ordered_substeps=_CYCLE_SUBSTEPS,
        mutator_role="github_draft_mutator",
        observer_role="github_governance_reader",
        ambiguity_trace=f"{cycle_id}:provider-ambiguity-hold",
        recovery_trace=f"{cycle_id}:resume-from-durable-checkpoint",
        byte_source_authority="BROKER_RESOLVED_ADMITTED_CANDIDATE_BYTES",
        byte_binding_fields=byte_binding_fields,
        next_cycle_gate="PRIOR_OUTCOME_DURABLY_COMMITTED",
    )


CYCLES = (
    _cycle(
        1,
        "draft-create",
        "candidate.release",
        "GITHUB_DRAFT_CREATE",
        "CREATED",
        "DRAFT_CREATED",
        ("cycle_ordinal", "release_body_sha256", "tag"),
    ),
    *(
        _cycle(
            index + 2,
            f"draft-asset-{index:02d}",
            f"candidate.release_asset_inventory[{index:02d}]",
            "GITHUB_DRAFT_ASSET_UPLOAD",
            "ASSET_UPLOADED",
            "DRAFT_STAGING",
            (
                "cycle_ordinal",
                "expected_asset_inventory_sha256",
                "name",
                "sha256",
                "size_bytes",
            ),
        )
        for index in range(17)
    ),
    _cycle(
        19,
        "draft-update",
        "candidate.release",
        "GITHUB_DRAFT_UPDATE",
        "STAGED",
        "DRAFT_STAGED",
        (
            "asset_inventory_sha256",
            "cycle_ordinal",
            "release_body_sha256",
            "tag",
        ),
    ),
)

AUTHORITY_SELECTORS = tuple(
    sorted(
        {
            selector
            for cycle in CYCLES
            for selector in (
                cycle.intent_selector,
                cycle.consumed_selector,
                cycle.outcome_selector,
            )
        }
        | {"DRAFT_TRANSITION:VERIFIED"}
    )
)

RECOVERY_BRANCHES = (
    DurableRecoveryBranch(
        "TIMEOUT_OR_UNKNOWN_AFTER_EFFECT",
        "AMBIGUOUS",
        "READ_ONLY_PROVIDER_REQUERY",
        False,
        False,
        0,
        (),
        None,
    ),
    DurableRecoveryBranch(
        "EXACT_PROVIDER_OBJECT",
        "OBSERVED_EXACT",
        "OUTCOME_DURABLE_COMMIT_FROM_ORIGINAL_CONSUMPTION",
        False,
        False,
        0,
        (),
        None,
    ),
    DurableRecoveryBranch(
        "PROVIDER_CONFLICT",
        "CONFLICT",
        "INCIDENT_HOLD",
        False,
        False,
        0,
        (),
        "HOLD",
    ),
    DurableRecoveryBranch(
        "PROVIDER_CONCLUSIVELY_ABSENT",
        "ABSENCE_VERIFIED",
        "ISSUE_NEW_LINKED_INTENT_THEN_CONSUME_THEN_ONE_PROVIDER_EFFECT",
        False,
        True,
        1,
        (
            "absence_observation_sha256",
            "attempt_id",
            "fencing_token",
            "prior_consumption_receipt_id",
            "prior_intent_id",
            "subject_identity_sha256",
        ),
        None,
    ),
)

MACHINE = DurableStateMachine(
    operation_path="/v1/releases/draft/advance",
    runner_cardinality="UNTIL_TERMINAL",
    max_advances=256,
    max_provider_mutations_per_advance=1,
    no_transaction_across_network=True,
    durable_checkpoint_after_each_substep=True,
    retry_interval_seconds=5,
    response_statuses=("COMPLETE", "HOLD", "IN_PROGRESS", "WAITING"),
    terminal_statuses=("COMPLETE", "HOLD"),
    progress_authority="NON_AUTHORITATIVE",
    request_jti_policy="FRESH_OIDC_JTI_PER_ADVANCE",
    idempotent_retry_semantics="SAME_REQUEST_ID_RETURNS_SAME_DURABLE_STATE",
    candidate_source=DurableCandidateSource(
        private_rpc="candidate-reader:read-admitted-candidate-v1",
        service_role="candidate_reader",
        response_schema=candidate_stream.RESPONSE_SCHEMA,
        binding_fields=(
            "candidate_artifact_digest",
            "candidate_artifact_id",
            "candidate_id",
            "candidate_inventory_sha256",
            "release_identity_id",
            "target_run_attempt",
            "target_run_id",
        ),
        extraction_policy="EXACT_25_MEMBERS_NO_LINKS_NO_TRAVERSAL_REVERIFY_EACH_CYCLE",
    ),
    cycles=CYCLES,
    terminal_verification=DurableTerminalVerification(
        selector="DRAFT_TRANSITION:VERIFIED",
        state="DRAFT_VERIFIED",
        ordered_substeps=(
            "READ_ONLY_RELEASE_REQUERY",
            "READ_ONLY_EXACT_17_ASSET_REQUERY",
            "TAG_BODY_DRAFT_TRUE_INVENTORY_CROSS_BIND",
            "VERIFIED_OUTCOME_DURABLE_COMMIT",
        ),
        observer_role="github_governance_reader",
        mismatch_status="HOLD",
    ),
    recovery_branches=RECOVERY_BRANCHES,
    replay_policy="DUPLICATE_JTI_OR_REQUEST_CANNOT_ADVANCE_STATE",
    stale_fence_policy=(
        "READ_ONLY_LOOKUP_ALLOWED_REJECT_BEFORE_STATE_MUTATION_OR_PROVIDER_IO"
    ),
    wrong_subject_policy=(
        "READ_ONLY_LOOKUP_ALLOWED_REJECT_BEFORE_STATE_MUTATION_OR_PROVIDER_IO"
    ),
)

DRAFT_STAGE = OperationProfile(
    operation_id="draft-stage",
    job_name="draft-stage",
    environment="github-release",
    ordered_calls=(
        OrderedCall(
            phase="DRAFT_ADVANCE",
            method="POST",
            path=MACHINE.operation_path,
            audience=GITHUB,
            request_schema=schema_ids.SELECTOR_REQUEST,
            response_schema=schema_ids.DRAFT_ADVANCE_RESPONSE,
            response_mode="CANONICAL",
            effect=DURABLE_STATE_MACHINE,
            receipt_kinds=(
                "DRAFT_TRANSITION",
                "MUTATION_INTENT",
                "MUTATION_INTENT_CONSUMED",
            ),
            receipt_selectors=AUTHORITY_SELECTORS,
            receipt_states=(
                "DRAFT_CREATED",
                "DRAFT_STAGED",
                "DRAFT_STAGING",
                "DRAFT_VERIFIED",
                "MUTATION_INTENT_CONSUMED",
                "MUTATION_INTENT_RECORDED",
            ),
            cardinality=MACHINE.runner_cardinality,
            interval_seconds=MACHINE.retry_interval_seconds,
            repeat_count=MACHINE.max_advances,
            authority_selectors=AUTHORITY_SELECTORS,
        ),
    ),
    absolute_timeout_seconds=3600,
    durable_state_machine=MACHINE,
)
