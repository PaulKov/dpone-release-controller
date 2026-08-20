"""Deep semantic validators for durable draft and publication tables."""

from tools.evidence.release_controller_operation_contract import (
    DURABLE_STATE_MACHINE,
    OperationProfile,
)
from tools.evidence.release_controller_operation_draft import CYCLES, MACHINE
from tools.evidence.release_controller_operation_publication import (
    FILE_ROWS,
    PUBLICATION_PLAN,
)


class OperationSemanticsError(ValueError):
    """A specialized state-machine table is incomplete or ambiguous."""


def validate(profile: OperationProfile) -> None:
    """Validate every optional specialized contract attached to a profile."""

    _durable_draft(profile)
    _publication(profile)


def _durable_draft(profile: OperationProfile) -> None:
    machine = profile.durable_state_machine
    if machine is None:
        if any(call.effect == DURABLE_STATE_MACHINE for call in profile.ordered_calls):
            raise OperationSemanticsError("durable call has no transition table")
        return
    durable_calls = tuple(
        call for call in profile.ordered_calls if call.effect == DURABLE_STATE_MACHINE
    )
    if (
        profile.operation_id != "draft-stage"
        or machine != MACHINE
        or machine.cycles != CYCLES
        or len(durable_calls) != 1
        or durable_calls[0].path != machine.operation_path
        or durable_calls[0].cardinality != machine.runner_cardinality
        or durable_calls[0].repeat_count != machine.max_advances
        or durable_calls[0].interval_seconds != machine.retry_interval_seconds
        or machine.max_provider_mutations_per_advance != 1
        or machine.no_transaction_across_network is not True
        or machine.durable_checkpoint_after_each_substep is not True
        or machine.response_statuses != ("COMPLETE", "HOLD", "IN_PROGRESS", "WAITING")
        or machine.terminal_statuses != ("COMPLETE", "HOLD")
        or machine.progress_authority != "NON_AUTHORITATIVE"
        or machine.request_jti_policy != "FRESH_OIDC_JTI_PER_ADVANCE"
        or machine.idempotent_retry_semantics
        != "SAME_REQUEST_ID_RETURNS_SAME_DURABLE_STATE"
        or len(machine.cycles) != 19
    ):
        raise OperationSemanticsError("durable draft state machine is invalid")
    expected_ids = (
        "draft-create",
        *(f"draft-asset-{index:02d}" for index in range(17)),
        "draft-update",
    )
    if tuple(cycle.cycle_id for cycle in machine.cycles) != expected_ids:
        raise OperationSemanticsError("durable draft cycle order is invalid")
    for ordinal, cycle in enumerate(machine.cycles, start=1):
        if (
            cycle.ordinal != ordinal
            or cycle.next_cycle_gate != "PRIOR_OUTCOME_DURABLY_COMMITTED"
            or cycle.byte_source_authority != "BROKER_RESOLVED_ADMITTED_CANDIDATE_BYTES"
            or "PROVIDER_RESULT_CLASSIFY" not in cycle.ordered_substeps
            or "INTERNAL_PINNED_CANDIDATE_SOURCE_STREAM" not in cycle.ordered_substeps
            or "SAFE_EXACT_MEMBER_EXTRACTION" not in cycle.ordered_substeps
        ):
            raise OperationSemanticsError("durable draft cycle binding is invalid")
        expected_transport = (
            (
                "cycle_ordinal",
                "expected_asset_inventory_sha256",
                "name",
                "sha256",
                "size_bytes",
            )
            if cycle.cycle_id.startswith("draft-asset-")
            else (
                ("cycle_ordinal", "release_body_sha256", "tag")
                if cycle.cycle_id == "draft-create"
                else (
                    "asset_inventory_sha256",
                    "cycle_ordinal",
                    "release_body_sha256",
                    "tag",
                )
            )
        )
        if cycle.byte_binding_fields != expected_transport:
            raise OperationSemanticsError("durable draft byte binding is invalid")
    source = machine.candidate_source
    if (
        source.private_rpc != "candidate-reader:read-admitted-candidate-v1"
        or source.service_role != "candidate_reader"
        or source.extraction_policy
        != "EXACT_25_MEMBERS_NO_LINKS_NO_TRAVERSAL_REVERIFY_EACH_CYCLE"
        or source.binding_fields
        != (
            "candidate_artifact_digest",
            "candidate_artifact_id",
            "candidate_id",
            "candidate_inventory_sha256",
            "release_identity_id",
            "target_run_attempt",
            "target_run_id",
        )
    ):
        raise OperationSemanticsError("durable candidate source is invalid")
    terminal = machine.terminal_verification
    if (
        terminal.selector != "DRAFT_TRANSITION:VERIFIED"
        or terminal.state != "DRAFT_VERIFIED"
        or terminal.ordered_substeps
        != (
            "READ_ONLY_RELEASE_REQUERY",
            "READ_ONLY_EXACT_17_ASSET_REQUERY",
            "TAG_BODY_DRAFT_TRUE_INVENTORY_CROSS_BIND",
            "VERIFIED_OUTCOME_DURABLE_COMMIT",
        )
        or terminal.observer_role != "github_governance_reader"
        or terminal.mismatch_status != "HOLD"
    ):
        raise OperationSemanticsError("durable terminal verification is invalid")
    branches = machine.recovery_branches
    if (
        tuple(branch.classification for branch in branches)
        != (
            "TIMEOUT_OR_UNKNOWN_AFTER_EFFECT",
            "EXACT_PROVIDER_OBJECT",
            "PROVIDER_CONFLICT",
            "PROVIDER_CONCLUSIVELY_ABSENT",
        )
        or any(branch.provider_mutation_allowed for branch in branches)
        or branches[-1].max_retry_intents_per_subject != 1
        or not branches[-1].requires_new_linked_intent
        or machine.replay_policy != "DUPLICATE_JTI_OR_REQUEST_CANNOT_ADVANCE_STATE"
        or "REJECT_BEFORE_STATE_MUTATION_OR_PROVIDER_IO"
        not in machine.stale_fence_policy
        or machine.wrong_subject_policy != machine.stale_fence_policy
    ):
        raise OperationSemanticsError("durable recovery table is invalid")


def _publication(profile: OperationProfile) -> None:
    plan = profile.publication_plan
    if plan is None:
        if profile.operation_id in {"pypi-prepare", "pypi-observe"}:
            raise OperationSemanticsError("PyPI operation has no exact file plan")
        return
    if (
        profile.operation_id not in {"pypi-prepare", "pypi-observe"}
        or plan != PUBLICATION_PLAN
        or plan.ordering != "BYTEWISE_FILENAME_ASCENDING"
        or len(plan.files) != 8
        or not plan.prepare_atomic_ledger_batch
        or plan.prepare_provider_io_allowed
    ):
        raise OperationSemanticsError("PyPI publication plan is invalid")
    expected = tuple((project, kind) for project, kind, _name in FILE_ROWS)
    if tuple((item.project, item.artifact_type) for item in plan.files) != expected:
        raise OperationSemanticsError("PyPI file order is invalid")
    for index, item in enumerate(plan.files, start=1):
        if (
            item.ordinal != index
            or item.inventory_selector != f"candidate.distributions[{index - 1:02d}]"
            or item.prepare_transitions != ("PENDING_UPLOAD", "SEALED_FOR_UPLOAD")
            or item.observe_transition != "INTEGRITY_VERIFIED"
            or item.observed_verified_count != index
        ):
            raise OperationSemanticsError("PyPI file transition table is invalid")
    if any(item.provider_mutation_allowed for item in plan.alternatives):
        raise OperationSemanticsError("PyPI observer may not mutate provider state")
