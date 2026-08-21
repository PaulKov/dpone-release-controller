"""Primitive closed types for Commit-A state-machine operation profiles."""

from __future__ import annotations

from dataclasses import dataclass

READ = "READ"
LOCAL_VERIFY = "LOCAL_VERIFY"
LEDGER_TX = "LEDGER_TX"
PROVIDER_MUTATION = "PROVIDER_MUTATION"
DURABLE_STATE_MACHINE = "DURABLE_STATE_MACHINE"
SERVER_REQUERY_LEDGER_TX = "SERVER_REQUERY_LEDGER_TX"
LEASE_SENTINEL_POLL = "LEASE_SENTINEL_POLL"
EFFECTS = frozenset(
    {
        READ,
        LOCAL_VERIFY,
        LEDGER_TX,
        PROVIDER_MUTATION,
        DURABLE_STATE_MACHINE,
        SERVER_REQUERY_LEDGER_TX,
        LEASE_SENTINEL_POLL,
    }
)


@dataclass(frozen=True, slots=True)
class OrderedCall:
    """One typed phase; no caller-selected path, audience, body, or codec."""

    phase: str
    method: str
    path: str
    audience: str | None
    request_schema: str
    response_schema: str | None
    response_mode: str
    effect: str
    receipt_kinds: tuple[str, ...]
    receipt_selectors: tuple[str, ...] = ()
    receipt_states: tuple[str, ...] = ()
    cardinality: str = "ONCE"
    interval_seconds: int | None = None
    repeat_count: int = 1
    authority_selectors: tuple[str, ...] = ()
    server_service_role: str | None = None


@dataclass(frozen=True, slots=True)
class DurableCycle:
    """One resumable draft effect with a durable checkpoint after every substep."""

    ordinal: int
    cycle_id: str
    subject: str
    intent_selector: str
    consumed_selector: str
    outcome_selector: str
    outcome_state: str
    ordered_substeps: tuple[str, ...]
    mutator_role: str
    observer_role: str
    ambiguity_trace: str
    recovery_trace: str
    byte_source_authority: str
    byte_binding_fields: tuple[str, ...]
    next_cycle_gate: str


@dataclass(frozen=True, slots=True)
class DurableCandidateSource:
    """Pinned private source for exact bytes already admitted by the ledger."""

    private_rpc: str
    service_role: str
    response_schema: str
    binding_fields: tuple[str, ...]
    extraction_policy: str


@dataclass(frozen=True, slots=True)
class DurableTerminalVerification:
    """Read-only whole-draft verification required before COMPLETE."""

    selector: str
    state: str
    ordered_substeps: tuple[str, ...]
    observer_role: str
    mismatch_status: str


@dataclass(frozen=True, slots=True)
class DurableRecoveryBranch:
    """Closed recovery decision after a consumed capability or provider call."""

    classification: str
    durable_state: str
    next_action: str
    provider_mutation_allowed: bool
    requires_new_linked_intent: bool
    max_retry_intents_per_subject: int
    retry_authority_link_fields: tuple[str, ...]
    terminal_status: str | None


@dataclass(frozen=True, slots=True)
class DurableStateMachine:
    """Closed server-side transition table driven by bounded one-step advances."""

    operation_path: str
    runner_cardinality: str
    max_advances: int
    max_provider_mutations_per_advance: int
    no_transaction_across_network: bool
    durable_checkpoint_after_each_substep: bool
    retry_interval_seconds: int
    response_statuses: tuple[str, ...]
    terminal_statuses: tuple[str, ...]
    progress_authority: str
    request_jti_policy: str
    idempotent_retry_semantics: str
    candidate_source: DurableCandidateSource
    cycles: tuple[DurableCycle, ...]
    terminal_verification: DurableTerminalVerification
    recovery_branches: tuple[DurableRecoveryBranch, ...]
    replay_policy: str
    stale_fence_policy: str
    wrong_subject_policy: str


@dataclass(frozen=True, slots=True)
class PublicationFilePlan:
    """One immutable distribution slot in byte-sorted candidate order."""

    ordinal: int
    project: str
    artifact_type: str
    inventory_selector: str
    prepare_transitions: tuple[str, ...]
    observe_transition: str
    observed_verified_count: int


@dataclass(frozen=True, slots=True)
class PublicationAlternative:
    """One fail-closed provider observation branch."""

    classification: str
    resulting_state: str
    terminal: bool
    provider_mutation_allowed: bool


@dataclass(frozen=True, slots=True)
class PublicationPlan:
    """Exact eight-file prepare and independently observed outcome table."""

    ordering: str
    files: tuple[PublicationFilePlan, ...]
    prepare_atomic_ledger_batch: bool
    prepare_provider_io_allowed: bool
    upload_intent_selector: str
    observe_prefix_selector: str
    complete_state: str
    alternatives: tuple[PublicationAlternative, ...]


@dataclass(frozen=True, slots=True)
class ServerTransactionPlan:
    """External reads followed by one fenced durable ledger commit."""

    phase: str
    pre_transaction_reads: tuple[str, ...]
    atomic_receipt_selectors: tuple[str, ...]
    receipt_producer_roles: tuple[tuple[str, str], ...]
    provider_io_inside_transaction: bool
    durable_commit_count: int
    state_recheck_before_commit: str


@dataclass(frozen=True, slots=True)
class OperationProfile:
    """Exact ordered phases executed by one named controller job."""

    operation_id: str
    job_name: str
    environment: str
    ordered_calls: tuple[OrderedCall, ...]
    absolute_timeout_seconds: int
    workflow_owner: str = "controller"
    workflow_path: str = ".github/workflows/release-controller.yml"
    durable_state_machine: DurableStateMachine | None = None
    publication_plan: PublicationPlan | None = None
    server_transactions: tuple[ServerTransactionPlan, ...] = ()


@dataclass(frozen=True, slots=True)
class ActionInput:
    """One workflow ``with`` input and its non-authoritative source class."""

    name: str
    value_type: str
    source: str
    literal: str | None = None


@dataclass(frozen=True, slots=True)
class ActionCodec:
    """Closed workflow-step executor and its exact input/output surface."""

    operation_id: str
    step_id: str
    phases: tuple[str, ...]
    action_ref: str
    inputs: tuple[ActionInput, ...]
    output_names: tuple[str, ...]
    output_authority: str
