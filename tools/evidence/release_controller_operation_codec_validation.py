"""Closed workflow-call and action-codec validation for operation v2."""

from tools.evidence.release_controller_operation_contract import (
    DURABLE_STATE_MACHINE,
    EFFECTS,
    LEDGER_TX,
    LEASE_SENTINEL_POLL,
    LOCAL_VERIFY,
    PROVIDER_MUTATION,
    SERVER_REQUERY_LEDGER_TX,
    ActionCodec,
    ActionInput,
    OperationProfile,
    OrderedCall,
)
from tools.evidence.release_controller_operation_errors import OperationProfileError
from tools.evidence.release_controller_operation_factory import (
    BROKER_ACTION_REF,
    CARDINALITIES,
    FORBIDDEN_INPUTS,
    INPUT_RE,
    INPUT_SOURCES,
    INPUT_TYPES,
    LEASE_ACTION_REF,
    PHASE_RE,
    PYPI_ACTION_REF,
    SCHEMA_RE,
    TOKEN_RE,
)

_EXACT_ACTION_LITERALS = {
    (LEASE_ACTION_REF, "lease_ttl_seconds"): ("POSITIVE_INTEGER", "300"),
    (LEASE_ACTION_REF, "renew_interval_seconds"): ("POSITIVE_INTEGER", "45"),
    (PYPI_ACTION_REF, "packages-dir"): (
        "PACKAGE_DIRECTORY",
        "release-controller-pypi/dist",
    ),
}


def validate_codec(
    codec: ActionCodec,
    profile: OperationProfile,
    calls: dict[str, OrderedCall],
) -> None:
    """Validate an executable action step against its exact operation phases."""

    action_refs = {
        BROKER_ACTION_REF,
        LEASE_ACTION_REF,
        PYPI_ACTION_REF,
    }
    names = tuple(value.name for value in codec.inputs)
    forbidden = FORBIDDEN_INPUTS.intersection(names)
    if (
        TOKEN_RE.fullmatch(codec.step_id) is None
        or codec.action_ref not in action_refs
        or not codec.phases
        or names != tuple(sorted(names, key=lambda value: value.encode("ascii")))
        or len(set(names)) != len(names)
        or forbidden
        or codec.output_names
        != tuple(sorted(codec.output_names, key=lambda value: value.encode("ascii")))
        or codec.output_authority not in {"NONE", "UX_HINT_ONLY"}
        or (codec.output_names and codec.output_authority != "UX_HINT_ONLY")
    ):
        raise OperationProfileError("controller workflow step codec is not closed")
    external = codec.action_ref == PYPI_ACTION_REF
    for phase in codec.phases:
        if phase not in calls or (calls[phase].method == "ACTION") is not external:
            raise OperationProfileError("workflow action executor/phase mismatch")
        if external and calls[phase].path != codec.action_ref:
            raise OperationProfileError("external workflow action ref mismatch")
    for value in codec.inputs:
        literal_source = value.source in {
            "WORKFLOW_LITERAL",
        }
        if (
            INPUT_RE.fullmatch(value.name) is None
            or value.value_type not in INPUT_TYPES
            or value.source not in INPUT_SOURCES
            or literal_source
            != (isinstance(value.literal, str) and bool(value.literal))
            or (value.name == "operation" and value.literal != profile.operation_id)
        ):
            raise OperationProfileError("controller action input is not closed")
        _literal(codec, profile, value)


def validate_call(call: OrderedCall, phases: set[str]) -> None:
    """Validate one ordered local, network, or external-action call."""

    if PHASE_RE.fullmatch(call.phase) is None or call.phase in phases:
        raise OperationProfileError("operation phase is invalid or duplicated")
    phases.add(call.phase)
    if (
        call.effect not in EFFECTS
        or call.method not in {"GET", "POST", "LOCAL", "ACTION"}
        or SCHEMA_RE.fullmatch(call.request_schema) is None
        or call.response_mode not in {"CANONICAL", "NONE"}
        or (
            call.response_mode == "CANONICAL"
            and (
                not isinstance(call.response_schema, str)
                or SCHEMA_RE.fullmatch(call.response_schema) is None
            )
        )
        or (call.response_mode == "NONE" and call.response_schema is not None)
        or tuple(sorted(set(call.receipt_kinds))) != call.receipt_kinds
        or len(set(call.receipt_selectors)) != len(call.receipt_selectors)
        or len(set(call.receipt_states)) != len(call.receipt_states)
        or len(set(call.authority_selectors)) != len(call.authority_selectors)
        or call.cardinality not in CARDINALITIES
        or call.server_service_role
        not in {
            None,
            "attestation_reader",
            "cancellation_observer",
            "controller_run_reader",
            "github_governance_reader",
            "pypi_reader",
            "recovery_observer",
            "tenant_scanner",
        }
        or (call.effect == SERVER_REQUERY_LEDGER_TX)
        != (call.server_service_role is not None)
    ):
        raise OperationProfileError("operation call contract is invalid")
    if call.method == "LOCAL":
        if (
            call.audience is not None
            or not call.path.startswith("local:")
            or call.effect != LOCAL_VERIFY
        ):
            raise OperationProfileError("local verifier exposes network authority")
    elif call.method == "ACTION":
        if (
            call.audience is not None
            or call.path != PYPI_ACTION_REF
            or call.effect != PROVIDER_MUTATION
            or call.response_mode != "NONE"
        ):
            raise OperationProfileError("action effect authority is not exact")
    elif (
        call.audience is None
        or not call.path.startswith("/")
        or "?" in call.path
        or "#" in call.path
    ):
        raise OperationProfileError("network call authority is not exact")
    elif call.response_mode != "CANONICAL":
        raise OperationProfileError("network call must return a canonical response")
    if call.effect in {
        LEDGER_TX,
        LEASE_SENTINEL_POLL,
        DURABLE_STATE_MACHINE,
        SERVER_REQUERY_LEDGER_TX,
    }:
        if not call.receipt_kinds:
            raise OperationProfileError("ledger transaction has no receipt kind")
    elif call.receipt_kinds:
        raise OperationProfileError("non-ledger call claims receipt authority")
    _validate_cardinality(call)


def _literal(codec: ActionCodec, profile: OperationProfile, value: ActionInput) -> None:
    name = value.name
    expected = _EXACT_ACTION_LITERALS.get((codec.action_ref, name))
    if name == "operation":
        expected = ("OPERATION_ID", profile.operation_id)
    if value.literal is None:
        if expected is not None:
            raise OperationProfileError("required action literal is absent")
        return
    if expected != (value.value_type, value.literal):
        raise OperationProfileError("action literal type or value is not exact")


def _validate_cardinality(call: OrderedCall) -> None:
    if call.cardinality == "ONCE":
        if call.interval_seconds is not None or call.repeat_count != 1:
            raise OperationProfileError("one-shot call has repeat settings")
    elif call.cardinality == "EXACT_COUNT":
        if call.interval_seconds is not None or not 2 <= call.repeat_count <= 64:
            raise OperationProfileError("exact call cardinality is invalid")
    elif call.cardinality == "WHILE_LEASE_ACTIVE":
        if (
            call.phase != "LEASE_RENEW"
            or call.interval_seconds != 45
            or call.receipt_kinds != ("LEASE_RENEWED",)
            or call.repeat_count != 0
            or call.effect != LEASE_SENTINEL_POLL
        ):
            raise OperationProfileError("lease sentinel cadence is not exact")
    elif (
        call.effect != DURABLE_STATE_MACHINE
        or call.interval_seconds != 5
        or call.repeat_count != 256
    ):
        raise OperationProfileError("durable advance cadence is not exact")
