"""Fail-closed structural and route-ownership validation for operation v2."""

from tools.evidence import release_controller_routes as controller_routes
from tools.evidence import release_controller_typed_routes as typed_routes
from tools.evidence import release_controller_operation_semantics as semantics
from tools.evidence import (
    release_controller_operation_codec_validation as codec_validation,
)
from tools.evidence.release_controller_service_roles import role_for_selector
from tools.evidence.release_controller_operation_contract import (
    DURABLE_STATE_MACHINE,
    SERVER_REQUERY_LEDGER_TX,
    ActionCodec,
    OperationProfile,
    OrderedCall,
)
from tools.evidence.release_controller_operation_errors import OperationProfileError
from tools.evidence.release_controller_operation_factory import (
    PHASE_RE,
    TOKEN_RE,
)


def validate(
    operations: tuple[OperationProfile, ...], codecs: tuple[ActionCodec, ...]
) -> None:
    """Reject ambiguity, hidden authority, route drift, and codec drift."""

    by_id = {profile.operation_id: profile for profile in operations}
    if len(by_id) != len(operations):
        raise OperationProfileError("duplicate controller operation ID")
    codecs_by_operation = {
        operation_id: tuple(
            codec for codec in codecs if codec.operation_id == operation_id
        )
        for operation_id in by_id
    }
    if any(not values for values in codecs_by_operation.values()) or {
        codec.operation_id for codec in codecs
    } != set(by_id):
        raise OperationProfileError("operation/action codec set mismatch")
    for profile in operations:
        _profile(profile, codecs_by_operation[profile.operation_id])
    _route_coverage(operations)


def _profile(profile: OperationProfile, codecs: tuple[ActionCodec, ...]) -> None:
    if (
        TOKEN_RE.fullmatch(profile.operation_id) is None
        or TOKEN_RE.fullmatch(profile.job_name) is None
        or profile.environment
        not in {"release-attest", "github-release", "ghcr", "pypi"}
        or profile.workflow_owner != "controller"
        or profile.workflow_path != ".github/workflows/release-controller.yml"
        or not profile.ordered_calls
        or type(profile.absolute_timeout_seconds) is not int
        or not 1 <= profile.absolute_timeout_seconds <= 21_600
    ):
        raise OperationProfileError("controller operation identity is invalid")
    phases: set[str] = set()
    for call in profile.ordered_calls:
        codec_validation.validate_call(call, phases)
    _server_transactions(profile)
    try:
        semantics.validate(profile)
    except semantics.OperationSemanticsError as exc:
        raise OperationProfileError(str(exc)) from exc
    if tuple(phase for codec in codecs for phase in codec.phases) != tuple(
        call.phase for call in profile.ordered_calls
    ) or len({codec.step_id for codec in codecs}) != len(codecs):
        raise OperationProfileError("workflow step/phase order mismatch")
    calls = {call.phase: call for call in profile.ordered_calls}
    for codec in codecs:
        codec_validation.validate_codec(codec, profile, calls)


def _server_transactions(profile: OperationProfile) -> None:
    """Require one exact post-read durable plan for every server requery call."""

    calls = tuple(
        call
        for call in profile.ordered_calls
        if call.effect == SERVER_REQUERY_LEDGER_TX
    )
    plans = profile.server_transactions
    if tuple(plan.phase for plan in plans) != tuple(call.phase for call in calls):
        raise OperationProfileError("server transaction plan coverage mismatch")
    for call, plan in zip(calls, plans, strict=True):
        if (
            not plan.pre_transaction_reads
            or len(set(plan.pre_transaction_reads)) != len(plan.pre_transaction_reads)
            or any(
                PHASE_RE.fullmatch(read) is None for read in plan.pre_transaction_reads
            )
            or plan.atomic_receipt_selectors != call.receipt_selectors
            or plan.receipt_producer_roles
            != tuple(
                (selector, role_for_selector(selector))
                for selector in call.receipt_selectors
            )
            or plan.provider_io_inside_transaction is not False
            or plan.durable_commit_count != 1
            or plan.state_recheck_before_commit
            != "RELEASE_ATTEMPT_LEASE_FENCE_AND_HEAD"
        ):
            raise OperationProfileError("server transaction plan is not atomic")


def _route_coverage(operations: tuple[OperationProfile, ...]) -> None:
    claims: dict[str, list[tuple[OperationProfile, OrderedCall]]] = {}
    for profile in operations:
        for call in profile.ordered_calls:
            for selector in call.authority_selectors:
                claims.setdefault(selector, []).append((profile, call))
    expected = {
        route.selector
        for route in controller_routes.ROUTES
        if route.requester_kind == "github_actions_job"
    }
    unknown = set(claims) - set(controller_routes.ROUTE_BY_SELECTOR)
    if unknown:
        raise OperationProfileError(
            f"operation claims unknown route selectors: {sorted(unknown)}"
        )
    observed = expected.intersection(claims)
    if observed != expected:
        raise OperationProfileError(
            f"workflow route coverage mismatch: missing={sorted(expected - observed)}"
        )
    for selector in expected:
        owners = claims[selector]
        if len(owners) != 1:
            raise OperationProfileError("workflow route selector has multiple owners")
        profile, call = owners[0]
        route = controller_routes.ROUTE_BY_SELECTOR[selector]
        typed = typed_routes.by_selector(selector)
        receipt_matches = (
            not call.receipt_kinds
            if route.receipt_type is None
            else route.receipt_type in call.receipt_kinds
        )
        if (
            profile.job_name != route.job_name
            or profile.environment != route.environment
            or call.method != route.method
            or call.path != route.path
            or call.path != typed.path
            or call.audience != route.audience
            or call.audience != typed.audience
            or not receipt_matches
            or not set(route.receipt_states).issubset(call.receipt_states)
        ):
            raise OperationProfileError(
                f"workflow route owner authority mismatch: {selector}"
            )
    _durable_internal_coverage(claims)


def _durable_internal_coverage(
    claims: dict[str, list[tuple[OperationProfile, OrderedCall]]],
) -> None:
    """Bind every internal draft transition to the sole durable advance call."""

    expected = {
        route.selector
        for route in controller_routes.ROUTES
        if route.requester_kind == "trusted_controller_service"
        and (
            "GITHUB_DRAFT_" in route.selector
            or route.selector.startswith("DRAFT_TRANSITION:")
        )
    }
    for selector in expected:
        owners = claims.get(selector, [])
        if len(owners) != 1:
            raise OperationProfileError("internal draft selector ownership mismatch")
        profile, call = owners[0]
        if (
            profile.operation_id != "draft-stage"
            or call.phase != "DRAFT_ADVANCE"
            or call.effect != DURABLE_STATE_MACHINE
        ):
            raise OperationProfileError(
                "internal draft selector escaped durable advance"
            )
