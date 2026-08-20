"""Lease and terminal operations independent from public closure projection."""

from tools.evidence import release_controller_schema_ids as schema_ids
from tools.evidence.release_controller_operation_contract import (
    LEASE_SENTINEL_POLL,
    READ,
    ActionCodec,
    OperationProfile,
    OrderedCall,
)
from tools.evidence.release_controller_operation_factory import (
    LEASE_ACTION_REF,
    action_input,
    once,
    selector_codec,
)
from tools.evidence.release_controller_route_contract import LEDGER

LEASE_ACQUIRE = OperationProfile(
    "lease-acquire",
    "lease-acquire",
    "release-attest",
    (
        once(
            "LEASE_ACQUIRE",
            "POST",
            "/v1/leases/acquire",
            LEDGER,
            schema_ids.SELECTOR_REQUEST,
            schema_ids.RECEIPT_PROJECTION,
            "LEDGER_TX",
            "LEASE_ACQUIRED",
            receipt_selectors=("LEASE_ACQUIRED:PRIMARY",),
            receipt_states=("LEASE_ACQUIRED",),
        ),
    ),
    60,
)

RECOVERY_LEASE_ACQUIRE = OperationProfile(
    "recovery-lease-acquire",
    "recovery-lease-acquire",
    "release-attest",
    (
        once(
            "RECOVERY_LEASE_ACQUIRE",
            "POST",
            "/v1/leases/recovery/acquire",
            LEDGER,
            schema_ids.SELECTOR_REQUEST,
            schema_ids.RECEIPT_PROJECTION,
            "LEDGER_TX",
            "LEASE_ACQUIRED",
            receipt_selectors=("LEASE_ACQUIRED:RECOVERY",),
            receipt_states=("LEASE_ACQUIRED",),
        ),
    ),
    60,
)

LEASE_SENTINEL = OperationProfile(
    "lease-sentinel",
    "lease-renew",
    "release-attest",
    (
        OrderedCall(
            phase="LEASE_RENEW",
            method="POST",
            path="/v1/leases/renew",
            audience=LEDGER,
            request_schema=schema_ids.LEASE_RENEW_REQUEST,
            response_schema=schema_ids.LEASE_RENEW_RESPONSE,
            response_mode="CANONICAL",
            effect=LEASE_SENTINEL_POLL,
            receipt_kinds=("LEASE_RENEWED",),
            receipt_selectors=("LEASE_RENEWED",),
            receipt_states=("LEASE_RENEWED",),
            cardinality="WHILE_LEASE_ACTIVE",
            interval_seconds=45,
            repeat_count=0,
            authority_selectors=("LEASE_RENEWED",),
        ),
    ),
    21_600,
)

TERMINAL_ASSERT = OperationProfile(
    "controller-complete",
    "controller-complete",
    "release-attest",
    (
        once(
            "TERMINAL_ASSERT",
            "POST",
            "/v1/releases/terminal/assert",
            LEDGER,
            schema_ids.SELECTOR_REQUEST,
            schema_ids.TERMINAL_ASSERT_RESPONSE,
            READ,
            authority_selectors=("TERMINAL_ASSERT",),
        ),
    ),
    60,
)


def codecs() -> tuple[ActionCodec, ...]:
    """Return the exact lease and terminal workflow action surfaces."""

    return (
        selector_codec("lease-acquire", "lease-acquire", ("LEASE_ACQUIRE",)),
        selector_codec(
            "recovery-lease-acquire",
            "recovery-lease-acquire",
            ("RECOVERY_LEASE_ACQUIRE",),
        ),
        selector_codec(
            "controller-complete", "controller-complete", ("TERMINAL_ASSERT",)
        ),
        ActionCodec(
            "lease-sentinel",
            "lease-sentinel",
            ("LEASE_RENEW",),
            LEASE_ACTION_REF,
            (
                action_input(
                    "lease_ttl_seconds",
                    "POSITIVE_INTEGER",
                    "WORKFLOW_LITERAL",
                    "300",
                ),
                action_input(
                    "operation",
                    "OPERATION_ID",
                    "WORKFLOW_LITERAL",
                    "lease-sentinel",
                ),
                action_input(
                    "renew_interval_seconds",
                    "POSITIVE_INTEGER",
                    "WORKFLOW_LITERAL",
                    "45",
                ),
                action_input("tag", "SEMVER_TAG"),
            ),
            (),
            "NONE",
        ),
    )
