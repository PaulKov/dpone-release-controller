"""Public facade for deterministic receipt-envelope v2 fixtures."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from tests import release_receipt_fixture_identity as identity
from tests import release_receipt_payload_fixtures as payloads
from tests import release_receipt_producer_fixtures as producers
from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_payloads
from tools.evidence.release_receipt_envelope_v2 import build

TAG = identity.TAG
VERSION = identity.VERSION
TAG_OBJECT_SHA = identity.TAG_OBJECT_SHA
COMMIT_SHA = identity.COMMIT_SHA
WORKFLOW_SHA = identity.WORKFLOW_SHA
ACTION_COMMIT_SHA = identity.ACTION_COMMIT_SHA
ACTION_METADATA_BLOB_SHA = identity.ACTION_METADATA_BLOB_SHA
ACTION_BUNDLE_SHA256 = identity.ACTION_BUNDLE_SHA256
CANDIDATE_INVENTORY_SHA256 = identity.CANDIDATE_INVENTORY_SHA256
RELEASE_ID = identity.RELEASE_ID
AUTHORITY_ID = identity.AUTHORITY_ID
ATTEMPT_ID = identity.ATTEMPT_ID
RECOVERY_ATTEMPT_ID = identity.RECOVERY_ATTEMPT_ID
QUEUE_ID = identity.QUEUE_ID
CANDIDATE_ID = identity.CANDIDATE_ID
LEASE_ID = identity.LEASE_ID
RECOVERY_LEASE_ID = identity.RECOVERY_LEASE_ID
AUTHORIZATION_ID = identity.AUTHORIZATION_ID
RECOVERY_ID = identity.RECOVERY_ID
DIST_FILES = identity.DIST_FILES

digest = identity.digest
distributions = identity.distributions
request_payload = payloads.request_payload
governance_payload = payloads.governance_payload
candidate_payload = payloads.candidate_payload
lease_acquired_payload = payloads.lease_acquired_payload
lease_renewed_payload = payloads.lease_renewed_payload
lease_released_payload = payloads.lease_released_payload
abandoned_lease_release_payload = payloads.abandoned_lease_release_payload
lease_expired_payload = payloads.lease_expired_payload
hygiene_payload = payloads.hygiene_payload
attestation_payload = payloads.attestation_payload
release_assets = payloads.release_assets
bundle_payload = payloads.bundle_payload
draft_created_payload = payloads.draft_created_payload
draft_asset_payload = payloads.draft_asset_payload
draft_inventory_payload = payloads.draft_inventory_payload
producer_for = producers.producer_for
committer = producers.committer

# Compatibility aliases for existing generators and fixture consumers. New code
# should use the public names above; the aliases can be removed after consumers
# migrate in a dedicated contract change.
_distributions = distributions
_request = request_payload
_governance = governance_payload
_candidate = candidate_payload
_lease_acquired = lease_acquired_payload
_lease_renewed = lease_renewed_payload
_lease_released = lease_released_payload
_lease_released_abandoned = abandoned_lease_release_payload
_lease_expired = lease_expired_payload
_hygiene = hygiene_payload
_attestation = attestation_payload
_release_assets = release_assets
_bundle = bundle_payload
_draft_created = draft_created_payload
_draft_asset = draft_asset_payload
_draft_inventory = draft_inventory_payload
_producer = producer_for
_committer = committer


def all_payloads() -> list[dict[str, Any]]:
    """Return at least one exact instance of every payload union branch."""

    from tests import release_receipt_intent_fixtures as intent_fixture
    from tests import release_receipt_publish_fixtures as publish
    from tests.release_receipt_gate_fixtures import all_gate_payloads

    payload_documents = [
        request_payload(),
        governance_payload("A"),
        candidate_payload(),
        lease_acquired_payload(),
        lease_renewed_payload(),
        lease_released_payload(),
        abandoned_lease_release_payload(),
        lease_expired_payload(),
        hygiene_payload(),
        intent_fixture.intent("ATTESTATION_CREATE"),
        intent_fixture.intent("PYPI_DEPLOYMENT_APPROVE"),
        attestation_payload(),
        bundle_payload(),
        intent_fixture.intent("GITHUB_DRAFT_CREATE"),
        draft_created_payload(),
        intent_fixture.intent("GITHUB_DRAFT_ASSET_UPLOAD"),
        draft_asset_payload(),
        intent_fixture.intent("GITHUB_DRAFT_UPDATE"),
        draft_inventory_payload("STAGED"),
        draft_inventory_payload("VERIFIED"),
        governance_payload("B"),
        publish.authorized(),
        intent_fixture.intent("PYPI_DEPLOYMENT_REJECT"),
        intent_fixture.intent("PYPI_FILE_UPLOAD_SET"),
        intent_fixture.intent("GITHUB_RELEASE_PUBLISH"),
        publish.pypi("PENDING_UPLOAD"),
        publish.pypi("SEALED_FOR_UPLOAD"),
        publish.upload_set(),
        publish.pypi("INTEGRITY_VERIFIED", verified_count=4),
        publish.pypi("ALREADY_PUBLISHED_EXACT", verified_count=8),
        publish.pypi("CONFLICT"),
        *all_gate_payloads(),
        publish.github("PUBLISH_ACCEPTED"),
        publish.github("IMMUTABLE_VERIFIED"),
        governance_payload("C"),
        publish.cancellation(False),
        publish.cancellation(True),
        publish.recovery(),
        publish.recovery_resumed(),
        publish.recovery_closed_exact(),
        publish.hold(),
        publish.hold_released(),
        publish.closed(),
    ]
    payload_documents.extend(
        intent_fixture.consumed(operation)
        for operation in sorted(intent_fixture.intents.OPERATIONS)
    )
    return payload_documents


def envelope_for(
    payload: Mapping[str, Any],
    *,
    attempt: Mapping[str, Any] | None = None,
    lease: Mapping[str, Any] | None = None,
    producer: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic envelope around one valid fixture payload."""

    semantics = release_receipt_payloads.validate(payload)
    scope_key = {
        "release": "release_identity_id",
        "candidate": "candidate_id",
        "authorization": "authorization_id",
        "recovery": "recovery_id",
    }[semantics.scope_kind]
    scope_value = (
        RELEASE_ID if scope_key == "release_identity_id" else payload[scope_key]
    )
    root_attempt = dict(
        attempt
        or {
            "attempt_id": payload.get("attempt_id", ATTEMPT_ID),
            "queue_entry_id": QUEUE_ID,
        }
    )
    root_lease = dict(
        lease
        or {
            "lease_id": payload.get("lease_id", LEASE_ID),
            "fencing_token": payload.get("fencing_token", 3),
        }
    )
    return build(
        stream={
            "release_identity_id": RELEASE_ID,
            "release_authority_id": AUTHORITY_ID,
            "sequence": 1 if semantics.lease_required else 0,
            "previous": digest("previous") if semantics.lease_required else "GENESIS",
        },
        scope={"kind": semantics.scope_kind, scope_key: scope_value},
        attempt=root_attempt,
        lease=root_lease if semantics.lease_required else None,
        producer=dict(producer or producer_for(payload)),
        committer=committer(),
        timestamps=_timestamps_for(payload),
        payload=payload,
    )


def _timestamps_for(payload: Mapping[str, Any]) -> dict[str, str]:
    floor = datetime(2026, 8, 15, tzinfo=timezone.utc)
    events = [
        datetime.strptime(payload[key], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        for key in contract.HISTORICAL_EVENT_TIMESTAMP_FIELDS
        if key in payload
    ]
    observed = max([floor, *events])
    committed = observed + timedelta(seconds=1)
    return {
        "observed_at": observed.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "committed_at": committed.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
