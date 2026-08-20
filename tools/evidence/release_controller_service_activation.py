"""A0 expected and post-A1 activated service-authority documents.

The expected document records only provider-observed staging membership.  A
separate post-promotion record embeds it together with a fresh final inventory;
therefore no A0 byte claims knowledge of a future traffic mutation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from tools.evidence import release_controller_service_inventory as activated
from tools.evidence import release_controller_service_expectation as expectation
from tools.evidence import (
    release_controller_service_activation_validation as validation,
)
from tools.evidence import release_receipt_contract as contract
from tools.evidence.release_canonical import canonical_json_bytes, sha256_id
from tools.evidence.release_controller_service_errors import ServiceActivationError

EXPECTED_SCHEMA = expectation.EXPECTED_SCHEMA
ACTIVATION_SCHEMA = validation.ACTIVATION_SCHEMA
HEAD_SCHEMA = "dpone.activated-service-authority-head.v1"
HEAD_ID_DOMAIN = "dpone.activated-service-authority-head.v1"
SCHEMA_VERSION = 1
ACTIVATION_ID_DOMAIN = "dpone.service-authority-activation-record.v1"
MAX_PROMOTION_EPOCH_SECONDS = validation.MAX_PROMOTION_EPOCH_SECONDS
MAX_PROVIDER_OBSERVATION_SECONDS = validation.MAX_PROVIDER_OBSERVATION_SECONDS
MAX_ACCEPTANCE_DELAY_SECONDS = validation.MAX_ACCEPTANCE_DELAY_SECONDS
MAX_HEAD_COMMIT_DELAY_SECONDS = 30
DEPLOYMENT_OBSERVER_ROLE = expectation.DEPLOYMENT_OBSERVER_ROLE
PROVIDER_API_VERSION = expectation.PROVIDER_API_VERSION
expected_document = expectation.expected_document
validate_expected = expectation.validate_expected
expected_digest = expectation.expected_digest
validate_activation = validation.validate_activation
provider_observation_digest = validation.provider_observation_digest


@dataclass(frozen=True, slots=True)
class ActivationCommitterBindings:
    """Precomputed immutable anchors shared by every receipt committer."""

    values: Mapping[str, str]


def activation_document(
    *,
    provisioned_record_id: str,
    provisioned_record_sha256: str,
    previous_record_id: str,
    previous_record_sha256: str,
    expected_service_authorities: Mapping[str, Any],
    activated_service_authorities: Mapping[str, Any],
    promotion_started_at: str,
    promotion_completed_at: str,
    provider_observation_started_at: str,
    provider_observation_completed_at: str,
    broker_accepted_at: str,
) -> dict[str, Any]:
    """Build one self-excluding post-promotion WORM record body."""

    result = {
        "schema": ACTIVATION_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "provisioned": {
            "record_id": provisioned_record_id,
            "record_sha256": provisioned_record_sha256,
        },
        "previous": {
            "record_id": previous_record_id,
            "record_sha256": previous_record_sha256,
        },
        "expected_service_authorities": dict(expected_service_authorities),
        "expected_service_authorities_sha256": expected_digest(
            expected_service_authorities
        ),
        "activated_service_authorities": dict(activated_service_authorities),
        "activated_service_authorities_sha256": activated.digest(
            activated_service_authorities
        ),
        "promotion_epoch": {
            "started_at": promotion_started_at,
            "completed_at": promotion_completed_at,
            "maximum_seconds": MAX_PROMOTION_EPOCH_SECONDS,
        },
        "provider_observation_window": {
            "started_at": provider_observation_started_at,
            "completed_at": provider_observation_completed_at,
            "maximum_seconds": MAX_PROVIDER_OBSERVATION_SECONDS,
            "provider_observation_count": len(
                activated_service_authorities["authorities"]
            ),
            "observer_authority_role": DEPLOYMENT_OBSERVER_ROLE,
            "observer_service_identity": validation.authority_by_role(
                activated_service_authorities, DEPLOYMENT_OBSERVER_ROLE
            )["service_identity"],
            "observer_worker_version_id": validation.authority_by_role(
                activated_service_authorities, DEPLOYMENT_OBSERVER_ROLE
            )["worker_version_id"],
            "provider_api_version": PROVIDER_API_VERSION,
        },
        "provider_observation_aggregate_sha256": provider_observation_digest(
            activated_service_authorities
        ),
        "observed_at": provider_observation_completed_at,
        "broker_accepted_at": broker_accepted_at,
    }
    validate_activation(result)
    return result


def activation_record_id(value: Any) -> str:
    """Return domain-separated identity of the self-excluding record body."""

    validate_activation(value)
    return sha256_id(ACTIVATION_ID_DOMAIN, value)


def activation_record_sha256(value: Any) -> str:
    """Return raw canonical-byte digest of the self-excluding record body."""

    validate_activation(value)
    return _sha256(canonical_json_bytes(value))


def authority_head_document(
    *,
    generation: int,
    previous: Mapping[str, Any],
    service_authority_activation_record: Mapping[str, Any],
    committed_at: str,
) -> dict[str, Any]:
    """Build the non-self-referential global activated-authority head."""

    record = dict(service_authority_activation_record)
    validate_activation(record)
    final = record["activated_service_authorities"]
    ingress = activated.validate(final)[activated.INGRESS_ROLE]
    result = {
        "schema": HEAD_SCHEMA,
        "schema_version": 1,
        "generation": generation,
        "previous": dict(previous),
        "expected_service_authorities_sha256": record[
            "expected_service_authorities_sha256"
        ],
        "activated_service_authorities_record_id": activation_record_id(record),
        "activated_service_authorities_record_sha256": activation_record_sha256(record),
        "activated_service_authorities_sha256": record[
            "activated_service_authorities_sha256"
        ],
        "ingress_worker_version_id": ingress["worker_version_id"],
        "committed_at": committed_at,
    }
    validate_authority_head(result, record)
    return result


def validate_authority_head(
    value: Any,
    activation_record: Any,
) -> None:
    """Verify one head against the exact embedded post-A1 activation record."""

    head = _mapping(value, "activated service authority head")
    _keys(
        head,
        {
            "schema",
            "schema_version",
            "generation",
            "previous",
            "expected_service_authorities_sha256",
            "activated_service_authorities_record_id",
            "activated_service_authorities_record_sha256",
            "activated_service_authorities_sha256",
            "ingress_worker_version_id",
            "committed_at",
        },
        "activated service authority head",
    )
    record = _mapping(activation_record, "service authority activation")
    validate_activation(record)
    if head["schema"] != HEAD_SCHEMA or head["schema_version"] != 1:
        raise ServiceActivationError("authority head schema/version mismatch")
    if type(head["generation"]) is not int or head["generation"] != 1:
        raise ServiceActivationError("authority head v1 generation must be one")
    for key in (
        "expected_service_authorities_sha256",
        "activated_service_authorities_record_id",
        "activated_service_authorities_record_sha256",
        "activated_service_authorities_sha256",
    ):
        _digest(head[key], key)
    previous = _mapping(head["previous"], "authority head previous")
    _keys(previous, {"kind"}, "authority head previous")
    if previous["kind"] != "GENESIS":
        raise ServiceActivationError("authority head v1 must use exact GENESIS")
    ingress = activated.validate(record["activated_service_authorities"])[
        activated.INGRESS_ROLE
    ]
    if (
        head["expected_service_authorities_sha256"]
        != record["expected_service_authorities_sha256"]
        or head["activated_service_authorities_record_id"]
        != activation_record_id(record)
        or head["activated_service_authorities_record_sha256"]
        != activation_record_sha256(record)
        or head["activated_service_authorities_sha256"]
        != record["activated_service_authorities_sha256"]
        or head["ingress_worker_version_id"] != ingress["worker_version_id"]
    ):
        raise ServiceActivationError("authority head/activation mismatch")
    committed = contract.timestamp(head["committed_at"], "authority head committed_at")
    accepted = contract.timestamp(record["broker_accepted_at"], "broker_accepted_at")
    if (
        committed < accepted
        or (committed - accepted).total_seconds() > MAX_HEAD_COMMIT_DELAY_SECONDS
    ):
        raise ServiceActivationError("authority head commit timing is invalid")


def authority_head_sha256(value: Any, activation_record: Any) -> str:
    """Return the tagged canonical digest of a validated authority head."""

    validate_authority_head(value, activation_record)
    return _sha256(canonical_json_bytes(value))


def authority_head_record_id(value: Any, activation_record: Any) -> str:
    """Return the domain-separated WORM record identity of the head body."""

    validate_authority_head(value, activation_record)
    return sha256_id(HEAD_ID_DOMAIN, value)


def compile_committer_bindings(
    value: Any,
    *,
    record_id: str,
    record_sha256: str,
) -> ActivationCommitterBindings:
    """Validate once and return all A0/A1/post/inventory committer anchors."""

    validate_activation(value)
    record = _mapping(value, "service authority activation")
    if record_id != activation_record_id(
        record
    ) or record_sha256 != activation_record_sha256(record):
        raise ServiceActivationError("service activation record identity mismatch")
    return ActivationCommitterBindings(
        values={
            "activation_provisioned_record_id": record["provisioned"]["record_id"],
            "activation_provisioned_digest": record["provisioned"]["record_sha256"],
            "activation_record_id": record["previous"]["record_id"],
            "activation_digest": record["previous"]["record_sha256"],
            "expected_service_authorities_sha256": record[
                "expected_service_authorities_sha256"
            ],
            "service_authority_activation_record_id": record_id,
            "service_authority_activation_record_sha256": record_sha256,
            "service_authority_inventory_sha256": record[
                "activated_service_authorities_sha256"
            ],
        }
    )


def bind_committer(
    committer: Mapping[str, Any], bindings: ActivationCommitterBindings
) -> None:
    """Cross-bind one committer to prevalidated activation anchors."""

    if any(committer.get(key) != value for key, value in bindings.values.items()):
        raise ServiceActivationError("committer service activation anchor mismatch")


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ServiceActivationError(f"{name} must be an object")
    return value


def _keys(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise ServiceActivationError(f"{name} keys are not exact")


def _digest(value: Any, name: str) -> None:
    try:
        contract.digest(value, name)
    except contract.ReceiptValidationError as exc:
        raise ServiceActivationError(str(exc)) from exc


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()
