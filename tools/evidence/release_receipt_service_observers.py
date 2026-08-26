"""Provider-reader and scanner producer variants for receipt v2."""

from __future__ import annotations

from typing import Any, Mapping

from tools.evidence import release_composite_observation as composite_observation
from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_service_common as common


def validate_github_reader(
    producer: Mapping[str, Any], payload: Mapping[str, Any]
) -> None:
    """Validate one permission-scoped GitHub provider reader."""

    common.exact_service_keys(
        producer,
        {
            "github_app_id",
            "installation_id",
            "provider_observation_sha256",
            "provider_api_version",
        },
        f"{producer.get('service_role')} producer",
    )
    expected = common.provider_evidence(payload)
    if producer["provider_observation_sha256"] != expected:
        raise contract.ReceiptValidationError("provider reader observation mismatch")
    common.validate_service_common(producer)
    contract.positive_fields(producer, "github_app_id", "installation_id")
    contract.digest(producer["provider_observation_sha256"], "provider observation")
    if producer["provider_api_version"] != contract.GITHUB_API_VERSION:
        raise contract.ReceiptValidationError("provider reader API version mismatch")


def validate_pypi_reader(
    producer: Mapping[str, Any], payload: Mapping[str, Any]
) -> None:
    """Validate the isolated PyPI integrity observer."""

    common.exact_service_keys(
        producer,
        {"provider_observation_sha256", "provider_api_version"},
        "PyPI reader producer",
    )
    if producer["provider_observation_sha256"] != common.provider_evidence(payload):
        raise contract.ReceiptValidationError("PyPI reader observation mismatch")
    common.validate_service_common(producer)
    contract.digest(producer["provider_observation_sha256"], "provider observation")
    if producer["provider_api_version"] != "pypi-integrity-v1":
        raise contract.ReceiptValidationError("PyPI reader API version mismatch")


def validate_composite_observer(
    producer: Mapping[str, Any], payload: Mapping[str, Any]
) -> None:
    """Bind independently authenticated GitHub and PyPI observations."""

    common.exact_service_keys(
        producer,
        {
            "github_app_id",
            "github_provider_api_version",
            "github_provider_observation_sha256",
            "github_reader_service_identity",
            "github_reader_service_authority_role",
            "github_reader_service_version_id",
            "github_reader_deployment_observation_sha256",
            "github_reader_deployment_observation_record_id",
            "github_reader_deployment_observation_record_sha256",
            "installation_id",
            "pypi_provider_api_version",
            "pypi_provider_observation_sha256",
            "pypi_reader_service_identity",
            "pypi_reader_service_authority_role",
            "pypi_reader_service_version_id",
            "pypi_reader_deployment_observation_sha256",
            "pypi_reader_deployment_observation_record_id",
            "pypi_reader_deployment_observation_record_sha256",
            "aggregate_observation_sha256",
        },
        f"{producer.get('service_role')} producer",
    )
    aggregate_key = (
        "provider_observation_sha256"
        if payload["kind"] == "CANCELLATION"
        else "observation_sha256"
    )
    if (
        producer["github_provider_observation_sha256"]
        != payload["github_provider_observation_sha256"]
        or producer["pypi_provider_observation_sha256"]
        != payload["pypi_provider_observation_sha256"]
        or producer["aggregate_observation_sha256"] != payload[aggregate_key]
        or producer["aggregate_observation_sha256"]
        != composite_observation.digest(
            producer["github_provider_observation_sha256"],
            producer["pypi_provider_observation_sha256"],
        )
        or producer["github_provider_api_version"] != contract.GITHUB_API_VERSION
        or producer["pypi_provider_api_version"] != "pypi-integrity-v1"
        or producer["github_reader_service_authority_role"] != "governance_reader"
        or producer["pypi_reader_service_authority_role"] != "pypi_reader"
    ):
        raise contract.ReceiptValidationError("composite observer binding mismatch")
    common.validate_service_common(producer)
    contract.positive_fields(producer, "github_app_id", "installation_id")
    contract.digest_fields(
        producer,
        "github_provider_observation_sha256",
        "github_reader_deployment_observation_sha256",
        "github_reader_deployment_observation_record_id",
        "github_reader_deployment_observation_record_sha256",
        "pypi_provider_observation_sha256",
        "pypi_reader_deployment_observation_sha256",
        "pypi_reader_deployment_observation_record_id",
        "pypi_reader_deployment_observation_record_sha256",
        "aggregate_observation_sha256",
    )
    for key in (
        "github_reader_service_identity",
        "github_reader_service_version_id",
        "pypi_reader_service_identity",
        "pypi_reader_service_version_id",
    ):
        contract.opaque(producer[key], f"producer.{key}")


def validate_tenant_scanner(
    producer: Mapping[str, Any], payload: Mapping[str, Any]
) -> None:
    """Validate the isolated tenant scanner result projection."""

    common.exact_service_keys(
        producer,
        {"candidate_id", "scan_result_sha256", "scanner_service_version_id"},
        "tenant scanner producer",
    )
    if (
        producer["candidate_id"] != payload["candidate_id"]
        or producer["scan_result_sha256"] != payload["archive_results_sha256"]
        or producer["scanner_service_version_id"]
        != payload["scanner_service_version_id"]
        or producer["service_version_id"] != payload["scanner_service_version_id"]
    ):
        raise contract.ReceiptValidationError("tenant scanner result mismatch")
    common.validate_service_common(producer)
    contract.digest_fields(producer, "candidate_id", "scan_result_sha256")
    contract.opaque(
        producer["scanner_service_version_id"], "scanner_service_version_id"
    )
