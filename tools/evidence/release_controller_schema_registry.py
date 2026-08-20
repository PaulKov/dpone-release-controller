"""Closed executable registry for every schema named by operation profile v2."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from tools.evidence import release_candidate_stream as candidate_stream
from tools.evidence import release_candidate_stream_response as candidate_response
from tools.evidence import release_controller_activation_proof as activation
from tools.evidence import release_controller_exchange as exchange
from tools.evidence.release_controller_wire_catalog import BY_SCHEMA
from tools.evidence.release_controller_wire_codecs import JsonWireCodec
from tools.evidence.release_controller_wire_delegated import (
    DelegatedWireVerificationError,
    verify_delegated_fixture,
)
from tools.evidence.release_canonical import canonical_json_bytes
from tools.evidence.release_controller_limits import MAX_CONTROL_DOCUMENT_BYTES


@dataclass(frozen=True, slots=True)
class DelegatedWireCodec:
    """Contextual JSON or provider stream with real builder and verifier callables."""

    schema_id: str
    wire_kind: str
    media_type: str
    maximum_bytes: int
    builder: Callable[..., Any]
    parser: Callable[..., Any]
    top_level_fields: tuple[str, ...]
    golden_body_name: str
    golden_headers_name: str | None = None

    def verify(
        self,
        body: bytes,
        headers: Mapping[str, str] | None,
        *,
        fixture_root: Path,
    ) -> None:
        """Enforce size and execute the contextual production verifier."""

        if not isinstance(body, bytes) or not 1 <= len(body) <= self.maximum_bytes:
            raise DelegatedWireVerificationError(
                f"{self.schema_id} body size is outside bounds"
            )
        verify_delegated_fixture(
            self.schema_id,
            body,
            headers,
            fixture_root=fixture_root,
        )

    def verify_golden(self, fixture_root: Path) -> None:
        """Read and deeply verify the checked-in body and optional headers."""

        body = (fixture_root / self.golden_body_name).read_bytes()
        headers = None
        if self.golden_headers_name is not None:
            raw_headers = (fixture_root / self.golden_headers_name).read_bytes()
            try:
                parsed = json.loads(raw_headers)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise DelegatedWireVerificationError(
                    f"{self.schema_id} header fixture is invalid"
                ) from exc
            if (
                not isinstance(parsed, dict)
                or canonical_json_bytes(parsed) != raw_headers
            ):
                raise DelegatedWireVerificationError(
                    f"{self.schema_id} header fixture is not canonical"
                )
            headers = parsed
        self.verify(body, headers, fixture_root=fixture_root)

    def schema_document(self) -> dict[str, Any]:
        """Describe the exact parser boundary; parser code owns nested semantics."""

        properties: dict[str, Any] = {
            field: {"type": ["array", "boolean", "integer", "object", "string"]}
            for field in self.top_level_fields
        }
        if "schema" in properties:
            properties["schema"] = {"const": self.schema_id}
        if "schema_version" in properties:
            properties["schema_version"] = {"const": 1}
        if not self.top_level_fields:
            return {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": (
                    "https://paulkov.github.io/dpone-release-controller/schemas/wire/"
                    f"{self.schema_id}.schema.json"
                ),
                "$comment": (
                    "Binary stream semantics and provider headers are enforced by "
                    f"{self.parser.__module__}.{self.parser.__name__}."
                ),
                "type": "string",
                "contentEncoding": "base64",
                "contentMediaType": self.media_type,
            }
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": (
                "https://paulkov.github.io/dpone-release-controller/schemas/wire/"
                f"{self.schema_id}.schema.json"
            ),
            "$comment": (
                "Nested semantics, provider headers, and binary member limits are "
                f"enforced by {self.parser.__module__}.{self.parser.__name__}."
            ),
            "type": "object",
            "additionalProperties": False,
            "required": list(self.top_level_fields),
            "properties": properties,
        }


def _candidate_request_builder(value: candidate_stream.CandidateStreamRequest) -> bytes:
    return value.encoded()


def _candidate_admit_response_builder(
    receipt: Mapping[str, Any], *, expected: exchange.CandidateAdmitRequest
) -> bytes:
    return exchange.candidate_admit_response_bytes(receipt, expected=expected)


DELEGATED = (
    DelegatedWireCodec(
        activation.REQUEST_SCHEMA,
        "canonical-json",
        "application/json",
        1_024,
        activation.request_bytes,
        activation.parse_request,
        ("schema", "schema_version"),
        f"{activation.REQUEST_SCHEMA}.json",
    ),
    DelegatedWireCodec(
        activation.RESPONSE_SCHEMA,
        "contextual-canonical-json",
        "application/json",
        MAX_CONTROL_DOCUMENT_BYTES,
        activation.reference_response_bytes,
        activation.verify_exchange,
        (
            "activated",
            "admitted_at",
            "controller",
            "expires_at",
            "proof_sha256",
            "provisioned",
            "request_id",
            "schema",
            "schema_version",
        ),
        f"{activation.RESPONSE_SCHEMA}.json",
    ),
    DelegatedWireCodec(
        candidate_stream.REQUEST_SCHEMA,
        "canonical-json",
        "application/json",
        4_096,
        _candidate_request_builder,
        candidate_stream.CandidateStreamRequest.parse,
        (
            "candidate_artifact_digest",
            "candidate_artifact_id",
            "candidate_run_attempt",
            "candidate_run_id",
            "expected_peeled_commit_sha",
            "schema",
            "schema_version",
            "tag",
        ),
        f"{candidate_stream.REQUEST_SCHEMA}.json",
    ),
    DelegatedWireCodec(
        candidate_stream.RESPONSE_SCHEMA,
        "provider-zip-stream",
        candidate_stream.CONTENT_TYPE,
        805_306_368,
        candidate_response.response_headers,
        candidate_response.open_candidate_stream,
        (),
        f"{candidate_stream.RESPONSE_SCHEMA}.zip",
        f"{candidate_stream.RESPONSE_SCHEMA}.headers.json",
    ),
    DelegatedWireCodec(
        exchange.CANDIDATE_ADMIT_REQUEST_SCHEMA,
        "contextual-canonical-json",
        "application/json",
        16_777_216,
        exchange.candidate_admit_request_bytes,
        exchange.parse_candidate_admit_request,
        (
            "candidate",
            "evidence",
            "provider_observation",
            "release_identity_id",
            "schema",
            "schema_version",
        ),
        f"{exchange.CANDIDATE_ADMIT_REQUEST_SCHEMA}.json",
    ),
    DelegatedWireCodec(
        exchange.CANDIDATE_ADMIT_RESPONSE_SCHEMA,
        "contextual-canonical-json",
        "application/json",
        16_777_216,
        _candidate_admit_response_builder,
        exchange.parse_candidate_admit_response,
        ("head", "receipt", "schema", "schema_version"),
        f"{exchange.CANDIDATE_ADMIT_RESPONSE_SCHEMA}.json",
    ),
)

DELEGATED_BY_SCHEMA = {codec.schema_id: codec for codec in DELEGATED}
if len(DELEGATED_BY_SCHEMA) != len(DELEGATED):
    raise RuntimeError("duplicate delegated wire schema")

REGISTRY: dict[str, JsonWireCodec | DelegatedWireCodec] = {
    **{
        schema_id: codec
        for schema_id, codec in BY_SCHEMA.items()
        if schema_id != "dpone.release-controller-error-response.v1"
    },
    **DELEGATED_BY_SCHEMA,
}


def validate_operation_coverage() -> None:
    """Reject any operation schema without exactly one executable codec."""

    from tools.evidence import release_controller_operations as operations

    used = {
        schema_id
        for profile in operations.OPERATIONS
        for call in profile.ordered_calls
        for schema_id in (call.request_schema, call.response_schema)
        if schema_id is not None
    }
    if used != set(REGISTRY):
        raise RuntimeError(
            "operation/wire registry mismatch: "
            f"missing={sorted(used - set(REGISTRY))}, "
            f"extra={sorted(set(REGISTRY) - used)}"
        )


def golden_root(root: Path) -> Path:
    """Return the single checked fixture directory for all registry entries."""

    return root / "tests/fixtures/release-controller-wire-v1"


validate_operation_coverage()
