"""Executable canonical codecs for the small Commit-A JSON wire surface.

Operation paths and action bundles select behavior; none of these documents
contains a caller-selected path, audience, method, receipt, envelope, token, or
capability.  The broker authors ledger state and returns only digest-bound
projections.  Provider mutation results are explicitly non-authoritative until
an isolated reader has re-queried the provider.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from tools.evidence import release_identity
from tools.evidence.release_canonical import (
    MAX_SAFE_INTEGER,
    CanonicalJsonError,
    canonical_json_bytes,
)
from tools.evidence.release_controller_limits import MAX_CONTROL_DOCUMENT_BYTES

MAX_WIRE_BYTES = MAX_CONTROL_DOCUMENT_BYTES
SCHEMA_VERSION = 1
SAMPLE_TAG = "v0.74.0"
SAMPLE_RELEASE_IDENTITY_ID = release_identity.release_identity_id(SAMPLE_TAG)

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_TAG_RE = re.compile(
    r"v(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\Z",
    re.ASCII,
)
_TOKEN_RE = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z", re.ASCII)
_OPERATION_RE = re.compile(r"[a-z][a-z0-9-]{1,63}\Z", re.ASCII)
_SELECTOR_RE = re.compile(r"[A-Z][A-Z0-9_]*(?::[A-Z][A-Z0-9_]*)?\Z", re.ASCII)
_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{7,127}\Z", re.ASCII)


class WireCodecError(ValueError):
    """Canonical operation bytes are malformed, oversized, or cross-bound."""


@dataclass(frozen=True, slots=True)
class JsonWireCodec:
    """One exact canonical JSON object codec and deterministic positive vector."""

    schema_id: str
    fields: tuple[str, ...]
    properties: Mapping[str, Mapping[str, Any]]
    golden_fields: Mapping[str, Any]
    semantic_validator: Callable[[Mapping[str, Any]], None]
    maximum_bytes: int = MAX_WIRE_BYTES

    def build(self, values: Mapping[str, Any]) -> bytes:
        """Build and re-parse the only accepted canonical representation."""

        document = {
            "schema": self.schema_id,
            "schema_version": SCHEMA_VERSION,
            **dict(values),
        }
        encoded = canonical_json_bytes(document)
        self.parse(encoded)
        return encoded

    def parse(
        self,
        data: bytes,
        *,
        expected_operation_id: str | None = None,
        expected_authority_selectors: tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        """Reject duplicate, non-canonical, unknown, or semantically invalid data."""

        if not isinstance(data, bytes) or not 1 <= len(data) <= self.maximum_bytes:
            raise WireCodecError("wire document size is invalid")
        try:
            raw = json.loads(data, object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError, WireCodecError) as exc:
            raise WireCodecError("wire document is not unique canonical JSON") from exc
        if not isinstance(raw, dict):
            raise WireCodecError("wire document root must be an object")
        try:
            if canonical_json_bytes(raw) != data:
                raise WireCodecError("wire document is not canonical JSON")
        except CanonicalJsonError as exc:
            raise WireCodecError("wire document leaves the canonical domain") from exc
        expected = {"schema", "schema_version", *self.fields}
        if set(raw) != expected:
            raise WireCodecError("wire document keys are not exact")
        if raw["schema"] != self.schema_id or raw["schema_version"] != SCHEMA_VERSION:
            raise WireCodecError("wire schema or version mismatch")
        self.semantic_validator(raw)
        if (
            expected_operation_id is not None
            and raw.get("operation_id") != expected_operation_id
        ):
            raise WireCodecError("wire response operation binding mismatch")
        if expected_authority_selectors is not None and raw.get(
            "authority_selectors"
        ) != list(expected_authority_selectors):
            raise WireCodecError("wire response selector binding mismatch")
        return raw

    def golden_bytes(self) -> bytes:
        """Return the checked positive wire vector for this exact schema."""

        return self.build(self.golden_fields)

    def json_schema(self) -> dict[str, Any]:
        """Return a closed Draft 2020-12 schema derived from the same field table."""

        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": (
                "https://paulkov.github.io/dpone-release-controller/schemas/wire/"
                f"{self.schema_id}.schema.json"
            ),
            "type": "object",
            "additionalProperties": False,
            "required": ["schema", "schema_version", *self.fields],
            "properties": {
                "schema": {"const": self.schema_id},
                "schema_version": {"const": SCHEMA_VERSION},
                **{key: dict(value) for key, value in self.properties.items()},
            },
        }


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WireCodecError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _selector(value: Mapping[str, Any]) -> None:
    _tag(value["tag"])
    _digest(value["release_identity_id"])
    if value["release_identity_id"] != release_identity.release_identity_id(
        value["tag"]
    ):
        raise WireCodecError("release identity/tag mismatch")


def _receipt(value: Mapping[str, Any]) -> None:
    _selector(value)
    if _OPERATION_RE.fullmatch(value["operation_id"]) is None:
        raise WireCodecError("receipt projection operation ID is invalid")
    selectors = value["authority_selectors"]
    if (
        not isinstance(selectors, list)
        or not selectors
        or selectors != sorted(set(selectors), key=lambda item: item.encode("ascii"))
        or any(_SELECTOR_RE.fullmatch(item) is None for item in selectors)
    ):
        raise WireCodecError("receipt projection selectors are not exact")
    _digest(value["head_receipt_id"])
    _digest(value["head_receipt_sha256"])
    _nonnegative(value["head_sequence"], "head_sequence")


def _receipt_batch(value: Mapping[str, Any]) -> None:
    _receipt(value)
    _digest(value["batch_sha256"])
    _digest(value["first_receipt_id"])
    _positive(value["receipt_count"], "receipt_count", maximum=64)


def _provider_result(value: Mapping[str, Any]) -> None:
    _selector(value)
    if (
        value["operation"]
        not in {
            "ATTESTATION_CREATE",
            "GITHUB_RELEASE_PUBLISH",
        }
        or value["status"] != "MUTATION_SUBMITTED_UNVERIFIED"
    ):
        raise WireCodecError("provider mutation result enum mismatch")
    _digest(value["provider_request_sha256"])


def _external_result(value: Mapping[str, Any]) -> None:
    _selector(value)
    if (
        value["operation"]
        not in {
            "PYPI_FILE_UPLOAD_SET",
        }
        or value["status"] != "LOCAL_SUCCESS_UNTRUSTED"
    ):
        raise WireCodecError("external action result enum mismatch")
    _digest(value["result_sha256"])


def _materialization_proof(value: Mapping[str, Any]) -> None:
    _selector(value)
    _digest(value["candidate_id"])
    _digest(value["candidate_inventory_sha256"])
    _digest(value["raw_zip_sha256"])
    _positive(value["raw_zip_size_bytes"], "raw_zip_size_bytes", maximum=805_306_368)
    if value["file_count"] != 25:
        raise WireCodecError("candidate proof must bind exactly 25 files")


def _draft_advance_request(value: Mapping[str, Any]) -> None:
    _selector(value)
    _digest(value["candidate_id"])
    _digest(value["cycle_transport_sha256"])
    _digest(value["local_verification_sha256"])


def _draft_advance_response(value: Mapping[str, Any]) -> None:
    _selector(value)
    if value["status"] not in {"COMPLETE", "HOLD", "IN_PROGRESS", "WAITING"}:
        raise WireCodecError("draft status is not closed")
    if (
        type(value["retry_after_seconds"]) is not int
        or not 0 <= value["retry_after_seconds"] <= 5
    ):
        raise WireCodecError("draft retry-after is outside the closed bound")
    expected_retry = 0 if value["status"] in {"COMPLETE", "HOLD"} else 5
    if value["retry_after_seconds"] != expected_retry:
        raise WireCodecError("draft status/retry-after coherence mismatch")
    _digest(value["durable_state_sha256"])
    _positive(value["advance_ordinal"], "advance_ordinal", maximum=256)


def _pypi_proof(value: Mapping[str, Any]) -> None:
    _materialization_proof(value)
    _digest(value["distribution_inventory_sha256"])
    _positive(
        value["distribution_total_bytes"],
        "distribution_total_bytes",
        maximum=536_870_912,
    )
    if value["distribution_file_count"] != 8:
        raise WireCodecError("PyPI proof must bind exactly eight distributions")


def _error(value: Mapping[str, Any]) -> None:
    if (
        not isinstance(value["request_id"], str)
        or _REQUEST_ID_RE.fullmatch(value["request_id"]) is None
    ):
        raise WireCodecError("error request ID is invalid")
    if (
        not isinstance(value["retryable"], bool)
        or _TOKEN_RE.fullmatch(value["code"]) is None
    ):
        raise WireCodecError("error response fields are invalid")


def _digest(value: Any) -> None:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise WireCodecError("digest is not canonical")


def _tag(value: Any) -> None:
    if not isinstance(value, str) or _TAG_RE.fullmatch(value) is None:
        raise WireCodecError("tag is not canonical")


def _positive(value: Any, name: str, *, maximum: int = MAX_SAFE_INTEGER) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise WireCodecError(f"{name} is not a bounded positive integer")


def _nonnegative(value: Any, name: str, *, maximum: int = MAX_SAFE_INTEGER) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        raise WireCodecError(f"{name} is not a bounded nonnegative integer")
