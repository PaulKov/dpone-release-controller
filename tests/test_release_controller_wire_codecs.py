"""Canonical wire codec coverage and adversarial byte tests."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path

from tools.evidence import release_controller_operations as operations
from tools.evidence import release_controller_schema_ids as schema_ids
from tools.evidence.release_canonical import canonical_json_bytes
from tools.evidence.release_controller_wire_catalog import BY_SCHEMA
from tools.evidence.release_controller_wire_codecs import WireCodecError
from tools.evidence.release_controller_schema_registry import DELEGATED, REGISTRY

GOLDEN_ROOT = Path("tests/fixtures/release-controller-wire-v1")


class ReleaseControllerWireCodecTests(unittest.TestCase):
    def test_every_generic_operation_schema_has_executable_codec_and_golden(
        self,
    ) -> None:
        used = {
            schema_id
            for profile in operations.OPERATIONS
            for call in profile.ordered_calls
            for schema_id in (call.request_schema, call.response_schema)
            if schema_id is not None
        }
        self.assertEqual(used, set(REGISTRY))
        generic = used.intersection(BY_SCHEMA)
        for schema_id in sorted(generic):
            with self.subTest(schema_id=schema_id):
                codec = BY_SCHEMA[schema_id]
                path = GOLDEN_ROOT / f"{schema_id}.json"
                self.assertEqual(path.read_bytes(), codec.golden_bytes())
                self.assertEqual(codec.parse(path.read_bytes())["schema"], schema_id)

    def test_unknown_extra_duplicate_noncanonical_and_cross_binding_fail_closed(
        self,
    ) -> None:
        codec = BY_SCHEMA[schema_ids.SELECTOR_REQUEST]
        golden = codec.golden_bytes()
        values = json.loads(golden)
        cases = (
            canonical_json_bytes({**values, "body": {}}),
            golden.replace(
                b'{"release_identity_id":',
                b'{"tag":"v0.74.0","release_identity_id":',
                1,
            ),
            json.dumps(values, indent=2).encode(),
            canonical_json_bytes({**values, "tag": "v0.74.1"}),
        )
        for data in cases:
            with self.subTest(data=data[:80]), self.assertRaises(WireCodecError):
                codec.parse(data)

    def test_every_contextual_or_stream_codec_has_schema_golden_and_callables(
        self,
    ) -> None:
        schema_root = Path("docs/schemas/release-controller-wire-v1")
        for codec in DELEGATED:
            with self.subTest(schema_id=codec.schema_id):
                self.assertTrue(callable(codec.builder))
                self.assertTrue(callable(codec.parser))
                self.assertGreater(codec.maximum_bytes, 0)
                self.assertTrue((schema_root / f"{codec.schema_id}.json").is_file())
                self.assertTrue((GOLDEN_ROOT / codec.golden_body_name).is_file())
                if codec.golden_headers_name is not None:
                    self.assertTrue((GOLDEN_ROOT / codec.golden_headers_name).is_file())

    def test_every_delegated_golden_executes_real_parser_and_frozen_context(
        self,
    ) -> None:
        for codec in DELEGATED:
            with self.subTest(schema_id=codec.schema_id):
                codec.verify_golden(GOLDEN_ROOT)

    def test_delegated_body_header_and_size_tampering_fail_closed(self) -> None:
        for codec in DELEGATED:
            body = (GOLDEN_ROOT / codec.golden_body_name).read_bytes()
            headers = None
            if codec.golden_headers_name is not None:
                headers = json.loads(
                    (GOLDEN_ROOT / codec.golden_headers_name).read_bytes()
                )
            with self.subTest(schema_id=codec.schema_id, mutation="body"):
                with self.assertRaises(ValueError):
                    codec.verify(body + b"\n", headers, fixture_root=GOLDEN_ROOT)
            with self.subTest(schema_id=codec.schema_id, mutation="size"):
                bounded = replace(codec, maximum_bytes=len(body) - 1)
                with self.assertRaises(ValueError):
                    bounded.verify(body, headers, fixture_root=GOLDEN_ROOT)
            if headers is not None:
                missing = dict(headers)
                missing.pop("content-length")
                with self.subTest(schema_id=codec.schema_id, mutation="headers"):
                    with self.assertRaises(ValueError):
                        codec.verify(body, missing, fixture_root=GOLDEN_ROOT)

    def test_delegated_json_schemas_pin_schema_and_version_constants(self) -> None:
        for codec in DELEGATED:
            if not codec.top_level_fields:
                continue
            schema = codec.schema_document()
            with self.subTest(schema_id=codec.schema_id):
                self.assertEqual(
                    schema["properties"]["schema"], {"const": codec.schema_id}
                )
                self.assertEqual(schema["properties"]["schema_version"], {"const": 1})

    def test_bounds_enums_and_batch_multiplicity_fail_closed(self) -> None:
        cases = (
            (schema_ids.DRAFT_ADVANCE_RESPONSE, "retry_after_seconds", 6),
            (schema_ids.PYPI_MATERIALIZATION_PROOF, "distribution_file_count", 9),
            (schema_ids.RECEIPT_BATCH_PROJECTION, "receipt_count", 65),
            (schema_ids.PROVIDER_MUTATION_RESULT, "status", "SUCCESS"),
        )
        for schema_id, key, value in cases:
            codec = BY_SCHEMA[schema_id]
            raw = json.loads(codec.golden_bytes())
            raw[key] = value
            with (
                self.subTest(schema_id=schema_id, key=key),
                self.assertRaises(WireCodecError),
            ):
                codec.parse(canonical_json_bytes(raw))

    def test_draft_terminal_and_progress_retry_cadence_is_exact(self) -> None:
        codec = BY_SCHEMA[schema_ids.DRAFT_ADVANCE_RESPONSE]
        valid = (("COMPLETE", 0), ("HOLD", 0), ("IN_PROGRESS", 5), ("WAITING", 5))
        for status, retry_after in valid:
            raw = json.loads(codec.golden_bytes())
            raw.update(status=status, retry_after_seconds=retry_after)
            codec.parse(canonical_json_bytes(raw))
            raw["retry_after_seconds"] = 5 - retry_after
            with self.subTest(status=status), self.assertRaises(WireCodecError):
                codec.parse(canonical_json_bytes(raw))

    def test_held_public_closure_schemas_have_no_wire_codec(self) -> None:
        held = {
            "dpone.release-controller-closed-finalize-response.v1",
            "dpone.release-controller-closure-materialization.v1",
            "dpone.release-controller-closure-upload-proof.v1",
            "dpone.release-controller-runtime-closure-verification-result.v1",
            "dpone.release-runtime-closure-request.v1",
            "dpone.release-runtime-closure-stream-response.v1",
        }
        self.assertTrue(held.isdisjoint(BY_SCHEMA))
        self.assertTrue(held.isdisjoint(REGISTRY))

    def test_receipt_projection_is_bound_to_operation_and_authority_selectors(
        self,
    ) -> None:
        codec = BY_SCHEMA[schema_ids.RECEIPT_PROJECTION]
        golden = codec.golden_bytes()
        codec.parse(
            golden,
            expected_operation_id="admit",
            expected_authority_selectors=("REQUEST_ENQUEUED",),
        )
        for operation_id, selectors in (
            ("close", ("REQUEST_ENQUEUED",)),
            ("admit", ("CLOSED",)),
        ):
            with (
                self.subTest(operation_id=operation_id),
                self.assertRaises(WireCodecError),
            ):
                codec.parse(
                    golden,
                    expected_operation_id=operation_id,
                    expected_authority_selectors=selectors,
                )

    def test_error_request_id_rejects_control_and_header_injection(self) -> None:
        codec = BY_SCHEMA[schema_ids.ERROR_RESPONSE]
        for request_id in ("request\r\nforged", " control-01", "short"):
            raw = json.loads(codec.golden_bytes())
            raw["request_id"] = request_id
            with self.subTest(request_id=request_id), self.assertRaises(WireCodecError):
                codec.parse(canonical_json_bytes(raw))


if __name__ == "__main__":
    unittest.main()
