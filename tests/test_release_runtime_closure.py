"""Negative tests for the held public runtime promotion boundary."""

from __future__ import annotations

from pathlib import Path
import unittest

from tools.evidence import release_controller_schema_registry as schema_registry
from tools.evidence import release_controller_wire_catalog as wire_catalog
from tools.evidence import release_runtime_closure
from tools.evidence import release_runtime_closure_authority
from tools.evidence import release_runtime_closure_contract
from tools.evidence import release_runtime_closure_observation
from tools.evidence import release_runtime_closure_provider
from tools.evidence.release_controller_workflow_ast import (
    WorkflowAstError,
    verify_runtime,
)
from tools.evidence.release_public_closure_hold import (
    REASON_CODE,
    PublicClosureContractHoldError,
)

ROOT = Path(__file__).resolve().parents[1]
HELD_WIRE_SCHEMAS = {
    "dpone.release-controller-closed-finalize-response.v1",
    "dpone.release-controller-closure-materialization.v1",
    "dpone.release-controller-closure-upload-proof.v1",
    "dpone.release-controller-runtime-closure-verification-result.v1",
    "dpone.release-runtime-closure-request.v1",
    "dpone.release-runtime-closure-stream-response.v1",
}


class RuntimeClosureHoldTests(unittest.TestCase):
    def test_runtime_request_and_response_entrypoints_are_unusable(self) -> None:
        calls = (
            release_runtime_closure.request_bytes,
            release_runtime_closure.parse_request,
            release_runtime_closure.verify_response,
            release_runtime_closure_contract.digest,
            release_runtime_closure_authority.verify_activation,
            release_runtime_closure_observation.verify_observation,
            release_runtime_closure_provider.verify_check,
        )
        for call in calls:
            with (
                self.subTest(call=call),
                self.assertRaisesRegex(
                    PublicClosureContractHoldError,
                    REASON_CODE,
                ),
            ):
                call(b"PRIVATE-CANARY")

    def test_runtime_workflow_verification_always_fails_closed(self) -> None:
        with self.assertRaisesRegex(WorkflowAstError, REASON_CODE):
            verify_runtime(
                {"jobs": {}},
                target_workflow_path=".github/workflows/runtime-image.yml",
                target_workflow_commit_sha="a" * 40,
                controller_action_commit_sha="b" * 40,
                controller_action_metadata_blob_sha="c" * 40,
                controller_action_bundle_sha256="sha256:" + "d" * 64,
            )

    def test_runtime_and_closure_wire_schemas_have_no_codec_or_fixture(self) -> None:
        self.assertTrue(HELD_WIRE_SCHEMAS.isdisjoint(wire_catalog.BY_SCHEMA))
        self.assertTrue(HELD_WIRE_SCHEMAS.isdisjoint(schema_registry.REGISTRY))
        for schema_id in HELD_WIRE_SCHEMAS:
            for root in (
                ROOT / "docs/schemas/release-controller-wire-v1",
                ROOT / "tests/fixtures/release-controller-wire-v1",
            ):
                with self.subTest(schema=schema_id, root=root):
                    self.assertFalse((root / f"{schema_id}.json").exists())
                    self.assertFalse((root / f"{schema_id}.zip").exists())
                    self.assertFalse((root / f"{schema_id}.headers.json").exists())


if __name__ == "__main__":
    unittest.main()
