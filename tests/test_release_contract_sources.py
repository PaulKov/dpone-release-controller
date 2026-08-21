"""Authority-direction and fail-closed tests for normative contract sources."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.evidence import release_receipt_contract
from tools.evidence import release_receipt_reference_vectors
from tools.evidence import release_receipt_schema_registry
from tools.evidence import release_receipt_vectors
from tools.evidence.release_contract_source import ContractSourceError, load_object

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_SCHEMA = ROOT / "docs/schemas/release/release-receipt-envelope-v2.schema.json"
CONFORMANCE_VECTOR = ROOT / "tests/fixtures/release-receipt-v2-golden.json"


class ReleaseContractSourceTests(unittest.TestCase):
    def test_schema_projection_and_runtime_kind_registry_are_exact(self) -> None:
        source = release_receipt_schema_registry.SOURCE
        registry_source = release_receipt_schema_registry.REGISTRY_SOURCE
        self.assertTrue(source.is_relative_to(ROOT / "docs/schemas"))
        self.assertTrue(registry_source.is_relative_to(ROOT / "contracts"))
        self.assertEqual(
            PUBLIC_SCHEMA.read_bytes(),
            release_receipt_schema_registry.schema_bytes(),
        )
        self.assertEqual(
            release_receipt_schema_registry.registered_receipt_types(),
            release_receipt_contract.PAYLOAD_KINDS,
        )

    def test_receipt_conformance_projection_uses_normative_positive_vector(
        self,
    ) -> None:
        source = release_receipt_reference_vectors.POSITIVE_SOURCE
        self.assertTrue(source.is_relative_to(ROOT / "contracts"))
        expected = release_receipt_reference_vectors.positive_envelope()
        generated = release_receipt_vectors.golden_document()
        self.assertEqual(generated["positive"]["envelope"], expected)
        self.assertEqual(json.loads(CONFORMANCE_VECTOR.read_bytes()), generated)

    def test_contract_loader_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ambiguous.json"
            path.write_bytes(b'{"schema":1,"schema":2}')
            with self.assertRaisesRegex(ContractSourceError, "duplicate key"):
                load_object(path, label="ambiguous contract")


if __name__ == "__main__":
    unittest.main()
