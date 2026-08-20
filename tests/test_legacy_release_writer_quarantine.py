"""Repository-wide guard against reactivating pre-broker release writers."""

from __future__ import annotations

import importlib
import unittest
from pathlib import Path
from unittest.mock import Mock

from tools.evidence.release_legacy_writer_guard import LegacyReleaseWriterDisabled

ROOT = Path(__file__).resolve().parents[1]
LEGACY_MODULES = (
    "tools.evidence.release_receipt_envelope",
    "tools.evidence.release_lease_service",
    "tools.evidence.release_stream_service",
    "tools.evidence.release_evidence_store_b2",
)


class LegacyReleaseWriterQuarantineTests(unittest.TestCase):
    def test_every_legacy_emitter_stops_before_store_write(self) -> None:
        store = Mock()
        envelope = importlib.import_module(LEGACY_MODULES[0])
        lease = importlib.import_module(LEGACY_MODULES[1])
        stream = importlib.import_module(LEGACY_MODULES[2])
        for operation in (
            envelope.build_receipt_envelope,
            lease.acquire_publication_lease,
            lease.release_publication_lease,
            stream.append_stream_receipt,
        ):
            with (
                self.subTest(operation=operation.__name__),
                self.assertRaises(LegacyReleaseWriterDisabled),
            ):
                operation(store=store)
        store.assert_not_called()

    def test_actions_side_b2_credentials_are_unusable(self) -> None:
        store = importlib.import_module(LEGACY_MODULES[3])
        with self.assertRaises(LegacyReleaseWriterDisabled):
            store.BackblazeB2EvidenceStore(object())
        with self.assertRaises(LegacyReleaseWriterDisabled):
            store.InMemoryEvidenceStore()

    def test_active_graph_has_no_legacy_import_or_direct_append(self) -> None:
        active_paths = [ROOT / "tools/evidence/release_evidence_cli.py"]
        active_paths.extend((ROOT / ".github/workflows").glob("*.yml"))
        forbidden = (
            "release_receipt_envelope.py",
            "release_stream_service.py",
            "release_lease_service.py",
            "append_receipt(",
        )
        for path in active_paths:
            text = path.read_text()
            for token in forbidden:
                with self.subTest(path=path, token=token):
                    self.assertNotIn(token, text)

    def test_no_legacy_retention_floor_or_direct_append_survives(self) -> None:
        evidence_root = ROOT / "tools/evidence"
        for path in evidence_root.glob("release_*.py"):
            text = path.read_text()
            with self.subTest(path=path):
                self.assertNotIn("retention_days: int = 365", text)
                self.assertNotIn("default=365", text)
                self.assertNotIn(".append_receipt(", text)


if __name__ == "__main__":
    unittest.main()
