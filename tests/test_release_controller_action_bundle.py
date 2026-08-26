"""Commit-A executable inventory contract tests."""

from __future__ import annotations

import copy
import unittest

from jsonschema import Draft202012Validator

from scripts.generate_release_controller_action_contract import (
    OUTPUT,
    generated_bytes,
    schema_document,
)
from tools.evidence import release_controller_action_bundle as bundle


class ReleaseControllerActionBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.blobs = {
            path: f"reviewed executable bytes: {path}\n".encode()
            for path in bundle.EXECUTABLE_PATHS
        }
        self.document = bundle.document(commit_sha="a" * 40, blobs=self.blobs)

    def test_exact_bundle_is_canonical_and_recomputed_from_provider_blobs(self) -> None:
        encoded = bundle.encoded(self.document, blobs=self.blobs)
        self.assertFalse(encoded.endswith(b"\n"))
        self.assertRegex(
            bundle.bundle_sha256(self.document, blobs=self.blobs),
            r"\Asha256:[0-9a-f]{64}\Z",
        )
        self.assertEqual(
            bundle.inventory_sha256(self.document),
            bundle.bundle_sha256(self.document, blobs=self.blobs),
        )
        runtime = next(
            member
            for member in self.document["members"]
            if member["path"] == bundle.RUNTIME_CLOSURE_METADATA_PATH
        )
        self.assertEqual(
            bundle.runtime_closure_metadata_blob_sha(self.document, blobs=self.blobs),
            runtime["git_blob_sha"],
        )
        self.assertEqual(
            bundle.inventory_runtime_metadata_blob_sha(self.document),
            runtime["git_blob_sha"],
        )

    def test_generated_schema_is_current_and_accepts_the_exact_inventory(self) -> None:
        self.assertEqual(OUTPUT.read_bytes(), generated_bytes())
        validator = Draft202012Validator(schema_document())
        self.assertEqual(list(validator.iter_errors(self.document)), [])

    def test_missing_extra_reordered_or_tampered_surface_fails_closed(self) -> None:
        missing = dict(self.blobs)
        missing.pop(bundle.EXECUTABLE_PATHS[-1])
        extra = {**self.blobs, "actions/unreviewed/dist/index.js": b"x"}
        tampered = dict(self.blobs)
        tampered[bundle.EXECUTABLE_PATHS[0]] += b"tampered"
        cases = {
            "missing": (self.document, missing),
            "extra": (self.document, extra),
            "tampered": (self.document, tampered),
        }
        reordered = copy.deepcopy(self.document)
        reordered["members"].reverse()
        cases["reordered"] = (reordered, self.blobs)
        for name, (document, blobs) in cases.items():
            with self.subTest(name=name), self.assertRaises(bundle.ActionBundleError):
                bundle.verify(document, blobs=blobs)

        oversized = copy.deepcopy(self.document)
        oversized["members"][0]["size_bytes"] = bundle.MAX_MEMBER_BYTES + 1
        with self.assertRaises(bundle.ActionBundleError):
            bundle.verify_inventory(oversized)

    def test_manifest_has_no_self_digest_and_a_is_full_sha(self) -> None:
        self.assertNotIn("bundle_sha256", self.document)
        with self.assertRaises(bundle.ActionBundleError):
            bundle.document(commit_sha="main", blobs=self.blobs)

    def test_selected_actions_are_exact_sha_pinned_and_bytewise_sorted(self) -> None:
        for target in (False, True):
            patterns = bundle.allowed_action_patterns("a" * 40, target=target)
            self.assertEqual(
                patterns,
                tuple(sorted(patterns, key=lambda item: item.encode("ascii"))),
            )
            self.assertTrue(all("@*" not in value for value in patterns))
            self.assertIn(
                "paulkov/dpone-release-controller@" + "a" * 40,
                patterns,
            )


if __name__ == "__main__":
    unittest.main()
