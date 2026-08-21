"""Cross-language closed canonical JSON domain tests."""

from __future__ import annotations

import math
import unittest

from tools.evidence import release_canonical as canonical


class ReleaseCanonicalTests(unittest.TestCase):
    def test_compact_ascii_key_order_and_unicode_value_are_stable(self) -> None:
        self.assertEqual(
            canonical.canonical_json_bytes({"z": [None, True, 1], "a": "Привет"}),
            '{"a":"Привет","z":[null,true,1]}'.encode(),
        )

    def test_nonportable_scalar_values_are_rejected(self) -> None:
        for value in (
            1.0,
            math.nan,
            math.inf,
            canonical.MAX_SAFE_INTEGER + 1,
            -canonical.MAX_SAFE_INTEGER - 1,
            b"bytes",
        ):
            with (
                self.subTest(value=value),
                self.assertRaises(canonical.CanonicalJsonError),
            ):
                canonical.canonical_json_bytes({"value": value})

    def test_non_ascii_empty_and_non_string_keys_are_rejected(self) -> None:
        for payload in ({1: "value"}, {"": "value"}, {"é": "value"}):
            with (
                self.subTest(payload=payload),
                self.assertRaises(canonical.CanonicalJsonError),
            ):
                canonical.canonical_json_bytes(payload)

    def test_surrogates_are_rejected_but_astral_scalars_are_stable(self) -> None:
        for value in ("\ud800", "\udfff", ["ok", "\udc00"]):
            with (
                self.subTest(value=value),
                self.assertRaises(canonical.CanonicalJsonError),
            ):
                canonical.canonical_json_bytes({"value": value})
        self.assertEqual(
            canonical.canonical_json_bytes({"value": "😀"}),
            '{"value":"😀"}'.encode(),
        )

    def test_depth_and_collection_limits_are_closed(self) -> None:
        nested: dict = {}
        cursor = nested
        for _ in range(canonical.MAX_DEPTH + 1):
            cursor["next"] = {}
            cursor = cursor["next"]
        for payload in (
            nested,
            {"items": [None] * (canonical.MAX_SEQUENCE_ITEMS + 1)},
            {f"k{index}": None for index in range(canonical.MAX_MAPPING_ENTRIES + 1)},
        ):
            with (
                self.subTest(size=len(payload)),
                self.assertRaises(canonical.CanonicalJsonError),
            ):
                canonical.canonical_json_bytes(payload)


if __name__ == "__main__":
    unittest.main()
