"""Static typed route table collision and fail-closed tests."""

from __future__ import annotations

import unittest

from tools.evidence import release_controller_typed_routes as typed


class ReleaseControllerTypedRouteTests(unittest.TestCase):
    def test_every_path_roundtrips_through_the_static_table(self) -> None:
        for selector, row in typed.ROUTES_BY_SELECTOR.items():
            with self.subTest(selector=selector):
                self.assertEqual(typed.by_selector(selector), row)
                self.assertIn(row, typed.by_path(row.path))
                self.assertRegex(row.path, r"\A/[a-z0-9/-]+\Z")
                self.assertNotIn("_", row.path)
                self.assertNotIn(":", row.path)
        grouped = typed.by_path("/v1/releases/pypi/prepare")
        self.assertEqual(
            {row.selector for row in grouped},
            {
                "MUTATION_INTENT:PYPI_FILE_UPLOAD_SET",
                "PYPI_FILE_TRANSITION:PENDING_UPLOAD",
                "PYPI_FILE_TRANSITION:SEALED_FOR_UPLOAD",
            },
        )

    def test_generic_append_intent_and_unknown_paths_are_absent(self) -> None:
        forbidden = {
            "/v1/receipts/append",
            "/v1/intents/issue",
            "/v1/intents/consume",
            "/v1/runtime/closure",
            "/v1/releases/closed-check/finalize",
            "/v1/releases/closed-check/project",
            "/v1/releases/closure/materialize",
        }
        self.assertFalse(forbidden.intersection(typed.BY_PATH))
        for value in (
            "/v1/releases/events/unknown/admit",
            "/v1/releases/intents/unknown/issue",
            "/v1/releases/events/CLOSED/admit",
        ):
            with self.subTest(path=value), self.assertRaises(typed.TypedRouteError):
                typed.by_path(value)


if __name__ == "__main__":
    unittest.main()
