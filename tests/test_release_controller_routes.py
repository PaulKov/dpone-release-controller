"""Parity tests for the single controller broker route profile."""

from __future__ import annotations

import unittest
from pathlib import Path

from tests.release_receipt_fixtures import all_payloads
from tools.evidence import release_controller_routes as routes
from tools.evidence import release_receipt_payload_state_contract as state_contract
from tools.evidence.release_controller_route_vectors import encoded

FIXTURE = Path("tests/fixtures/release-controller-route-profile-v1.json")


class ReleaseControllerRoutesTests(unittest.TestCase):
    def test_fixture_is_current_and_only_executable_payloads_have_routes(self) -> None:
        self.assertEqual(FIXTURE.read_bytes(), encoded())
        for payload in all_payloads():
            selector = routes.selector_for(payload)
            if selector in routes.HELD_PUBLIC_CLOSURE_SELECTORS:
                with (
                    self.subTest(selector=selector),
                    self.assertRaises(routes.contract.ReceiptValidationError),
                ):
                    routes.profile_for(payload)
            else:
                profile = routes.profile_for(payload)
                self.assertEqual(profile.receipt_type, payload["kind"])

    def test_each_github_job_has_one_immutable_environment(self) -> None:
        environments: dict[str, set[str]] = {}
        for route in routes.ROUTES:
            if route.requester_kind != "github_actions_job":
                continue
            assert route.job_name is not None and route.environment is not None
            environments.setdefault(route.job_name, set()).add(route.environment)
        self.assertTrue(environments)
        self.assertTrue(all(len(values) == 1 for values in environments.values()))
        self.assertNotIn("draft-intent", environments)
        self.assertNotIn("draft-stage", environments)
        self.assertNotIn("draft-verify", environments)
        self.assertEqual(environments["attest-create"], {"release-attest"})
        self.assertEqual(environments["lease-acquire"], {"release-attest"})
        self.assertEqual(environments["lease-renew"], {"release-attest"})
        self.assertEqual(environments["controller-complete"], {"release-attest"})
        self.assertEqual(environments["pypi-publish"], {"pypi"})
        self.assertEqual(environments["pypi-observe"], {"release-attest"})

    def test_route_states_equal_the_closed_payload_schema_union(self) -> None:
        self.assertEqual(
            {
                route.selector: route.receipt_states
                for route in routes.ROUTES
                if route.receipt_type is not None
            },
            {
                selector: states
                for selector, states in state_contract.STATES_BY_SELECTOR.items()
            },
        )

    def test_intent_and_provider_result_jobs_are_not_aliases(self) -> None:
        pairs = (
            ("attest-create", "attest-verify"),
            ("github-publish-intent", "github-publish"),
        )
        jobs = {route.job_name for route in routes.ROUTES if route.job_name}
        for left, right in pairs:
            with self.subTest(left=left, right=right):
                self.assertIn(left, jobs)
                self.assertIn(right, jobs)
                self.assertNotEqual(left, right)

    def test_read_only_verifiers_and_scanner_have_no_mutation_authority(self) -> None:
        expected = {
            "GITHUB_RELEASE_TRANSITION:IMMUTABLE_VERIFIED": (
                "release-attest",
                routes.GOVERNANCE,
            ),
            "TENANT_HYGIENE_VERIFIED": ("release-attest", routes.LEDGER),
        }
        for selector, authority in expected.items():
            with self.subTest(selector=selector):
                profile = routes.ROUTE_BY_SELECTOR[selector]
                self.assertEqual((profile.environment, profile.audience), authority)
                self.assertNotEqual(profile.audience, routes.GITHUB)
                self.assertNotEqual(profile.audience, routes.CANDIDATE)
        draft_verified = routes.ROUTE_BY_SELECTOR["DRAFT_TRANSITION:VERIFIED"]
        self.assertEqual(draft_verified.requester_kind, "trusted_controller_service")
        self.assertIsNone(draft_verified.environment)
        self.assertIsNone(draft_verified.audience)

    def test_public_closure_selectors_have_no_executable_route(self) -> None:
        self.assertTrue(routes.HELD_PUBLIC_CLOSURE_SELECTORS)
        self.assertTrue(
            routes.HELD_PUBLIC_CLOSURE_SELECTORS.isdisjoint(routes.ROUTE_BY_SELECTOR)
        )

    def test_draft_receipts_are_internal_durable_service_authority(self) -> None:
        draft = [
            route
            for route in routes.ROUTES
            if "GITHUB_DRAFT_" in route.selector
            or route.selector.startswith("DRAFT_TRANSITION:")
        ]
        self.assertEqual(len(draft), 10)
        self.assertTrue(
            all(route.requester_kind == "trusted_controller_service" for route in draft)
        )
        self.assertTrue(all(route.job_name is None for route in draft))

    def test_attestation_mutation_is_split_from_provider_verification(self) -> None:
        consume = routes.ROUTE_BY_SELECTOR[
            "MUTATION_INTENT_CONSUMED:ATTESTATION_CREATE"
        ]
        verify_profile = routes.ROUTE_BY_SELECTOR["ATTESTATION_VERIFIED"]
        self.assertEqual(consume.job_name, "attest-create")
        self.assertEqual(
            consume.path,
            "/v1/releases/intents/attestation-create/consume",
        )
        self.assertEqual(consume.receipt_type, "MUTATION_INTENT_CONSUMED")
        self.assertEqual(verify_profile.job_name, "attest-verify")
        self.assertEqual(
            verify_profile.path,
            "/v1/releases/events/attestation-verified/admit",
        )

    def test_candidate_stream_and_broker_authored_admit_are_distinct(self) -> None:
        source = routes.ROUTE_BY_SELECTOR["CANDIDATE_SOURCE"]
        admit = routes.ROUTE_BY_SELECTOR["CANDIDATE_HANDOFF"]
        self.assertIsNone(source.receipt_type)
        self.assertEqual(source.audience, routes.CANDIDATE)
        self.assertEqual(source.path, "/v1/providers/github/candidate")
        self.assertEqual(admit.receipt_type, "CANDIDATE_HANDOFF")
        self.assertEqual(admit.audience, routes.LEDGER)
        self.assertEqual(admit.path, "/v1/releases/candidate/admit")

    def test_already_published_exact_uses_recovery_only_job(self) -> None:
        profile = routes.ROUTE_BY_SELECTOR[
            "PYPI_FILE_TRANSITION:ALREADY_PUBLISHED_EXACT"
        ]
        self.assertEqual(profile.job_name, "pypi-recovery-observe")

    def test_pypi_upload_mutation_has_one_consumed_set_authority(self) -> None:
        consume = routes.ROUTE_BY_SELECTOR[
            "MUTATION_INTENT_CONSUMED:PYPI_FILE_UPLOAD_SET"
        ]
        observed = routes.ROUTE_BY_SELECTOR["PYPI_UPLOAD_SET_OBSERVED"]
        self.assertEqual(
            (consume.job_name, consume.environment, consume.audience, consume.path),
            (
                "pypi-publish",
                "pypi",
                routes.PYPI,
                "/v1/releases/intents/pypi-file-upload-set/consume",
            ),
        )
        self.assertEqual(
            (observed.job_name, observed.environment, observed.audience),
            ("pypi-observe", "release-attest", routes.LEDGER),
        )
        self.assertNotIn(
            "PYPI_FILE_TRANSITION:UPLOAD_ACCEPTED", routes.ROUTE_BY_SELECTOR
        )

    def test_expiry_is_a_broker_timer_not_a_workflow_claim(self) -> None:
        profile = routes.ROUTE_BY_SELECTOR["LEASE_EXPIRED"]
        self.assertEqual(profile.requester_kind, "release_authority_broker_timer")
        self.assertEqual(profile.method, "INTERNAL")
        self.assertIsNone(profile.job_name)
        self.assertIsNone(profile.audience)


if __name__ == "__main__":
    unittest.main()
