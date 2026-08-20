"""Dispatch, locator and fresh broker activation preflight tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.evidence import release_controller_activation_proof as proof_contract
from tools.evidence.release_canonical import canonical_json_bytes
from tools.evidence.release_controller_preflight import (
    DispatchSelectors,
    ProductionPreflightError,
    evaluate,
    load_activation_contract,
    require_controller_identity,
    require_live_activation,
)
from tests.release_controller_preflight_fixtures import (
    CONFIG_PATH,
    CONTROLLER_REF,
    FakeActivationClient,
    FrozenClock,
    WORKFLOW_SHA,
    config as _config,
    digest as _digest,
    environment as _environment,
    proof_exchange as _proof_exchange,
    selectors as _selectors,
    temporary_config as _temporary_config,
    verify_exchange as _verify_exchange,
)


class ReleaseControllerPreflightTests(unittest.TestCase):
    def test_checked_in_locator_allows_dry_run_but_cannot_activate_live(self) -> None:
        selectors, contract, controller, proof = evaluate(
            config_path=CONFIG_PATH,
            selectors=_selectors(),
            environ=_environment(),
        )
        self.assertEqual(selectors.mode, "dry-run")
        self.assertFalse(contract.locator_ready)
        self.assertEqual(controller.workflow_sha, WORKFLOW_SHA)
        self.assertIsNone(proof)

        with self.assertRaisesRegex(
            ProductionPreflightError,
            "PUBLIC_CLOSURE_CONTRACT_NOT_FROZEN",
        ):
            evaluate(
                config_path=CONFIG_PATH,
                selectors=_selectors(mode="live"),
                environ=_environment(),
            )

    def test_live_admission_is_held_before_broker_exchange(self) -> None:
        config = _config()
        config["credential_broker"]["endpoint"] = "https://broker.example.test"
        client = FakeActivationClient(_proof_exchange())
        with _temporary_config(config) as path:
            with self.assertRaisesRegex(
                ProductionPreflightError,
                "PUBLIC_CLOSURE_CONTRACT_NOT_FROZEN",
            ):
                evaluate(
                    config_path=path,
                    selectors=_selectors(mode="live"),
                    environ=_environment(),
                    activation_client=client,
                    clock=FrozenClock(),
                )
        self.assertEqual(client.calls, [])

    def test_direct_live_helper_is_held_before_broker_exchange(self) -> None:
        config = _config()
        config["credential_broker"]["endpoint"] = "https://broker.example.test"
        client = FakeActivationClient(_proof_exchange())
        with _temporary_config(config) as path:
            contract = load_activation_contract(path)
            controller = require_controller_identity(_environment())
            with self.assertRaisesRegex(
                ProductionPreflightError,
                "PUBLIC_CLOSURE_CONTRACT_NOT_FROZEN",
            ):
                require_live_activation(
                    contract,
                    controller=controller,
                    client=client,
                    clock=FrozenClock(),
                )
        self.assertEqual(client.calls, [])

    def test_forged_flags_markers_or_config_booleans_cannot_activate(self) -> None:
        forged_environment = {
            **_environment(),
            "DPONE_RELEASE_ACTIVATION_MARKER": "forged",
            "DPONE_RELEASE_ACTIVATION_COMMIT_SHA": WORKFLOW_SHA,
            "DPONE_RELEASE_LIVE_MUTATION_ENABLED": "true",
        }
        with self.assertRaisesRegex(
            ProductionPreflightError,
            "PUBLIC_CLOSURE_CONTRACT_NOT_FROZEN",
        ):
            evaluate(
                config_path=CONFIG_PATH,
                selectors=_selectors(mode="live"),
                environ=forged_environment,
            )
        for key, value in (
            ("state", "active"),
            ("live_mutation_enabled", True),
            ("provider_prerequisites", {"everything": True}),
        ):
            config = _config()
            config[key] = value
            with self.subTest(key=key), _temporary_config(config) as path:
                with self.assertRaisesRegex(ProductionPreflightError, "unexpected"):
                    load_activation_contract(path)

    def test_only_exact_seven_dispatch_inputs_are_accepted(self) -> None:
        cases = (
            {**_selectors(), "repository": "PaulKov/dpone"},
            {
                key: value
                for key, value in _selectors().items()
                if key != "candidate_artifact_id"
            },
        )
        for selectors in cases:
            with self.assertRaisesRegex(ProductionPreflightError, "keys are not exact"):
                DispatchSelectors.from_mapping(selectors)

    def test_stable_tag_and_ascii_selector_syntax_are_closed(self) -> None:
        invalid = (
            {"tag": "v0.74.0-rc.1"},
            {"tag": "v0.74.0+build"},
            {"tag": "v01.74.0"},
            {"candidate_run_id": "+1"},
            {"candidate_run_id": "١"},
            {"candidate_run_attempt": "0"},
            {"candidate_artifact_id": "9007199254740992"},
            {"candidate_artifact_digest": "b" * 64},
            {"expected_peeled_commit_sha": "B" * 40},
        )
        for replacement in invalid:
            with self.subTest(replacement=replacement):
                with self.assertRaises(ProductionPreflightError):
                    DispatchSelectors.from_mapping({**_selectors(), **replacement})

    def test_controller_workflow_and_run_identity_are_not_selectable(self) -> None:
        mutations = {
            "GITHUB_REPOSITORY": "PaulKov/dpone",
            "GITHUB_REPOSITORY_ID": "1255975556",
            "GITHUB_REPOSITORY_OWNER_ID": "1",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/feature",
            "GITHUB_WORKFLOW_REF": (
                "PaulKov/dpone-release-controller/.github/workflows/ci.yml@refs/heads/master"
            ),
            "GITHUB_SHA": "A" * 40,
            "GITHUB_RUN_ATTEMPT": "١",
            "GITHUB_RUN_ID": "9007199254740992",
        }
        for key, value in mutations.items():
            with self.subTest(key=key):
                with self.assertRaises(ProductionPreflightError):
                    evaluate(
                        config_path=CONFIG_PATH,
                        selectors=_selectors(),
                        environ={**_environment(), key: value},
                    )

    def test_recovery_tag_remains_valid_after_master_advances(self) -> None:
        environment = {**_environment(), "CONTROLLER_MASTER_SHA": "9" * 40}
        _, _, controller, _ = evaluate(
            config_path=CONFIG_PATH,
            selectors=_selectors(),
            environ=environment,
        )
        self.assertEqual(controller.ref, CONTROLLER_REF)
        self.assertEqual(controller.workflow_sha, WORKFLOW_SHA)

    def test_deleted_default_branch_workflow_path_blocks_recovery(self) -> None:
        exchange = _proof_exchange()
        body = json.loads(exchange.response_bytes)
        del body["controller"]["default_branch_workflow_blob_sha"]
        del body["proof_sha256"]
        body["proof_sha256"] = _digest(canonical_json_bytes(body))
        client = FakeActivationClient(
            proof_contract.BrokerActivationExchange(
                request_id=exchange.request_id,
                response_bytes=canonical_json_bytes(body),
            )
        )
        with self.assertRaisesRegex(
            proof_contract.ActivationProofError,
            "keys are not exact",
        ):
            _verify_exchange(client.exchange)

    def test_default_branch_blob_is_bound_but_target_policy_epoch_is_reusable(
        self,
    ) -> None:
        exchange = _proof_exchange()
        body = json.loads(exchange.response_bytes)
        body["controller"]["default_branch_workflow_blob_sha"] = "2" * 40
        del body["proof_sha256"]
        body["proof_sha256"] = _digest(canonical_json_bytes(body))
        client = FakeActivationClient(
            proof_contract.BrokerActivationExchange(
                request_id=exchange.request_id,
                response_bytes=canonical_json_bytes(body),
            )
        )
        with self.assertRaises(proof_contract.ActivationProofError):
            _verify_exchange(client.exchange)

        reusable = json.loads(_proof_exchange().response_bytes)
        reusable["activated"]["target_policy_commit_sha"] = "8" * 40
        del reusable["proof_sha256"]
        reusable["proof_sha256"] = _digest(canonical_json_bytes(reusable))
        client = FakeActivationClient(
            proof_contract.BrokerActivationExchange(
                request_id=exchange.request_id,
                response_bytes=canonical_json_bytes(reusable),
            )
        )
        verified = _verify_exchange(client.exchange)
        self.assertEqual(verified.target_policy_commit_sha, "8" * 40)

    def test_commit_a_is_distinct_from_p_and_exact_across_a0_a1(self) -> None:
        cases = (
            ("provisioned", "controller_action_commit_sha", WORKFLOW_SHA),
            ("activated", "controller_action_commit_sha", "7" * 40),
            ("activated", "controller_action_metadata_blob_sha", "6" * 40),
            ("activated", "controller_action_bundle_sha256", _digest(b"drift")),
        )
        for owner, key, value in cases:
            exchange = _proof_exchange()
            body = json.loads(exchange.response_bytes)
            body[owner][key] = value
            del body["proof_sha256"]
            body["proof_sha256"] = _digest(canonical_json_bytes(body))
            client = FakeActivationClient(
                proof_contract.BrokerActivationExchange(
                    request_id=exchange.request_id,
                    response_bytes=canonical_json_bytes(body),
                )
            )
            with self.subTest(owner=owner, key=key):
                with self.assertRaises(proof_contract.ActivationProofError):
                    _verify_exchange(client.exchange)

    def test_broker_locator_audiences_and_proof_schema_are_exact(self) -> None:
        cases = []
        audience = _config()
        audience["credential_broker"]["audiences"]["candidate_read"] = (
            "dpone-release-controller-artifact-read"
        )
        cases.append(audience)
        query = _config()
        query["credential_broker"]["endpoint"] = (
            "https://broker.example.test?override=true"
        )
        cases.append(query)
        schema = _config()
        schema["credential_broker"]["activation_response_schema"] = "open.v1"
        cases.append(schema)
        for config in cases:
            with _temporary_config(config) as path:
                with self.assertRaises(ProductionPreflightError):
                    load_activation_contract(path)

    def test_worm_retention_and_candidate_shape_cannot_be_weakened(self) -> None:
        mutations = (
            ("ledger", "mirror_retention_days", 365),
            ("ledger", "writer_can_change_retention", True),
            ("candidate_handoff", "expected_file_count", 26),
            ("candidate_handoff", "max_artifact_member_bytes", 1_000_000_000),
            ("candidate_handoff", "max_distribution_file_bytes", 100_000_001),
            ("candidate_handoff", "max_distribution_total_bytes", 536_870_913),
            (
                "candidate_handoff",
                "manifest_schema_sha256",
                "sha256:" + "f" * 64,
            ),
        )
        for section, key, value in mutations:
            with self.subTest(section=section, key=key):
                config = _config()
                config[section][key] = value
                with _temporary_config(config) as path:
                    with self.assertRaises(ProductionPreflightError):
                        load_activation_contract(path)

    def test_duplicate_or_extension_config_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            duplicate = Path(directory) / "duplicate.json"
            text = CONFIG_PATH.read_text()
            duplicate.write_text(
                text.replace(
                    '"schema_version": 2,',
                    '"schema_version": 2,\n  "schema_version": 2,',
                )
            )
            with self.assertRaisesRegex(ProductionPreflightError, "duplicate JSON key"):
                load_activation_contract(duplicate)
        config = _config()
        config["repository"] = "override"
        with _temporary_config(config) as path:
            with self.assertRaisesRegex(ProductionPreflightError, "unexpected"):
                load_activation_contract(path)


if __name__ == "__main__":
    unittest.main()
