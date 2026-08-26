"""Operation-v2 workflow AST and Commit-A dataflow tests."""

from __future__ import annotations

import unittest

from tools.evidence.release_controller_workflow_ast import (
    WorkflowAstError,
    verify,
    verify_runtime,
)
from tools.evidence.release_controller_workflow_contract import (
    CONTROLLER_PERMISSIONS,
    CONTROLLER_RUNNER,
    DISPATCH_CONTRACT,
    FINAL_IF,
    expected_if,
    expected_needs,
    expected_outputs,
    expected_step,
    required_jobs,
)

ACTION_COMMIT = "a" * 40
ACTION_METADATA_BLOB = "b" * 40
ACTION_BUNDLE = "sha256:" + "c" * 64


class WorkflowAstTests(unittest.TestCase):
    def test_exact_operation_v2_job_graph_is_accepted(self) -> None:
        workflow = _controller_workflow()
        verify(workflow, broker_action_commit=ACTION_COMMIT)
        sentinel = workflow["jobs"]["lease-renew"]["steps"][0]["with"]
        self.assertEqual(sentinel["renew_interval_seconds"], "45")
        self.assertEqual(sentinel["lease_ttl_seconds"], "300")
        self.assertIn("draft-stage", workflow["jobs"])
        self.assertNotIn("draft-intent", workflow["jobs"])

    def test_release_cleanup_and_recovery_entrypoints_are_mutually_exclusive(
        self,
    ) -> None:
        workflow = _controller_workflow()
        self.assertEqual(workflow["jobs"]["recovery-lease-acquire"]["needs"], [])
        self.assertEqual(
            workflow["jobs"]["recovery-lease-acquire"]["if"],
            "${{ inputs.operation == 'recovery' }}",
        )
        self.assertEqual(
            workflow["jobs"]["cancel"]["needs"],
            ["lease-acquire", "close"],
        )
        self.assertIn("inputs.operation == 'release'", workflow["jobs"]["cancel"]["if"])
        self.assertEqual(workflow["jobs"]["controller-complete"]["if"], FINAL_IF)
        self.assertTrue(workflow["jobs"]["controller-complete"]["steps"])
        workflow["jobs"]["cancel"]["if"] = "${{ always() }}"
        with self.assertRaises(WorkflowAstError):
            verify(workflow, broker_action_commit=ACTION_COMMIT)

    def test_environment_dependencies_permissions_and_job_set_fail_closed(self) -> None:
        mutations = (
            ("environment", "pypi"),
            ("name", "duplicate display name"),
            ("permissions", {"contents": "read", "id-token": "write"}),
            ("needs", ["admit"]),
        )
        for key, value in mutations:
            workflow = _controller_workflow()
            workflow["jobs"]["draft-stage"][key] = value
            with self.subTest(key=key), self.assertRaises(WorkflowAstError):
                verify(workflow, broker_action_commit=ACTION_COMMIT)
        workflow = _controller_workflow()
        workflow["jobs"]["unreviewed-helper"] = {"steps": [{"run": "true"}]}
        with self.assertRaisesRegex(WorkflowAstError, "job set"):
            verify(workflow, broker_action_commit=ACTION_COMMIT)

    def test_exact_external_action_order_and_commit_a_pins_are_enforced(self) -> None:
        workflow = _controller_workflow()
        workflow["jobs"]["pypi-publish"]["steps"].reverse()
        with self.assertRaisesRegex(WorkflowAstError, "codec/order"):
            verify(workflow, broker_action_commit=ACTION_COMMIT)

        workflow = _controller_workflow()
        workflow["jobs"]["admit"]["steps"][0]["uses"] = (
            "PaulKov/dpone-release-controller/actions/broker-call@main"
        )
        with self.assertRaisesRegex(WorkflowAstError, "codec/order"):
            verify(workflow, broker_action_commit=ACTION_COMMIT)

    def test_public_closure_jobs_and_cross_job_hints_are_absent(self) -> None:
        workflow = _controller_workflow()
        held = {
            "closed-check-intent",
            "closed-check-project",
            "closed-check-verify",
            "closure-artifact-upload",
            "closure-artifact-verify",
        }
        self.assertTrue(held.isdisjoint(workflow["jobs"]))
        self.assertFalse(
            any(
                "closure-artifact" in str(job.get("outputs", {}))
                for job in workflow["jobs"].values()
            )
        )
        verify(workflow, broker_action_commit=ACTION_COMMIT)

    def test_caller_selected_authority_aliases_and_run_steps_are_rejected(self) -> None:
        cases = (
            ("origin", "https://attacker.invalid"),
            ("request_json", "{}"),
            ("token", "secret"),
        )
        for key, value in cases:
            workflow = _controller_workflow()
            workflow["jobs"]["draft-stage"]["steps"][0]["with"][key] = value
            with self.subTest(key=key), self.assertRaises(WorkflowAstError):
                verify(workflow, broker_action_commit=ACTION_COMMIT)
        workflow = _controller_workflow()
        workflow["jobs"]["draft-stage"]["steps"].append(
            {"run": "curl https://attacker.invalid"}
        )
        with self.assertRaises(WorkflowAstError):
            verify(workflow, broker_action_commit=ACTION_COMMIT)

    def test_runtime_workflow_gate_is_unconditionally_held(self) -> None:
        for workflow in ({}, {"jobs": {}}, {"jobs": {"promote-certified-image": {}}}):
            with (
                self.subTest(workflow=workflow),
                self.assertRaisesRegex(
                    WorkflowAstError,
                    "PUBLIC_CLOSURE_CONTRACT_NOT_FROZEN",
                ),
            ):
                verify_runtime(
                    workflow,
                    target_workflow_path=".github/workflows/runtime-image.yml",
                    target_workflow_commit_sha="f" * 40,
                    controller_action_commit_sha=ACTION_COMMIT,
                    controller_action_metadata_blob_sha=ACTION_METADATA_BLOB,
                    controller_action_bundle_sha256=ACTION_BUNDLE,
                )


def _controller_workflow() -> dict:
    jobs = {}
    for job_name, contract in required_jobs().items():
        job = {
            "name": job_name,
            "environment": contract.environment,
            "if": expected_if(contract.operation_id),
            "needs": list(expected_needs(job_name, contract.operation_id)),
            "permissions": dict(CONTROLLER_PERMISSIONS),
            "runs-on": CONTROLLER_RUNNER,
            "timeout-minutes": contract.timeout_minutes,
            "steps": [expected_step(codec, ACTION_COMMIT) for codec in contract.codecs],
        }
        outputs = expected_outputs(job_name)
        if outputs:
            job["outputs"] = outputs
        jobs[job_name] = job
    return {
        "name": "Release controller",
        "on": DISPATCH_CONTRACT,
        "permissions": {},
        "jobs": jobs,
    }


if __name__ == "__main__":
    unittest.main()
