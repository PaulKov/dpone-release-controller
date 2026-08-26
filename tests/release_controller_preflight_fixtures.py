"""Owned, reusable fixtures for controller activation preflight tests."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from tools.evidence import release_controller_action_bundle as action_bundle
from tools.evidence import release_controller_activation_proof as proof_contract
from tools.evidence.release_canonical import canonical_json_bytes

CONFIG_PATH = Path("config/release-controller-v2.json")
WORKFLOW_SHA = "a" * 40
ACTION_SHA = "9" * 40
ACTION_BLOBS = {
    path: f"reviewed Commit-A executable: {path}\n".encode()
    for path in action_bundle.EXECUTABLE_PATHS
}
ACTION_DOCUMENT = action_bundle.document(commit_sha=ACTION_SHA, blobs=ACTION_BLOBS)
ACTION_METADATA_BLOB_SHA = action_bundle.runtime_closure_metadata_blob_sha(
    ACTION_DOCUMENT, blobs=ACTION_BLOBS
)
ACTION_BUNDLE_SHA256 = action_bundle.bundle_sha256(ACTION_DOCUMENT, blobs=ACTION_BLOBS)
CONTROLLER_TAG_SHA = "f" * 40
CONTROLLER_REF = "refs/tags/v2.0.0"
NOW = datetime(2026, 8, 15, 0, 0, 30, tzinfo=timezone.utc)


class FrozenClock:
    """Deterministic clock for freshness and recovery tests."""

    def now(self) -> datetime:
        return NOW


class FakeActivationClient:
    """Record exact broker requests and return one frozen exchange."""

    def __init__(self, exchange: proof_contract.BrokerActivationExchange) -> None:
        self.exchange = exchange
        self.calls: list[dict] = []

    def request_activation_proof(self, **values):
        self.calls.append(values)
        return self.exchange


def selectors(*, mode: str = "dry-run") -> dict[str, str]:
    """Return the only accepted seven immutable dispatch selectors."""

    return {
        "mode": mode,
        "tag": "v0.74.0",
        "expected_peeled_commit_sha": "b" * 40,
        "candidate_run_id": "31900000001",
        "candidate_run_attempt": "1",
        "candidate_artifact_id": "9300000001",
        "candidate_artifact_digest": "sha256:" + ("c" * 64),
    }


def environment() -> dict[str, str]:
    """Return the immutable controller workflow identity."""

    return {
        "GITHUB_REPOSITORY": "PaulKov/dpone-release-controller",
        "GITHUB_REPOSITORY_ID": "1305993853",
        "GITHUB_REPOSITORY_OWNER_ID": "74862786",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/tags/v2.0.0",
        "GITHUB_WORKFLOW_REF": (
            "PaulKov/dpone-release-controller/.github/workflows/"
            "release-controller.yml@refs/tags/v2.0.0"
        ),
        "GITHUB_SHA": WORKFLOW_SHA,
        "GITHUB_RUN_ID": "123456789",
        "GITHUB_RUN_ATTEMPT": "2",
    }


def proof_exchange() -> proof_contract.BrokerActivationExchange:
    """Build the canonical fresh A0/A1 broker proof exchange."""

    request_id = "request-01HXDPONE"
    body = {
        "schema": "dpone.release-broker-activation-proof.v1",
        "schema_version": 1,
        "request_id": request_id,
        "controller": {
            "repository_id": 1_305_993_853,
            "workflow_id": 316_322_127,
            "workflow_sha": WORKFLOW_SHA,
            "workflow_ref": (
                "PaulKov/dpone-release-controller/.github/workflows/"
                f"release-controller.yml@{CONTROLLER_REF}"
            ),
            "ref": CONTROLLER_REF,
            "ref_type": "tag",
            "tag_object_sha": CONTROLLER_TAG_SHA,
            "default_branch_ref": "refs/heads/master",
            "default_branch_workflow_blob_sha": "c" * 40,
            "default_branch_workflow_observation_sha256": digest(
                b"default branch workflow observation"
            ),
            "run_id": 123_456_789,
            "run_attempt": 2,
        },
        "provisioned": {
            "record_id": digest(b"A0"),
            "digest": digest(b"A0 bytes"),
            "worker_version_id": "worker-version-001",
            "worm_version_id": "b2-version-001",
            "controller_workflow_commit_sha": WORKFLOW_SHA,
            "controller_workflow_blob_sha": "c" * 40,
            "controller_action_commit_sha": ACTION_SHA,
            "controller_action_metadata_blob_sha": ACTION_METADATA_BLOB_SHA,
            "controller_action_bundle_sha256": ACTION_BUNDLE_SHA256,
            "controller_workflow_id": 316_322_127,
            "controller_ref": CONTROLLER_REF,
            "controller_ref_type": "tag",
            "controller_tag_object_sha": CONTROLLER_TAG_SHA,
            "controller_peeled_commit_sha": WORKFLOW_SHA,
        },
        "activated": {
            "record_id": digest(b"A1"),
            "digest": digest(b"A1 bytes"),
            "previous": digest(b"A0"),
            "target_policy_commit_sha": "b" * 40,
            "target_policy_sha256": digest(b"policy"),
            "target_policy_blob_sha": "d" * 40,
            "controller_action_commit_sha": ACTION_SHA,
            "controller_action_metadata_blob_sha": ACTION_METADATA_BLOB_SHA,
            "controller_action_bundle_sha256": ACTION_BUNDLE_SHA256,
            "worm_version_id": "b2-version-002",
        },
        "admitted_at": "2026-08-15T00:00:00Z",
        "expires_at": "2026-08-15T00:01:00Z",
    }
    body["proof_sha256"] = digest(canonical_json_bytes(body))
    return proof_contract.BrokerActivationExchange(
        request_id=request_id,
        response_bytes=canonical_json_bytes(body),
    )


def verify_exchange(
    exchange: proof_contract.BrokerActivationExchange,
) -> proof_contract.ActivationProof:
    """Verify a fixture exchange without crossing the public live HOLD boundary."""

    return proof_contract.verify_exchange(
        exchange,
        expected=proof_contract.ExpectedControllerRun(
            repository_id=1_305_993_853,
            ref=CONTROLLER_REF,
            workflow_ref=(
                "PaulKov/dpone-release-controller/.github/workflows/"
                f"release-controller.yml@{CONTROLLER_REF}"
            ),
            workflow_sha=WORKFLOW_SHA,
            run_id=123_456_789,
            run_attempt=2,
        ),
        clock=FrozenClock(),
    )


def config() -> dict:
    """Load a fresh mutable copy of the checked-in HOLD config."""

    return json.loads(CONFIG_PATH.read_text())


class temporary_config:
    """Install one temporary canonical config for a single test scope."""

    def __init__(self, value: dict) -> None:
        self._config = copy.deepcopy(value)
        self._temporary: tempfile.TemporaryDirectory | None = None

    def __enter__(self) -> Path:
        self._temporary = tempfile.TemporaryDirectory()
        path = Path(self._temporary.name) / "activation.json"
        path.write_text(json.dumps(self._config, indent=2, sort_keys=True) + "\n")
        return path

    def __exit__(self, *_: object) -> None:
        assert self._temporary is not None
        self._temporary.cleanup()


def digest(data: bytes) -> str:
    """Return the canonical prefixed SHA-256 digest."""

    return "sha256:" + hashlib.sha256(data).hexdigest()
