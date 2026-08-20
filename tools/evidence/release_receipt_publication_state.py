"""Exact candidate, PyPI, draft, and immutable-release inventory state."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from tools.evidence import release_receipt_contract as contract
from tools.evidence import release_receipt_inventory as inventory


@dataclass(slots=True)
class PublicationState:
    """Cross-bind provider transitions to the imported closed inventories."""

    candidate_id: str | None = None
    distributions: dict[tuple[str, str, str], dict[str, Any]] = field(
        default_factory=dict
    )
    distribution_inventory_sha256: str | None = None
    expected_assets: dict[str, dict[str, Any]] = field(default_factory=dict)
    expected_asset_inventory_sha256: str | None = None
    expected_asset_count: int = 0
    public_bundle_manifest_sha256: str | None = None
    release_id: int | None = None
    release_body_sha256: str | None = None
    uploaded_assets: dict[str, dict[str, Any]] = field(default_factory=dict)
    pypi_files: dict[tuple[str, str, str], str] = field(default_factory=dict)
    pypi_verified_count: int = 0
    immutable_release_verified: bool = False

    def bind_candidate(self, payload: Mapping[str, Any]) -> None:
        records = inventory.distribution_inventory(payload["distribution_inventory"])
        inventory.require_digest(
            payload["distribution_inventory_sha256"],
            inventory.DISTRIBUTION_SCHEMA,
            records,
            "distribution_inventory_sha256",
        )
        self.candidate_id = payload["candidate_id"]
        self.distribution_inventory_sha256 = payload["distribution_inventory_sha256"]
        self.distributions = {
            (item["project"], item["version"], item["filename"]): dict(item)
            for item in records
        }

    def bind_public_bundle(self, payload: Mapping[str, Any]) -> None:
        self._equal(payload["candidate_id"], self.candidate_id, "bundle candidate")
        records = inventory.github_asset_inventory(
            payload["release_asset_inventory"],
            expected_count=payload["expected_asset_count"],
        )
        inventory.require_digest(
            payload["expected_asset_inventory_sha256"],
            inventory.GITHUB_ASSET_SCHEMA,
            records,
            "expected_asset_inventory_sha256",
        )
        self.expected_assets = {item["name"]: dict(item) for item in records}
        self.expected_asset_count = len(records)
        self.expected_asset_inventory_sha256 = payload[
            "expected_asset_inventory_sha256"
        ]
        self.public_bundle_manifest_sha256 = payload["manifest_sha256"]

    def bind_draft(self, payload: Mapping[str, Any]) -> None:
        self._equal(payload["candidate_id"], self.candidate_id, "draft candidate")
        self._equal(
            payload["public_bundle_manifest_sha256"],
            self.public_bundle_manifest_sha256,
            "draft public bundle",
        )
        transition = payload["transition"]
        if transition == "CREATED":
            self.release_id = payload["release_id"]
            self.release_body_sha256 = payload["release_body_sha256"]
            return
        self._equal(payload["release_id"], self.release_id, "draft release ID")
        if transition == "ASSET_UPLOADED":
            self._bind_uploaded_asset(payload["asset"])
            return
        self._equal(
            payload["release_body_sha256"],
            self.release_body_sha256,
            "draft body",
        )
        self._equal(
            payload["assets_sha256"],
            self.expected_asset_inventory_sha256,
            "draft asset inventory",
        )
        if payload["asset_count"] != self.expected_asset_count:
            raise contract.ReceiptValidationError("draft asset count mismatch")
        if set(self.uploaded_assets) != set(self.expected_assets):
            raise contract.ReceiptValidationError("draft asset set is incomplete")

    def bind_pypi(self, payload: Mapping[str, Any], *, recovery: bool = False) -> str:
        self._equal(payload["candidate_id"], self.candidate_id, "PyPI candidate")
        key = (payload["project"], payload["version"], payload["filename"])
        expected = self.distributions.get(key)
        if expected is None:
            raise contract.ReceiptValidationError("unexpected PyPI distribution")
        for name in ("size_bytes", "sha256"):
            self._equal(payload[name], expected[name], f"PyPI {name}")
        current = self.pypi_files.get(key)
        transition = payload["transition"]
        required = {
            "PENDING_UPLOAD": None,
            "SEALED_FOR_UPLOAD": "PENDING_UPLOAD",
            "UPLOAD_ACCEPTED": "SEALED_FOR_UPLOAD",
            "INTEGRITY_VERIFIED": "UPLOAD_ACCEPTED",
        }
        if transition in required and current != required[transition]:
            raise contract.ReceiptValidationError("per-file PyPI transition mismatch")
        if transition == "ALREADY_PUBLISHED_EXACT":
            if not recovery or current != "UPLOAD_ACCEPTED":
                raise contract.ReceiptValidationError(
                    "already-published exact is recovery-only"
                )
        self.pypi_files[key] = transition
        if transition in {"INTEGRITY_VERIFIED", "ALREADY_PUBLISHED_EXACT"}:
            self.pypi_verified_count += 1
            if payload["verified_file_count"] != self.pypi_verified_count:
                raise contract.ReceiptValidationError("PyPI verified count mismatch")
        return transition

    def bind_github(self, payload: Mapping[str, Any]) -> None:
        self._equal(payload["release_id"], self.release_id, "GitHub release ID")
        self._equal(
            payload["public_bundle_manifest_sha256"],
            self.public_bundle_manifest_sha256,
            "GitHub public bundle",
        )
        self._equal(
            payload["release_body_sha256"], self.release_body_sha256, "GitHub body"
        )
        assets_digest = (
            payload["asset_inventory_sha256"]
            if payload["transition"] == "PUBLISH_ACCEPTED"
            else payload["assets_sha256"]
        )
        self._equal(
            assets_digest,
            self.expected_asset_inventory_sha256,
            "GitHub asset inventory",
        )
        if payload["transition"] == "IMMUTABLE_VERIFIED":
            if (
                payload["asset_count"] != self.expected_asset_count
                or payload["verified_asset_count"] != self.expected_asset_count
            ):
                raise contract.ReceiptValidationError(
                    "immutable release asset count mismatch"
                )
            self.immutable_release_verified = True

    def require_closed(self, payload: Mapping[str, Any]) -> None:
        if self.pypi_verified_count != len(self.distributions):
            raise contract.ReceiptValidationError("PyPI inventory is not complete")
        if not self.immutable_release_verified:
            raise contract.ReceiptValidationError("GitHub release is not immutable")
        self._equal(
            payload["pypi_inventory_sha256"],
            self.distribution_inventory_sha256,
            "CLOSED PyPI inventory",
        )
        self._equal(
            payload["github_release_inventory_sha256"],
            self.expected_asset_inventory_sha256,
            "CLOSED GitHub inventory",
        )

    def _bind_uploaded_asset(self, raw: Any) -> None:
        asset = contract.mapping(raw, "draft asset")
        name = asset["name"]
        expected = self.expected_assets.get(name)
        if expected is None:
            raise contract.ReceiptValidationError("unexpected draft asset")
        if name in self.uploaded_assets:
            raise contract.ReceiptValidationError("duplicate draft asset receipt")
        for key in ("size_bytes", "sha256"):
            self._equal(asset[key], expected[key], f"draft asset {key}")
        self.uploaded_assets[name] = dict(asset)

    @staticmethod
    def _equal(actual: Any, expected: Any, name: str) -> None:
        if actual != expected:
            raise contract.ReceiptValidationError(f"{name} mismatch")
