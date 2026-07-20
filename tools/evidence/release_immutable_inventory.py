"""Inventory GitHub immutable-release setting (observe-only; no mutation)."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def _load_sibling(module_name: str, filename: str) -> Any:
    if module_name in sys.modules:
        return sys.modules[module_name]
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


canonical = _load_sibling("dpone_agent_release_canonical", "release_canonical.py")
stream = _load_sibling("dpone_agent_release_stream_service", "release_stream_service.py")

StreamPrerequisiteError = stream.StreamPrerequisiteError


def observe_immutable_releases(
    api: Any,
    *,
    owner: str,
    repo: str,
) -> dict[str, Any]:
    """Return observed immutable-release inventory without changing settings."""

    del repo  # repository-level endpoint not available; org/user path is authoritative today.
    # GitHub documents org settings at /orgs/{org}/settings/immutable-releases.
    # User-owned repositories and missing org endpoints remain UNVERIFIED.
    try:
        payload = api.request("GET", f"/orgs/{owner}/settings/immutable-releases")
        assert isinstance(payload, dict)
        enabled = bool(payload.get("enabled_for_new_repos") or payload.get("enabled") or False)
        return {
            "required": True,
            "observed": "ENABLED" if enabled else "DISABLED",
            "source": f"orgs/{owner}/settings/immutable-releases",
            "raw_keys": sorted(payload.keys()),
        }
    except Exception as exc:
        # Duck-type status: sibling importlib loads can fork GitHubApiError identity.
        status = getattr(exc, "status", None)
        if not isinstance(status, int):
            raise
        return {
            "required": True,
            "observed": "UNVERIFIED",
            "source": f"orgs/{owner}/settings/immutable-releases",
            "reason": f"HTTP_{status}",
            "detail": str(exc)[:300],
        }


class InventoryError(RuntimeError):
    """Immutable-release inventory prerequisites failed."""


def run_immutable_inventory(
    store: Any,
    api: Any,
    *,
    owner: str,
    repo: str,
    release_identity_id: str,
    release_authority_id: str,
    repository_id: int,
    tag_ref: str,
    producer: Mapping[str, Any],
    now_utc: str,
    retention_days: int = 365,
) -> dict[str, Any]:
    """Append IMMUTABLE_RELEASE_INVENTORY under an active AUTHORIZED lease."""

    receipts = store.list_receipts(release_identity_id)
    authorized = None
    for receipt in reversed(receipts):
        if str((receipt.get("payload") or {}).get("kind")) == "AUTHORIZED":
            authorized = receipt
            break
    if authorized is None:
        raise InventoryError("AUTHORIZED_REQUIRED")
    authorization_id = str(authorized["payload"]["authorization_id"])
    observation = observe_immutable_releases(api, owner=owner, repo=repo)
    inventory_id = canonical.sha256_id(
        "dpone.release.immutable-inventory.v2",
        {
            "authorization_id": authorization_id,
            "owner": owner,
            "repo": repo,
            "observation": observation,
        },
    )
    receipt = stream.append_stream_receipt(
        store,
        release_identity_id=release_identity_id,
        release_authority_id=release_authority_id,
        repository_id=repository_id,
        tag_ref=tag_ref,
        producer=producer,
        receipt_type="immutable_release_inventory",
        payload={
            "kind": "IMMUTABLE_RELEASE_INVENTORY",
            "mode": "OBSERVE",
            "authorization_id": authorization_id,
            "inventory_id": inventory_id,
            "owner": owner,
            "repo": repo,
            "mutated": False,
            **observation,
        },
        now_utc=now_utc,
        retention_days=retention_days,
        scope={"kind": "release", "release_identity_id": release_identity_id},
    )
    return {
        "status": "IMMUTABLE_RELEASE_INVENTORY",
        "mode": "OBSERVE",
        "inventory_id": inventory_id,
        "observed": observation["observed"],
        "receipt": receipt,
    }
