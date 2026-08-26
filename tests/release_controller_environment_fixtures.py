"""Deterministic normalized A0 controller-environment observation."""

from __future__ import annotations

import hashlib
from typing import Any


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def observation() -> dict[str, Any]:
    """Return one exact provider-observed positive vector."""

    tag = "v2.0.0"
    environments = {
        name: _environment(name, index=index, tag=tag)
        for index, name in enumerate(
            ("release-attest", "pypi", "github-release"), start=1
        )
    }
    return {
        "schema": "dpone.release-controller-environment-observation.v1",
        "schema_version": 1,
        "provider_api_version": "2026-03-10",
        "controller_ref": f"refs/tags/{tag}",
        "controller_tag_name": tag,
        "observed_at": "2026-08-15T00:00:00Z",
        "controller_environments": environments,
    }


def _environment(name: str, *, index: int, tag: str) -> dict[str, Any]:
    value: dict[str, Any] = {
        "environment_id": 18_405_660_890 + index,
        "environment_name": name,
        "can_admins_bypass": False,
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
        "deployment_policy_count": 1,
        "deployment_policies": [{"id": 20_000_000 + index, "name": tag, "type": "tag"}],
        "protection_rule_count": 0,
        "protection_rules": [],
        "secret_count": 0,
        "variable_count": 0,
        "provider_observation_sha256": digest(f"provider/{name}"),
        "deployment_policy_observation_sha256": digest(f"policy/{name}"),
        "zero_secrets_variables_observation_sha256": digest(f"hygiene/{name}"),
        "observed_at": "2026-08-15T00:00:00Z",
    }
    if name == "pypi":
        value["protection_rule_count"] = 1
        value["protection_rules"] = [
            {
                "id": 30_000_001,
                "type": "custom",
                "app_role": "pypi_deployment_gate",
                "app_id": 9_000_001,
                "installation_id": 10_000_001,
                "app_slug": "dpone-release-controller-pypi-gate",
                "enabled": True,
                "accepted_action": "requested",
            }
        ]
        value["activation_evidence"] = {
            "provider_observation_sha256": value["provider_observation_sha256"],
            "public_preview_feature_evidence_sha256": digest("preview/pypi"),
            "fail_closed_readiness_evidence_sha256": digest("negative/pypi"),
        }
    return value
