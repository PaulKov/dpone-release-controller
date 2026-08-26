"""Closed provider requirements that an immutable broker A0 must prove.

Live provider identifiers never appear here. App, installation, environment,
and rule IDs exist only in the provider-observed, WORM-mirrored A0 record.
"""

from __future__ import annotations

from typing import Any, Mapping

GATE_APP_SLUG = "dpone-release-controller-pypi-gate"

GITHUB_ACTIONS_REQUIREMENTS: Mapping[str, Any] = {
    "allowed_actions": "selected",
    "github_owned_allowed": True,
    "verified_allowed": False,
    "sha_pinning_required": True,
    "patterns_allowed_authority": "A0_PRODUCTION_WORKFLOW_ACTION_INVENTORY",
}

GITHUB_APP_REQUIREMENTS: Mapping[str, Any] = {
    "controller_run_reader": {
        "repository": "PaulKov/dpone-release-controller",
        "repository_selection": "selected",
        "repository_ids": [1_305_993_853],
        "permissions": {
            "actions": "read",
            "administration": "read",
            "attestations": "read",
            "checks": "read",
            "contents": "read",
            "environments": "read",
            "metadata": "read",
        },
        "subscribed_events": [],
        "webhook_active": False,
        "oauth_callback_enabled": False,
        "user_authorization_enabled": False,
        "request_oauth_on_install": False,
        "broker_enforced_methods": ["GET"],
    },
    "candidate_reader": {
        "repository": "PaulKov/dpone",
        "repository_selection": "selected",
        "repository_ids": [1_255_975_556],
        "permissions": {
            "actions": "read",
            "contents": "read",
            "metadata": "read",
        },
        "subscribed_events": [],
        "webhook_active": False,
        "oauth_callback_enabled": False,
        "user_authorization_enabled": False,
        "request_oauth_on_install": False,
    },
    "governance_reader": {
        "repository": "PaulKov/dpone",
        "repository_selection": "selected",
        "repository_ids": [1_255_975_556],
        "permissions": {
            "administration": "read",
            "actions": "read",
            "attestations": "read",
            "checks": "read",
            "contents": "read",
            "metadata": "read",
            "statuses": "read",
        },
        "subscribed_events": [],
        "webhook_active": False,
        "oauth_callback_enabled": False,
        "user_authorization_enabled": False,
        "request_oauth_on_install": False,
        "broker_enforced_methods": ["GET"],
    },
    "release_mutator": {
        "repository": "PaulKov/dpone",
        "repository_selection": "selected",
        "repository_ids": [1_255_975_556],
        "permissions": {
            "contents": "write",
            "metadata": "read",
        },
        "subscribed_events": [],
        "webhook_active": False,
        "oauth_callback_enabled": False,
        "user_authorization_enabled": False,
        "request_oauth_on_install": False,
    },
    "closed_projector": {
        "repository": "PaulKov/dpone",
        "repository_selection": "selected",
        "repository_ids": [1_255_975_556],
        "permissions": {"checks": "write", "metadata": "read"},
        "subscribed_events": [],
        "webhook_active": False,
        "oauth_callback_enabled": False,
        "user_authorization_enabled": False,
        "request_oauth_on_install": False,
    },
    "pypi_deployment_gate": {
        "repository": "PaulKov/dpone-release-controller",
        "repository_selection": "selected",
        "repository_ids": [1_305_993_853],
        "permissions": {
            "actions": "read",
            "deployments": "write",
            "metadata": "read",
        },
        "subscribed_events": ["deployment_protection_rule"],
        "webhook_active": True,
        "oauth_callback_enabled": False,
        "user_authorization_enabled": False,
        "request_oauth_on_install": False,
        "subscription_action": "requested",
    },
    "runtime_deployment_gate": {
        "repository": "PaulKov/dpone",
        "repository_selection": "selected",
        "repository_ids": [1_255_975_556],
        "permissions": {
            "actions": "read",
            "deployments": "write",
            "metadata": "read",
        },
        "subscribed_events": ["deployment_protection_rule"],
        "webhook_active": True,
        "oauth_callback_enabled": False,
        "user_authorization_enabled": False,
        "request_oauth_on_install": False,
        "subscription_action": "requested",
        "callback_method": "POST",
        "callback_path_template": (
            "/repos/PaulKov/dpone/actions/runs/{run_id}/deployment_protection_rule"
        ),
        "callback_success_status": 204,
    },
}


def _environment_requirements(name: str) -> dict[str, Any]:
    return {
        "environment_name": name,
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
        "can_admins_bypass": False,
        "deployment_policy": {
            "authority": "A0_PROVISIONED_RECORD",
            "type": "tag",
            "name_authority": "A0_CONTROLLER_EXECUTION_TAG_NAME",
            "policy_count": 1,
            "exact_match_required": True,
            "wildcards_allowed": False,
        },
        "required_secret_count": 0,
        "required_variable_count": 0,
        "activation_evidence_fields": [
            "provider_observation_sha256",
            "deployment_policy_observation_sha256",
            "zero_secrets_variables_observation_sha256",
        ],
    }


PYPI_PROTECTION_REQUIREMENTS: Mapping[str, Any] = {
    **_environment_requirements("pypi"),
    "protection_rule_count": 1,
    "accepted_action": "requested",
    "protection_rule": {
        "app_role": "pypi_deployment_gate",
        "app_slug": GATE_APP_SLUG,
        "enabled": True,
    },
    "activation_evidence_fields": [
        "provider_observation_sha256",
        "deployment_policy_observation_sha256",
        "zero_secrets_variables_observation_sha256",
        "public_preview_feature_evidence_sha256",
        "fail_closed_readiness_evidence_sha256",
    ],
}

RELEASE_ATTEST_ENVIRONMENT_REQUIREMENTS: Mapping[str, Any] = {
    **_environment_requirements("release-attest"),
    "protection_rule_count": 0,
}

GITHUB_RELEASE_ENVIRONMENT_REQUIREMENTS: Mapping[str, Any] = {
    **_environment_requirements("github-release"),
    "protection_rule_count": 0,
}


def _target_runtime_environment(name: str, *, gated: bool) -> dict[str, Any]:
    value = {
        "environment_name": name,
        "deployment_branch_policy_authority": "A0_PROVIDER_OBSERVED_EXACT_POLICY",
        "can_admins_bypass": False,
        "required_secret_count": 0,
        "required_variable_count": 0,
        "protection_rule_count": int(gated),
        "activation_evidence_fields": [
            "provider_observation_sha256",
            "deployment_policy_observation_sha256",
            "zero_secrets_variables_observation_sha256",
        ],
    }
    if gated:
        value["protection_rule"] = {
            "app_role": "runtime_deployment_gate",
            "enabled": True,
            "accepted_action": "requested",
        }
        value["activation_evidence_fields"].append(
            "fail_closed_readiness_evidence_sha256"
        )
    return value


TARGET_RUNTIME_ENVIRONMENT_REQUIREMENTS: Mapping[str, Any] = {
    "ghcr_candidate": _target_runtime_environment("ghcr-candidate", gated=False),
    "ghcr": _target_runtime_environment("ghcr", gated=True),
}

REQUIRED_PROVIDER_PROFILE: Mapping[str, Any] = {
    "github_actions": GITHUB_ACTIONS_REQUIREMENTS,
    "github_apps": GITHUB_APP_REQUIREMENTS,
    "trusted_controller": {
        "environments": {
            "release_attest": RELEASE_ATTEST_ENVIRONMENT_REQUIREMENTS,
            "pypi": PYPI_PROTECTION_REQUIREMENTS,
            "github_release": GITHUB_RELEASE_ENVIRONMENT_REQUIREMENTS,
        }
    },
    "target_runtime": {
        "environments": TARGET_RUNTIME_ENVIRONMENT_REQUIREMENTS,
        "workflow_path": ".github/workflows/runtime-image.yml",
        "candidate_job": "push-attest-runtime-candidate",
        "promotion_job": "promote-certified-image",
        "promotion_check_name": "Promote certified runtime image aliases",
        "ghcr_environment_job_count": 1,
    },
}
