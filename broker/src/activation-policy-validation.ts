import { POSITIVE_ID, SAFE_NAME, SHA1, targetSelectedActions } from "./activation-contract";
import {
  nested,
  requireDigest,
  requireExactInteger,
  requireExactStringArray,
  requireLiteral,
} from "./activation-fields";
import { assertControllerActionsPolicyFrozen } from "./activation-infrastructure";
import { canonicalBytes, sha256Hex } from "./canonical";
import { TRUST } from "./config";
import { assert } from "./errors";
import { validateGitHubRulesetProjection } from "./github-ruleset-projection";
import type { JsonObject } from "./types";
import {
  exactObject,
  requireBoolean,
  requireInteger,
  requireObject,
  requireString,
} from "./validation";

/** Validate controller branch, environment and deployment-gate governance. */
export function validateControllerGovernance(
  governance: JsonObject,
  apps: JsonObject,
  controller: JsonObject,
): void {
  validateActionsPolicy(
    governance,
    assertControllerActionsPolicyFrozen(
      requireString(controller, "controller_action_commit_sha", 40, SHA1),
    ),
  );
  requireLiteral(governance, "repository", TRUST.controllerRepository);
  requireExactInteger(governance, "repository_id", TRUST.controllerRepositoryId);
  requireLiteral(governance, "protected_ref", TRUST.controllerDefaultBranchRef);
  const ref = requireString(controller, "ref", 80);
  const tag = ref.slice("refs/tags/".length);
  const environments = nested(governance, "environments", [
    "github_release",
    "pypi",
    "release_attest",
  ]);
  validateControllerEnvironment(
    nested(environments, "github_release", controllerEnvironmentFields(false)),
    "github-release",
    tag,
  );
  validateControllerEnvironment(
    nested(environments, "release_attest", controllerEnvironmentFields(false)),
    "release-attest",
    tag,
  );
  const gate = nested(environments, "pypi", controllerEnvironmentFields(true));
  validateControllerEnvironment(gate, "pypi", tag);
  requireLiteral(gate, "accepted_action", "requested");
  requireExactInteger(gate, "protection_rule_count", 1);
  const rule = nested(gate, "protection_rule", [
    "app_id",
    "app_slug",
    "enabled",
    "protection_rule_id",
  ]);
  requireInteger(rule, "protection_rule_id", 1);
  assert(requireBoolean(rule, "enabled"), "ACTIVATION_PYPI_GATE_INVALID");
  const gateApp = requireObject(apps.pypi_deployment_gate, "ACTIVATION_PYPI_GATE_APP_REQUIRED");
  requireLiteral(rule, "app_id", requireString(gateApp, "app_id", 32, POSITIVE_ID));
  requireLiteral(rule, "app_slug", requireString(gateApp, "app_slug", 128, SAFE_NAME));
  const activationEvidence = nested(gate, "activation_evidence", [
    "fail_closed_readiness_evidence_sha256",
    "provider_observation_sha256",
    "public_preview_feature_evidence_sha256",
  ]);
  for (const key of Object.keys(activationEvidence)) requireDigest(activationEvidence, key);
  requireString(governance, "ruleset_id", 32, POSITIVE_ID);
  for (const key of [
    "no_admin_bypass_evidence_sha256",
    "ruleset_evidence_sha256",
    "workflow_enabled_evidence_sha256",
  ]) {
    requireDigest(governance, key);
  }
}

/** Validate target ruleset and exact Commit-A Actions allowlist. */
export function validateTargetGovernance(
  governance: JsonObject,
  controllerActionCommitSha: string,
): void {
  validateActionsPolicy(governance, targetSelectedActions(controllerActionCommitSha));
  requireLiteral(governance, "repository", TRUST.targetRepository);
  requireExactInteger(governance, "repository_id", TRUST.targetRepositoryId);
  const branchRulesetId = requireString(governance, "branch_ruleset_id", 32, POSITIVE_ID);
  const branchProjection = validateGitHubRulesetProjection(governance.branch_ruleset_projection, {
    repository: TRUST.targetRepository,
    repositoryId: TRUST.targetRepositoryId,
    rulesetId: Number(branchRulesetId),
  });
  assert(
    branchProjection.enforcement === "active" &&
      branchProjection.source_type === "Repository" &&
      branchProjection.source === TRUST.targetRepository &&
      JSON.stringify(branchProjection.bypass_actors) === "[]" &&
      JSON.stringify(branchProjection.conditions) ===
        JSON.stringify({ exclude: [], include: [TRUST.targetDefaultBranchRef] }),
    "ACTIVATION_TARGET_RULESET_PROJECTION_INVALID",
  );
  requireString(governance, "tag_ruleset_id", 32, POSITIVE_ID);
  for (const key of [
    "branch_ruleset_evidence_sha256",
    "branch_ruleset_projection_sha256",
    "ghcr_environment_evidence_sha256",
    "immutable_releases_evidence_sha256",
    "tag_ruleset_evidence_sha256",
  ]) {
    requireDigest(governance, key);
  }
}

export async function verifyActionsPolicyDigest(governance: JsonObject): Promise<void> {
  const policy = requireObject(governance.actions_policy, "ACTIVATION_ACTIONS_POLICY_REQUIRED");
  const patterns = policy.patterns_allowed;
  assert(Array.isArray(patterns), "ACTIVATION_ACTIONS_POLICY_INVALID");
  const computed = `sha256:${await sha256Hex(canonicalBytes({ patterns_allowed: patterns }))}`;
  assert(computed === policy.patterns_allowed_sha256, "ACTIVATION_ACTIONS_PATTERN_DIGEST_MISMATCH");
}

function controllerEnvironmentFields(pypi: boolean): string[] {
  const fields = [
    "can_admins_bypass",
    "deployment_branch_policies",
    "deployment_branch_policy",
    "deployment_branch_policy_count",
    "environment_id",
    "environment_name",
    "provider_observation_sha256",
    "protection_rule_count",
    "secret_count",
    "variable_count",
  ];
  if (pypi) fields.push("accepted_action", "activation_evidence", "protection_rule");
  return fields;
}

function validateControllerEnvironment(
  environment: JsonObject,
  expectedName: string,
  expectedTag: string,
): void {
  requireLiteral(environment, "environment_name", expectedName);
  requireInteger(environment, "environment_id", 1);
  assert(!requireBoolean(environment, "can_admins_bypass"), "ACTIVATION_ENVIRONMENT_INVALID");
  requireDigest(environment, "provider_observation_sha256");
  requireExactInteger(environment, "secret_count", 0);
  requireExactInteger(environment, "variable_count", 0);
  requireExactInteger(environment, "protection_rule_count", expectedName === "pypi" ? 1 : 0);
  requireExactInteger(environment, "deployment_branch_policy_count", 1);
  const branchPolicy = nested(environment, "deployment_branch_policy", [
    "custom_branch_policies",
    "protected_branches",
  ]);
  assert(
    !requireBoolean(branchPolicy, "protected_branches") &&
      requireBoolean(branchPolicy, "custom_branch_policies"),
    "ACTIVATION_ENVIRONMENT_INVALID",
  );
  const policies = environment.deployment_branch_policies;
  assert(Array.isArray(policies) && policies.length === 1, "ACTIVATION_ENVIRONMENT_INVALID");
  const policy = exactObject(policies[0], [
    "name",
    "policy_id",
    "provider_observation_sha256",
    "type",
  ]);
  requireLiteral(policy, "name", expectedTag);
  requireInteger(policy, "policy_id", 1);
  requireDigest(policy, "provider_observation_sha256");
  requireLiteral(policy, "type", "tag");
}

function validateActionsPolicy(governance: JsonObject, expectedPatterns: readonly string[]): void {
  const policy = nested(governance, "actions_policy", [
    "allowed_actions",
    "can_approve_pull_request_reviews",
    "default_workflow_permissions",
    "github_owned_allowed",
    "patterns_allowed",
    "patterns_allowed_sha256",
    "provider_observation_sha256",
    "sha_pinning_required",
    "verified_allowed",
  ]);
  requireLiteral(policy, "allowed_actions", "selected");
  requireLiteral(policy, "default_workflow_permissions", "read");
  assert(
    !requireBoolean(policy, "can_approve_pull_request_reviews") &&
      requireBoolean(policy, "github_owned_allowed") &&
      requireBoolean(policy, "sha_pinning_required") &&
      !requireBoolean(policy, "verified_allowed"),
    "ACTIVATION_ACTIONS_POLICY_INVALID",
  );
  requireExactStringArray(policy, "patterns_allowed", expectedPatterns);
  requireDigest(policy, "patterns_allowed_sha256");
  requireDigest(policy, "provider_observation_sha256");
}
