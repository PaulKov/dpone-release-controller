import {
  CONTROLLER_ACTION_BUNDLE_SCHEMA,
  CONTROLLER_ACTION_EXECUTABLE_PATHS,
  controllerSelectedActions,
  targetSelectedActions,
} from "../src/activation-contract";
import { digestObject } from "../src/canonical";
import { controllerActionBundleSha256 } from "../src/controller-action-bundle";
import { githubRulesetProjectionDigest } from "../src/github-ruleset-projection";
import type { JsonObject } from "../src/types";
import rulesetProjectionFixture from "./fixtures/github-ruleset-projection-v1-golden.json";
import { requiredString, tagged } from "./activation-schema-topology.fixtures";

const ACTION_COMMIT_SHA = "d".repeat(40);
const PRODUCTION_COMMIT_SHA = "c".repeat(40);
const RELEASE_TAG = "v1.0.0";

export interface ValidGovernanceFixture {
  readonly controller: JsonObject;
  readonly controllerGovernance: JsonObject;
  readonly targetGovernance: JsonObject;
}

/** Build controller and target governance with all content digests recomputed. */
export async function validGovernanceFixture(
  githubApps: JsonObject,
): Promise<ValidGovernanceFixture> {
  const controller = await controllerEvidence();
  return {
    controller,
    controllerGovernance: await controllerGovernance(githubApps),
    targetGovernance: await targetGovernance(),
  };
}

async function controllerEvidence(): Promise<JsonObject> {
  const members = CONTROLLER_ACTION_EXECUTABLE_PATHS.map((path, index) => ({
    git_blob_sha: (index + 1).toString(16).repeat(40),
    mode: "100644",
    path,
    sha256: tagged(index + 1),
    size_bytes: index + 1,
  }));
  const actionBundle: JsonObject = {
    commit_sha: ACTION_COMMIT_SHA,
    members,
    repository: "PaulKov/dpone-release-controller",
    repository_id: 1_305_993_853,
    schema: CONTROLLER_ACTION_BUNDLE_SCHEMA,
    schema_version: 1,
  };
  const reusableActions = [0, 2, 4].map((metadataIndex) => {
    const metadata = requireDefined(members[metadataIndex], "action metadata member missing");
    const bundle = requireDefined(members[metadataIndex + 1], "action bundle member missing");
    return {
      action_path: metadata.path,
      action_yaml_blob_sha: metadata.git_blob_sha,
      bundle_path: bundle.path,
      bundle_sha256: bundle.sha256,
    };
  });
  return {
    controller_action_bundle: actionBundle,
    controller_action_bundle_sha256: await controllerActionBundleSha256(actionBundle),
    controller_action_commit_sha: ACTION_COMMIT_SHA,
    controller_action_metadata_blob_sha: "5".repeat(40),
    default_branch_ref: "refs/heads/master",
    default_branch_workflow_blob_sha: "1".repeat(40),
    default_branch_workflow_observation_sha256: tagged(91),
    peeled_commit_sha: PRODUCTION_COMMIT_SHA,
    production_commit_sha: PRODUCTION_COMMIT_SHA,
    production_tree_sha: "a".repeat(40),
    ref: `refs/tags/${RELEASE_TAG}`,
    ref_type: "tag",
    repository: "PaulKov/dpone-release-controller",
    repository_id: 1_305_993_853,
    reusable_actions: reusableActions,
    reusable_actions_commit_sha: ACTION_COMMIT_SHA,
    reusable_actions_tree_sha: "e".repeat(40),
    tag_no_bypass_evidence_sha256: tagged(92),
    tag_object_sha: "2".repeat(40),
    tag_protection_evidence_sha256: tagged(93),
    workflow_blob_sha: "f".repeat(40),
    workflow_id: 987_654_321,
    workflow_identity_evidence_sha256: tagged(94),
    workflow_path: ".github/workflows/release-controller.yml",
    workflow_sha256: tagged(95),
  };
}

async function controllerGovernance(githubApps: JsonObject): Promise<JsonObject> {
  const pypiApp = requireObject(githubApps.pypi_deployment_gate, "PyPI gate app missing");
  return {
    actions_policy: await actionsPolicy(controllerSelectedActions(ACTION_COMMIT_SHA), 300),
    environments: {
      github_release: controllerEnvironment("github-release", 1, false),
      pypi: {
        ...controllerEnvironment("pypi", 2, true),
        accepted_action: "requested",
        activation_evidence: {
          fail_closed_readiness_evidence_sha256: tagged(340),
          provider_observation_sha256: tagged(341),
          public_preview_feature_evidence_sha256: tagged(342),
        },
        protection_rule: {
          app_id: requiredString(pypiApp, "app_id"),
          app_slug: requiredString(pypiApp, "app_slug"),
          enabled: true,
          protection_rule_id: 501,
        },
      },
      release_attest: controllerEnvironment("release-attest", 3, false),
    },
    no_admin_bypass_evidence_sha256: tagged(350),
    protected_ref: "refs/heads/master",
    repository: "PaulKov/dpone-release-controller",
    repository_id: 1_305_993_853,
    ruleset_evidence_sha256: tagged(351),
    ruleset_id: "18806830",
    workflow_enabled_evidence_sha256: tagged(352),
  };
}

function controllerEnvironment(name: string, id: number, pypi: boolean): JsonObject {
  return {
    can_admins_bypass: false,
    deployment_branch_policies: [
      {
        name: RELEASE_TAG,
        policy_id: id + 100,
        provider_observation_sha256: tagged(360 + id),
        type: "tag",
      },
    ],
    deployment_branch_policy: {
      custom_branch_policies: true,
      protected_branches: false,
    },
    deployment_branch_policy_count: 1,
    environment_id: id,
    environment_name: name,
    protection_rule_count: pypi ? 1 : 0,
    provider_observation_sha256: tagged(370 + id),
    secret_count: 0,
    variable_count: 0,
  };
}

async function targetGovernance(): Promise<JsonObject> {
  const branchRulesetProjection: JsonObject = structuredClone(rulesetProjectionFixture);
  return {
    actions_policy: await actionsPolicy(targetSelectedActions(ACTION_COMMIT_SHA), 400),
    branch_ruleset_evidence_sha256: tagged(410),
    branch_ruleset_id: "18806829",
    branch_ruleset_projection: branchRulesetProjection,
    branch_ruleset_projection_sha256: await githubRulesetProjectionDigest(branchRulesetProjection),
    ghcr_environment_evidence_sha256: tagged(411),
    immutable_releases_evidence_sha256: tagged(412),
    repository: "PaulKov/dpone",
    repository_id: 1_255_975_556,
    tag_ruleset_evidence_sha256: tagged(413),
    tag_ruleset_id: "18806831",
  };
}

async function actionsPolicy(
  patternsAllowed: readonly string[],
  digestSeed: number,
): Promise<JsonObject> {
  const patterns = [...patternsAllowed];
  return {
    allowed_actions: "selected",
    can_approve_pull_request_reviews: false,
    default_workflow_permissions: "read",
    github_owned_allowed: true,
    patterns_allowed: patterns,
    patterns_allowed_sha256: await digestObject({ patterns_allowed: patterns }),
    provider_observation_sha256: tagged(digestSeed),
    sha_pinning_required: true,
    verified_allowed: false,
  };
}

function requireObject(value: unknown, message: string): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(message);
  }
  return value as JsonObject;
}

function requireDefined<T>(value: T | undefined, message: string): T {
  if (value === undefined) throw new Error(message);
  return value;
}
