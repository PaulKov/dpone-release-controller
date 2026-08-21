import { PATH, SHA1 } from "./activation-contract";
import { requireDigest, requireExactInteger, requireLiteral } from "./activation-fields";
import { TRUST } from "./config";
import {
  parseControllerActionBundle,
  runtimeClosureMetadataBlobSha,
} from "./controller-action-bundle";
import { assert } from "./errors";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

/** Validate the immutable controller workflow and Commit-A action bundle. */
export function validateController(controller: JsonObject): JsonObject {
  requireLiteral(controller, "repository", TRUST.controllerRepository);
  requireExactInteger(controller, "repository_id", TRUST.controllerRepositoryId);
  requireInteger(controller, "workflow_id", 1);
  requireLiteral(controller, "workflow_path", TRUST.controllerWorkflowPath);
  const ref = requireString(
    controller,
    "ref",
    80,
    /^refs\/tags\/v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u,
  );
  requireLiteral(controller, "ref_type", "tag");
  requireLiteral(controller, "default_branch_ref", TRUST.controllerDefaultBranchRef);
  requireDigest(controller, "workflow_identity_evidence_sha256");
  requireDigest(controller, "tag_protection_evidence_sha256");
  requireDigest(controller, "tag_no_bypass_evidence_sha256");
  requireDigest(controller, "default_branch_workflow_observation_sha256");
  for (const key of [
    "controller_action_commit_sha",
    "controller_action_metadata_blob_sha",
    "default_branch_workflow_blob_sha",
    "peeled_commit_sha",
    "production_commit_sha",
    "production_tree_sha",
    "reusable_actions_commit_sha",
    "reusable_actions_tree_sha",
    "tag_object_sha",
    "workflow_blob_sha",
  ]) {
    requireString(controller, key, 40, SHA1);
  }
  requireDigest(controller, "controller_action_bundle_sha256");
  requireDigest(controller, "workflow_sha256");
  assert(ref.startsWith("refs/tags/"), "ACTIVATION_CONTROLLER_REF_INVALID");
  assert(
    controller.production_commit_sha === controller.peeled_commit_sha,
    "ACTIVATION_CONTROLLER_COMMIT_MISMATCH",
  );
  assert(
    controller.tag_object_sha !== controller.peeled_commit_sha,
    "ACTIVATION_CONTROLLER_TAG_MUST_BE_ANNOTATED",
  );
  assert(
    controller.controller_action_commit_sha === controller.reusable_actions_commit_sha &&
      controller.controller_action_commit_sha !== controller.production_commit_sha,
    "ACTIVATION_CONTROLLER_ACTION_COMMIT_MISMATCH",
  );
  const actionCommitSha = requireString(controller, "controller_action_commit_sha", 40, SHA1);
  const actionBundle = parseControllerActionBundle(
    controller.controller_action_bundle,
    actionCommitSha,
  );
  assert(
    runtimeClosureMetadataBlobSha(actionBundle) === controller.controller_action_metadata_blob_sha,
    "ACTIVATION_CONTROLLER_ACTION_METADATA_MISMATCH",
  );
  const actions = controller.reusable_actions;
  assert(Array.isArray(actions) && actions.length === 3, "ACTIVATION_ACTIONS_INVALID");
  const bundleMembers = actionBundle.members;
  assert(Array.isArray(bundleMembers), "ACTIVATION_ACTIONS_INVALID", 500);
  for (let index = 0; index < actions.length; index += 1) {
    const action = exactObject(actions[index], [
      "action_path",
      "action_yaml_blob_sha",
      "bundle_path",
      "bundle_sha256",
    ]);
    const metadataMember = exactObject(bundleMembers[index * 2], [
      "git_blob_sha",
      "mode",
      "path",
      "sha256",
      "size_bytes",
    ]);
    const bundleMember = exactObject(bundleMembers[index * 2 + 1], [
      "git_blob_sha",
      "mode",
      "path",
      "sha256",
      "size_bytes",
    ]);
    requireLiteral(action, "action_path", requireString(metadataMember, "path", 256, PATH));
    requireLiteral(
      action,
      "action_yaml_blob_sha",
      requireString(metadataMember, "git_blob_sha", 40, SHA1),
    );
    requireLiteral(action, "bundle_path", requireString(bundleMember, "path", 256, PATH));
    requireLiteral(action, "bundle_sha256", requireDigest(bundleMember, "sha256"));
  }
  return controller;
}
