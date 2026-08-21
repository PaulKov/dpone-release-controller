import {
  ACTIVATED_RECORD_SCHEMA,
  POSITIVE_ID,
  PROVISIONED_RECORD_SCHEMA,
  SHA1,
  SHA256_HEX,
} from "./activation-contract";
import { nested, requireDigest, requireExactInteger, requireLiteral } from "./activation-fields";
import { canonicalBytes, sha256Hex } from "./canonical";
import { isGitSha, TRUST } from "./config";
import { assert, BrokerError } from "./errors";
import type { JsonObject } from "./types";
import { requireObject, requireString } from "./validation";

export function validateActivationTarget(target: JsonObject): JsonObject {
  requireLiteral(target, "repository", TRUST.targetRepository);
  requireExactInteger(target, "repository_id", TRUST.targetRepositoryId);
  const commit = requireString(target, "commit_sha", 40, SHA1);
  requireString(target, "tree_sha", 40, SHA1);
  requireLiteral(target, "policy_path", ".agents/policy/github-branch-protection.yml");
  requireString(target, "policy_blob_sha", 40, SHA1);
  requireDigest(target, "policy_sha256");
  requireLiteral(target, "runtime_workflow_path", TRUST.runtimeWorkflowPath);
  requireString(target, "runtime_workflow_blob_sha", 40, SHA1);
  requireDigest(target, "runtime_workflow_sha256");
  const rehearsal = nested(target, "runtime_oidc_rehearsal", [
    "check_run_id",
    "evidence_sha256",
    "jti_sha256",
    "repository_id",
    "workflow_sha",
  ]);
  requireString(rehearsal, "check_run_id", 32, POSITIVE_ID);
  requireDigest(rehearsal, "evidence_sha256");
  requireDigest(rehearsal, "jti_sha256");
  requireExactInteger(rehearsal, "repository_id", TRUST.targetRepositoryId);
  const workflowSha = requireString(rehearsal, "workflow_sha", 40, SHA1);
  assert(workflowSha === commit && isGitSha(workflowSha), "ACTIVATION_RUNTIME_WORKFLOW_MISMATCH");
  return target;
}

export function parseProvisionedEnvelope(envelope: JsonObject): {
  readonly broker: JsonObject;
  readonly controller: JsonObject;
  readonly githubApps: JsonObject;
  readonly oidc: JsonObject;
  readonly recordId: string;
  readonly serviceAuthorities: JsonObject;
  readonly targetGovernance: JsonObject;
} {
  requireLiteral(envelope, "schema", PROVISIONED_RECORD_SCHEMA);
  requireExactInteger(envelope, "schema_version", 1);
  requireExactInteger(envelope, "sequence", 0);
  requireExactInteger(envelope, "fencing_token", 1);
  requireLiteral(envelope, "previous", "GENESIS");
  const recordId = requireDigest(envelope, "record_id");
  const evidence = requireObject(envelope.evidence, "ACTIVATION_EVIDENCE_INVALID");
  return {
    broker: requireObject(evidence.broker, "ACTIVATION_BROKER_INVALID"),
    controller: requireObject(evidence.controller, "ACTIVATION_CONTROLLER_INVALID"),
    githubApps: requireObject(evidence.github_apps, "ACTIVATION_GITHUB_APPS_INVALID"),
    oidc: requireObject(evidence.oidc, "ACTIVATION_OIDC_INVALID"),
    recordId,
    serviceAuthorities: requireObject(
      evidence.service_authorities,
      "SERVICE_AUTHORITY_EXPECTATION_REQUIRED",
    ),
    targetGovernance: requireObject(
      evidence.target_governance,
      "ACTIVATION_TARGET_GOVERNANCE_REQUIRED",
    ),
  };
}

export function parseActivatedEnvelope(envelope: JsonObject): {
  readonly controllerActionBundleSha256: string;
  readonly controllerActionCommitSha: string;
  readonly controllerActionMetadataBlobSha: string;
  readonly previous: string;
  readonly provisioned: JsonObject;
  readonly promotion: JsonObject;
  readonly recordId: string;
  readonly target: JsonObject;
  readonly serviceAuthorities: JsonObject;
} {
  requireLiteral(envelope, "schema", ACTIVATED_RECORD_SCHEMA);
  requireExactInteger(envelope, "schema_version", 1);
  requireExactInteger(envelope, "sequence", 1);
  requireExactInteger(envelope, "fencing_token", 2);
  const previous = requireDigest(envelope, "previous");
  const recordId = requireDigest(envelope, "record_id");
  return {
    controllerActionBundleSha256: requireDigest(envelope, "controller_action_bundle_sha256"),
    controllerActionCommitSha: requireString(envelope, "controller_action_commit_sha", 40, SHA1),
    controllerActionMetadataBlobSha: requireString(
      envelope,
      "controller_action_metadata_blob_sha",
      40,
      SHA1,
    ),
    previous,
    promotion: requireObject(envelope.promotion, "ACTIVATION_PROMOTION_EVIDENCE_INVALID"),
    provisioned: requireObject(envelope.provisioned, "ACTIVATION_PROVISIONED_POINTER_INVALID"),
    recordId,
    serviceAuthorities: requireObject(
      envelope.service_authorities,
      "SERVICE_AUTHORITY_OBSERVATION_REQUIRED",
    ),
    target: requireObject(envelope.target, "ACTIVATION_TARGET_INVALID"),
  };
}

export async function assertActivationRecordDigest(
  envelope: JsonObject,
  expectedRecordId: string,
): Promise<void> {
  const body = { ...envelope };
  delete body.record_id;
  const digest = await sha256Hex(canonicalBytes(body));
  if (!SHA256_HEX.test(digest) || expectedRecordId !== `sha256:${digest}`) {
    throw new BrokerError("ACTIVATION_RECORD_DIGEST_INVALID", 503, false);
  }
}
