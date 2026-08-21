import { activatedServiceAuthoritiesSha256 } from "./activated-authority-head";
import { parseCurrentHeadProof } from "./activated-authority-head-proof";
import {
  ACTIVATION_PROOF_REQUEST_SCHEMA,
  ACTIVATION_PROOF_SCHEMA,
} from "./activation-proof-contract";
import { canonicalBytes, canonicalJson, digestObject, sha256Hex } from "./canonical";
import { LIMITS, TRUST } from "./config";
import { assert } from "./errors";
import type { ControllerJobObservation } from "./controller-run-client";
import type {
  ActivationSnapshot,
  ActivationTrust,
  AuthenticatedWorkflow,
  JsonObject,
} from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export {
  ACTIVATION_PROOF_RECOVERY_SCHEMA,
  ACTIVATION_PROOF_REQUEST_SCHEMA,
  ACTIVATION_PROOF_SCHEMA,
} from "./activation-proof-contract";
export {
  activationProofRecoveryClaimsDigest,
  buildActivationProofRecovery,
} from "./activation-proof-recovery";

export function parseActivationProofRequest(value: unknown): void {
  const request = exactObject(value, ["schema", "schema_version"]);
  requireLiteral(request, "schema", ACTIVATION_PROOF_REQUEST_SCHEMA);
  requireExactInteger(request, "schema_version", 1);
}

export async function admissionClaimsDigest(
  auth: AuthenticatedWorkflow,
  observation: ControllerJobObservation,
  requestId: string,
): Promise<string> {
  return digestObject({
    actor_id: auth.actorId,
    audience: auth.audience,
    check_run_id: auth.checkRunId,
    environment: auth.environment,
    expires_at: auth.expiresAt,
    issued_at: auth.issuedAt,
    job_name: observation.jobName,
    jti: auth.jti,
    not_before: auth.notBefore,
    observation_sha256: observation.digest,
    ref: auth.ref,
    repository: auth.repository,
    repository_id: auth.repositoryId,
    repository_owner_id: auth.repositoryOwnerId,
    request_id: requestId,
    run_attempt: auth.runAttempt,
    run_id: auth.runId,
    sha: auth.sha,
    subject: auth.subject,
    workflow_ref: auth.workflowRef,
    workflow_sha: auth.workflowSha,
  });
}

/** Stable semantic key for recovery across fresh OIDC transport tokens. */
export async function activationProofIntentDigest(
  auth: AuthenticatedWorkflow,
  observation: ControllerJobObservation,
  snapshot: ActivationSnapshot,
): Promise<string> {
  const activated = snapshot.activated;
  assert(activated !== null, "BROKER_PROVISIONING", 503);
  return digestObject({
    activated_record_id: activated.recordId,
    activated_record_sha256: activated.digest,
    actor_id: auth.actorId,
    audience: auth.audience,
    check_run_id: auth.checkRunId,
    environment: auth.environment,
    job_name: observation.jobName,
    observation_sha256: observation.digest,
    ref: auth.ref,
    repository: auth.repository,
    repository_id: auth.repositoryId,
    repository_owner_id: auth.repositoryOwnerId,
    run_attempt: auth.runAttempt,
    run_id: auth.runId,
    schema: "dpone.release-broker-activation-proof-intent.v1",
    schema_version: 1,
    sha: auth.sha,
    subject: auth.subject,
    workflow_ref: auth.workflowRef,
    workflow_sha: auth.workflowSha,
  });
}

export async function buildActivationProof(input: {
  readonly activation: ActivationTrust;
  readonly activatedAuthorityHead: JsonObject;
  readonly auth: AuthenticatedWorkflow;
  readonly nowMs: number;
  readonly observation: ControllerJobObservation;
  readonly requestId: string;
  readonly snapshot: ActivationSnapshot;
}): Promise<JsonObject> {
  const activated = input.snapshot.activated;
  assert(activated !== null, "BROKER_PROVISIONING", 503);
  const currentHead = await parseCurrentHeadProof(input.activatedAuthorityHead);
  assertCurrentHeadBinding(currentHead, input, input.nowMs);
  const previous = requireString(activated.envelope, "previous", 71, /^sha256:[0-9a-f]{64}$/u);
  assert(previous === input.snapshot.provisioned.recordId, "ACTIVATION_CHAIN_MISMATCH", 503);
  const admittedAtMs = Math.floor(input.nowMs / 1000) * 1000;
  const admittedAt = canonicalUtcSeconds(admittedAtMs);
  const expiresAt = canonicalUtcSeconds(admittedAtMs + 60_000);
  const body: JsonObject = {
    activated: {
      controller_action_bundle_sha256: input.activation.controllerActionBundleSha256,
      controller_action_commit_sha: input.activation.controllerActionCommitSha,
      controller_action_metadata_blob_sha: input.activation.controllerActionMetadataBlobSha,
      digest: input.activation.activatedDigest,
      previous,
      record_id: input.activation.activatedRecordId,
      target_branch_ruleset_evidence_sha256: input.activation.targetBranchRulesetEvidenceSha256,
      target_branch_ruleset_id: input.activation.targetBranchRulesetId,
      target_branch_ruleset_projection_sha256: input.activation.targetBranchRulesetProjectionSha256,
      target_default_branch_ref: input.activation.targetDefaultBranchRef,
      target_policy_blob_sha: input.activation.targetPolicyBlobSha,
      target_policy_commit_sha: input.activation.targetPolicyCommitSha,
      target_policy_sha256: input.activation.targetPolicySha256,
      target_runtime_workflow_blob_sha: input.activation.targetRuntimeWorkflowBlobSha,
      target_runtime_workflow_sha256: input.activation.targetRuntimeWorkflowSha256,
      worm_version_id: activated.worm.versionId,
    },
    activated_authority_head: currentHead,
    admitted_at: admittedAt,
    controller: {
      default_branch_ref: input.observation.defaultBranchRef,
      default_branch_workflow_blob_sha: input.observation.defaultBranchWorkflowBlobSha,
      default_branch_workflow_observation_sha256:
        input.observation.defaultBranchWorkflowObservationSha256,
      ref: input.activation.controllerRef,
      ref_type: input.activation.controllerRefType,
      repository_id: TRUST.controllerRepositoryId,
      run_attempt: input.auth.runAttempt,
      run_id: positiveSafeInteger(input.auth.runId),
      tag_object_sha: input.activation.controllerTagObjectSha,
      workflow_id: input.activation.controllerWorkflowId,
      workflow_ref: input.activation.controllerWorkflowRef,
      workflow_sha: input.auth.workflowSha,
    },
    expires_at: expiresAt,
    provisioned: {
      controller_action_bundle_sha256: input.activation.controllerActionBundleSha256,
      controller_action_commit_sha: input.activation.controllerActionCommitSha,
      controller_action_metadata_blob_sha: input.activation.controllerActionMetadataBlobSha,
      controller_workflow_blob_sha: input.activation.controllerWorkflowBlobSha,
      controller_workflow_commit_sha: input.activation.controllerWorkflowSha,
      controller_workflow_id: input.activation.controllerWorkflowId,
      controller_ref: input.activation.controllerRef,
      controller_ref_type: input.activation.controllerRefType,
      controller_tag_object_sha: input.activation.controllerTagObjectSha,
      controller_peeled_commit_sha: input.activation.controllerWorkflowSha,
      digest: input.activation.provisionedDigest,
      record_id: input.activation.provisionedRecordId,
      worker_version_id: input.activation.workerVersionId,
      worm_version_id: input.snapshot.provisioned.worm.versionId,
    },
    request_id: input.requestId,
    schema: ACTIVATION_PROOF_SCHEMA,
    schema_version: 1,
  };
  const proof: JsonObject = {
    ...body,
    proof_sha256: `sha256:${await sha256Hex(canonicalBytes(body))}`,
  };
  assert(
    canonicalBytes(proof).byteLength > 0 && canonicalBytes(proof).byteLength <= LIMITS.bodyBytes,
    "ACTIVATION_PROOF_SIZE_INVALID",
    503,
  );
  return proof;
}

function assertCurrentHeadBinding(
  proof: JsonObject,
  input: {
    readonly activation: ActivationTrust;
    readonly requestId: string;
    readonly snapshot: ActivationSnapshot;
  },
  nowMs: number,
): void {
  const activated = input.snapshot.activated;
  assert(activated !== null, "BROKER_PROVISIONING", 503);
  const head = exactObject(proof.head, [
    "activated",
    "activated_service_authorities_sha256",
    "committed_at",
    "generation",
    "ingress_worker_version_id",
    "previous",
    "record_id",
    "schema",
    "schema_version",
  ]);
  const headActivated = exactObject(head.activated, ["record_id", "record_sha256", "worm"]);
  const acceptedAt = Date.parse(
    requireString(
      proof,
      "broker_accepted_at",
      32,
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u,
    ),
  );
  const activatedCommittedAt = Date.parse(
    requireString(
      activated.envelope,
      "committed_at",
      32,
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u,
    ),
  );
  const headCommittedAt = Date.parse(
    requireString(head, "committed_at", 32, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u),
  );
  const expectedActivatedWorm: JsonObject = {
    digest: activated.worm.digest,
    key: activated.worm.key,
    retention_until: activated.worm.retentionUntil,
    version_id: activated.worm.versionId,
  };
  assert(
    proof.request_id === input.requestId &&
      acceptedAt <= nowMs &&
      nowMs - acceptedAt <= 60_000 &&
      activatedCommittedAt <= headCommittedAt &&
      headActivated.record_id === activated.recordId &&
      headActivated.record_sha256 === activated.digest &&
      canonicalJson(headActivated.worm) === canonicalJson(expectedActivatedWorm) &&
      Date.parse(activated.worm.retentionUntil) >= activatedCommittedAt + 2557 * 86_400_000 &&
      head.activated_service_authorities_sha256 ===
        activatedServiceAuthoritiesSha256(activated.envelope) &&
      head.ingress_worker_version_id === input.activation.workerVersionId,
    "ACTIVATION_PROOF_HEAD_MISMATCH",
    503,
  );
}

function canonicalUtcSeconds(value: number): string {
  assert(Number.isSafeInteger(value) && value >= 0, "ACTIVATION_PROOF_TIME_INVALID", 500);
  return new Date(value).toISOString().replace(".000Z", "Z");
}

function positiveSafeInteger(value: string): number {
  assert(/^[1-9][0-9]{0,15}$/u.test(value), "OIDC_RUN_ID_INVALID", 401);
  const parsed = Number(value);
  assert(Number.isSafeInteger(parsed), "OIDC_RUN_ID_INVALID", 401);
  return parsed;
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, expected.length) === expected,
    "ACTIVATION_PROOF_REQUEST_INVALID",
  );
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "ACTIVATION_PROOF_REQUEST_INVALID",
  );
}
