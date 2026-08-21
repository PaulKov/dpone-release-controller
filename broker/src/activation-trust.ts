import {
  POSITIVE_ID,
  SAFE_NAME,
  type SERVICE_BINDINGS,
  SHA1,
  WORKER_VERSION,
} from "./activation-contract";
import { requireDigest, stringArray } from "./activation-fields";
import { extractPrivateServicePins, servicePin } from "./activation-infrastructure";
import { parseActivatedEnvelope, parseProvisionedEnvelope } from "./activation-records";
import { controllerActionFromProvisioned } from "./activation-controller-action";
import type { ProvisionRequest } from "./activation-schema-types";
import { TRUST } from "./config";
import { assert, BrokerError } from "./errors";
import type {
  ActivationSnapshot,
  ActivationTrust,
  ControllerActivationTrust,
  JsonObject,
  PrivateServicePin,
} from "./types";
import { requireInteger, requireObject, requireString } from "./validation";

export function assertObservedAtBounded(observedAt: string, nowMs: number): void {
  const observedMs = Date.parse(observedAt);
  assert(
    Number.isFinite(observedMs) && observedMs <= nowMs + 30_000 && observedMs >= nowMs - 900_000,
    "ACTIVATION_OBSERVED_AT_OUT_OF_BOUNDS",
    409,
  );
}

export function controllerTrustFromSnapshot(
  snapshot: ActivationSnapshot,
  currentWorkerVersionId: string,
): ControllerActivationTrust {
  const record = parseProvisionedEnvelope(snapshot.provisioned.envelope);
  assert(snapshot.provisioned.recordId === record.recordId, "ACTIVATION_RECORD_ID_MISMATCH", 503);
  const broker = record.broker;
  const controllerRunReaderApp = requireObject(
    record.githubApps.controller_run_reader,
    "ACTIVATION_CONTROLLER_RUN_READER_APP_INVALID",
  );
  const workerVersionId = requireString(broker, "worker_version_id", 128, WORKER_VERSION);
  assert(workerVersionId === currentWorkerVersionId, "ACTIVATION_DEPLOYMENT_VERSION_MISMATCH", 503);
  return {
    ...controllerActionFromProvisioned(record.controller),
    controllerActorIds: new Set(stringArray(record.oidc, "controller_actor_ids")),
    controllerDefaultBranchWorkflowBlobSha: requireString(
      record.controller,
      "default_branch_workflow_blob_sha",
      40,
      SHA1,
    ),
    controllerWorkflowBlobSha: requireString(record.controller, "workflow_blob_sha", 40, SHA1),
    controllerWorkflowId: requireInteger(record.controller, "workflow_id", 1),
    controllerRef: requireString(
      record.controller,
      "ref",
      80,
      /^refs\/tags\/v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u,
    ),
    controllerRefType: "tag",
    controllerTagObjectSha: requireString(record.controller, "tag_object_sha", 40, SHA1),
    controllerWorkflowRef:
      `${TRUST.controllerRepository}/${TRUST.controllerWorkflowPath}@` +
      requireString(record.controller, "ref", 80),
    controllerWorkflowSha: requireString(record.controller, "production_commit_sha", 40, SHA1),
    controllerRunReaderApp: {
      appId: requireString(controllerRunReaderApp, "app_id", 32, POSITIVE_ID),
      appSlug: requireString(controllerRunReaderApp, "app_slug", 128, SAFE_NAME),
      installationId: requireString(controllerRunReaderApp, "installation_id", 32, POSITIVE_ID),
    },
    provisionedDigest: snapshot.provisioned.digest,
    provisionedRecordId: snapshot.provisioned.recordId,
    privateServices: extractPrivateServicePins(broker),
    repositoryOwnerId: requireString(record.oidc, "repository_owner_id", 32, POSITIVE_ID),
    workerVersionId,
  };
}

export function provisionRequestServicePin(
  request: ProvisionRequest,
  role: keyof typeof SERVICE_BINDINGS,
): PrivateServicePin {
  return servicePin(request.broker, role);
}

export function provisionedRecordServicePin(
  envelope: JsonObject,
  role: keyof typeof SERVICE_BINDINGS,
): PrivateServicePin {
  const record = parseProvisionedEnvelope(envelope);
  return servicePin(record.broker, role);
}

export function activationTrustFromSnapshot(
  snapshot: ActivationSnapshot,
  currentWorkerVersionId: string,
): ActivationTrust {
  const controller = controllerTrustFromSnapshot(snapshot, currentWorkerVersionId);
  if (snapshot.activated === null) {
    throw new BrokerError("BROKER_PROVISIONING", 503, true);
  }
  const activated = parseActivatedEnvelope(snapshot.activated.envelope);
  assert(
    activated.recordId === snapshot.activated.recordId &&
      activated.previous === snapshot.provisioned.recordId &&
      activated.provisioned.record_id === snapshot.provisioned.recordId &&
      activated.provisioned.digest === snapshot.provisioned.digest &&
      activated.provisioned.worker_version_id === currentWorkerVersionId &&
      activated.provisioned.worm_key === snapshot.provisioned.worm.key &&
      activated.provisioned.worm_version_id === snapshot.provisioned.worm.versionId,
    "ACTIVATION_CHAIN_MISMATCH",
    503,
  );
  const provisioned = parseProvisionedEnvelope(snapshot.provisioned.envelope);
  assert(
    activated.controllerActionBundleSha256 === controller.controllerActionBundleSha256 &&
      activated.controllerActionCommitSha === controller.controllerActionCommitSha &&
      activated.controllerActionMetadataBlobSha === controller.controllerActionMetadataBlobSha,
    "ACTIVATION_CONTROLLER_ACTION_CHAIN_MISMATCH",
    503,
  );
  return {
    ...controller,
    activatedDigest: snapshot.activated.digest,
    activatedRecordId: snapshot.activated.recordId,
    runtimeActorIds: new Set(stringArray(provisioned.oidc, "runtime_actor_ids")),
    targetBranchRulesetEvidenceSha256: requireDigest(
      provisioned.targetGovernance,
      "branch_ruleset_evidence_sha256",
    ),
    targetBranchRulesetId: requireString(
      provisioned.targetGovernance,
      "branch_ruleset_id",
      32,
      /^[1-9][0-9]{0,31}$/u,
    ),
    targetBranchRulesetProjectionSha256: requireDigest(
      provisioned.targetGovernance,
      "branch_ruleset_projection_sha256",
    ),
    targetDefaultBranchRef: TRUST.targetDefaultBranchRef,
    targetPolicyBlobSha: requireString(activated.target, "policy_blob_sha", 40, SHA1),
    targetPolicyCommitSha: requireString(activated.target, "commit_sha", 40, SHA1),
    targetPolicySha256: requireDigest(activated.target, "policy_sha256"),
    targetRuntimeWorkflowBlobSha: requireString(
      activated.target,
      "runtime_workflow_blob_sha",
      40,
      SHA1,
    ),
    targetRuntimeWorkflowSha256: requireDigest(activated.target, "runtime_workflow_sha256"),
  };
}
