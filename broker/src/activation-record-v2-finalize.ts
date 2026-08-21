import {
  ACTIVATION_RECORD_V2_UUID,
  exactRecordV2Object,
  recordV2Digest,
  recordV2Fail,
  recordV2Integer,
  recordV2String,
  recordV2Timestamp,
} from "./activation-record-v2-codec";
import {
  parseActivationRecordV2Worm,
  validateActivationRecordV2Worm,
} from "./activation-record-v2-evidence";
import { activationRecordV2WormKey } from "./activation-record-v2-identity";
import type { JsonObject } from "./types";

const SHA1 = /^[0-9a-f]{40}$/u;
const SAFE_PATH = /^[A-Za-z0-9._/-]{1,512}$/u;
const REPOSITORY = /^[A-Za-z0-9_.-]{1,64}\/[A-Za-z0-9_.-]{1,64}$/u;

export interface ParsedActivationRecordV2Finalize {
  readonly completedAt: string;
  readonly provisionedRecordId: string;
  readonly provisionedRecordSha256: string;
  readonly provisionedRetentionUntil: string;
  readonly semantic: JsonObject;
  readonly startedAt: string;
}

/** Validate the exact A1 request-derived subtrees before deriving its semantic intent. */
export function validateActivationRecordV2Finalize(
  root: JsonObject,
  workerVersionId: string,
): ParsedActivationRecordV2Finalize {
  const approvals = validateApprovals(root.approvals);
  const promotion = validatePromotion(root.promotion, workerVersionId);
  const provisioned = validateProvisioned(root.provisioned, workerVersionId);
  const target = validateTarget(root.target);
  return {
    completedAt: promotion.completedAt,
    provisionedRecordId: provisioned.recordId,
    provisionedRecordSha256: provisioned.recordSha256,
    provisionedRetentionUntil: provisioned.retentionUntil,
    semantic: {
      approvals,
      promotion: promotion.document,
      provisioned: provisioned.document,
      target,
    },
    startedAt: promotion.startedAt,
  };
}

function validateApprovals(value: unknown): JsonObject {
  const approvals = exactRecordV2Object(value, [
    "adr_sha256",
    "feature_design_sha256",
    "final_diff_sha256",
    "independent_review_receipt_id",
    "owner_approval_receipt_id",
  ]);
  Object.keys(approvals).forEach((key) => recordV2Digest(approvals, key));
  return approvals;
}

function validatePromotion(
  value: unknown,
  workerVersionId: string,
): { readonly completedAt: string; readonly document: JsonObject; readonly startedAt: string } {
  const promotion = exactRecordV2Object(value, [
    "completed_at",
    "deployment_id",
    "promotion_report_record_id",
    "promotion_report_record_sha256",
    "promotion_report_worm",
    "provider_observation_sha256",
    "started_at",
    "worker_version_id",
  ]);
  const startedAt = recordV2Timestamp(promotion, "started_at");
  const completedAt = recordV2Timestamp(promotion, "completed_at");
  recordV2String(promotion, "deployment_id", ACTIVATION_RECORD_V2_UUID, 36);
  recordV2Digest(promotion, "promotion_report_record_id");
  const reportSha256 = recordV2Digest(promotion, "promotion_report_record_sha256");
  recordV2Digest(promotion, "provider_observation_sha256");
  if (
    recordV2String(promotion, "worker_version_id", ACTIVATION_RECORD_V2_UUID, 36) !==
      workerVersionId ||
    Date.parse(startedAt) > Date.parse(completedAt)
  ) {
    recordV2Fail("ACTIVATION_RECORD_V2_PROMOTION_INVALID");
  }
  const worm = validateActivationRecordV2Worm(
    promotion.promotion_report_worm,
    reportSha256,
    completedAt,
  );
  if (!/^receipts\/v1\/deployment-observations\/[A-Za-z0-9._/-]{1,460}\.json$/u.test(worm.key)) {
    recordV2Fail("ACTIVATION_RECORD_V2_PROMOTION_INVALID");
  }
  return { completedAt, document: promotion, startedAt };
}

function validateProvisioned(
  value: unknown,
  workerVersionId: string,
): {
  readonly document: JsonObject;
  readonly recordId: string;
  readonly recordSha256: string;
  readonly retentionUntil: string;
} {
  const provisioned = exactRecordV2Object(value, [
    "component_set_id",
    "manifest_pointer_sha256",
    "record_id",
    "record_sha256",
    "resolved_projection_sha256",
    "worker_version_id",
    "worm",
  ]);
  recordV2Digest(provisioned, "component_set_id");
  recordV2Digest(provisioned, "manifest_pointer_sha256");
  const recordId = recordV2Digest(provisioned, "record_id");
  const recordSha256 = recordV2Digest(provisioned, "record_sha256");
  recordV2Digest(provisioned, "resolved_projection_sha256");
  if (
    recordV2String(provisioned, "worker_version_id", ACTIVATION_RECORD_V2_UUID, 36) !==
    workerVersionId
  ) {
    recordV2Fail("ACTIVATION_RECORD_V2_PREDECESSOR_INVALID");
  }
  const worm = parseActivationRecordV2Worm(
    provisioned.worm,
    recordSha256,
    activationRecordV2WormKey(workerVersionId, 0, recordSha256),
  );
  return { document: provisioned, recordId, recordSha256, retentionUntil: worm.retentionUntil };
}

function validateTarget(value: unknown): JsonObject {
  const target = exactRecordV2Object(value, [
    "commit_sha",
    "policy_blob_sha",
    "policy_path",
    "policy_sha256",
    "repository",
    "repository_id",
    "runtime_oidc_rehearsal",
    "runtime_workflow_blob_sha",
    "runtime_workflow_path",
    "runtime_workflow_sha256",
    "tree_sha",
  ]);
  const commitSha = recordV2String(target, "commit_sha", SHA1, 40);
  recordV2String(target, "tree_sha", SHA1, 40);
  recordV2String(target, "policy_blob_sha", SHA1, 40);
  recordV2String(target, "policy_path", SAFE_PATH);
  recordV2Digest(target, "policy_sha256");
  recordV2String(target, "repository", REPOSITORY, 129);
  const repositoryId = recordV2Integer(target, "repository_id", 1, Number.MAX_SAFE_INTEGER);
  recordV2String(target, "runtime_workflow_blob_sha", SHA1, 40);
  recordV2String(target, "runtime_workflow_path", SAFE_PATH);
  recordV2Digest(target, "runtime_workflow_sha256");
  const rehearsal = exactRecordV2Object(target.runtime_oidc_rehearsal, [
    "check_run_id",
    "evidence_sha256",
    "jti_sha256",
    "repository_id",
    "workflow_sha",
  ]);
  recordV2String(rehearsal, "check_run_id", /^[1-9][0-9]{0,31}$/u, 32);
  recordV2Digest(rehearsal, "evidence_sha256");
  recordV2Digest(rehearsal, "jti_sha256");
  if (
    recordV2Integer(rehearsal, "repository_id", repositoryId, repositoryId) !== repositoryId ||
    recordV2String(rehearsal, "workflow_sha", SHA1, 40) !== commitSha
  ) {
    recordV2Fail("ACTIVATION_RECORD_V2_TARGET_INVALID");
  }
  return target;
}
