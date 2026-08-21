import type { ActivationOperationCloudflareRequest } from "./activation-operation-cloudflare-request";
import {
  batchFail,
  requireBatchInteger,
  requireBatchLiteral,
  requireBatchObject,
} from "./cloudflare-evidence-batch-codec";
import type { CloudflareEvidenceBatchBindingV2 } from "./cloudflare-evidence-batch-contract";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export const CLOUDFLARE_EVIDENCE_BATCH_RESUME_RPC_PATH_V2 =
  "/rpc/v2/cloudflare-evidence/batch/resume" as const;
export const CLOUDFLARE_EVIDENCE_BATCH_RESUME_SCHEMA_V2 =
  "dpone.cloudflare-evidence-worm-batch-resume.v2";
export const CLOUDFLARE_EVIDENCE_BATCH_RESUME_MISSING_SCHEMA_V2 =
  "dpone.cloudflare-evidence-worm-batch-resume-missing.v2";
export const MAX_CLOUDFLARE_EVIDENCE_BATCH_RESUME_BYTES = 4_096;

const DIGEST = /^sha256:[0-9a-f]{64}$/u;

export interface CloudflareEvidenceBatchResumeV2 {
  readonly binding: Pick<
    CloudflareEvidenceBatchBindingV2,
    "activationIssuanceId" | "activationIssuanceOrdinal" | "activationSequence" | "batchId"
  >;
  readonly delegationSha256: string;
}

export function buildCloudflareEvidenceBatchResumeV2(
  delegation: ActivationOperationCloudflareRequest,
): JsonObject {
  const binding = delegation.binding;
  return {
    activation_issuance_id: binding.activationIssuanceId,
    activation_issuance_ordinal: binding.activationIssuanceOrdinal,
    activation_sequence: binding.activationSequence,
    batch_id: binding.batchId,
    delegation_sha256: delegation.delegationSha256,
    schema: CLOUDFLARE_EVIDENCE_BATCH_RESUME_SCHEMA_V2,
    schema_version: 2,
  };
}

export function parseCloudflareEvidenceBatchResumeV2(
  value: unknown,
): CloudflareEvidenceBatchResumeV2 {
  const body = exactObject(value, [
    "activation_issuance_id",
    "activation_issuance_ordinal",
    "activation_sequence",
    "batch_id",
    "delegation_sha256",
    "schema",
    "schema_version",
  ]);
  requireBatchLiteral(body, "schema", CLOUDFLARE_EVIDENCE_BATCH_RESUME_SCHEMA_V2);
  requireBatchInteger(body, "schema_version", 2);
  return {
    binding: {
      activationIssuanceId: requireString(body, "activation_issuance_id", 71, DIGEST),
      activationIssuanceOrdinal: requireInteger(body, "activation_issuance_ordinal", 1, 1_000_000),
      activationSequence: requireInteger(body, "activation_sequence", 0, 1) as 0 | 1,
      batchId: requireString(body, "batch_id", 71, DIGEST),
    },
    delegationSha256: requireString(body, "delegation_sha256", 71, DIGEST),
  };
}

export function buildCloudflareEvidenceBatchResumeMissingV2(
  expected: CloudflareEvidenceBatchResumeV2,
): JsonObject {
  return {
    batch_id: expected.binding.batchId,
    delegation_sha256: expected.delegationSha256,
    schema: CLOUDFLARE_EVIDENCE_BATCH_RESUME_MISSING_SCHEMA_V2,
    schema_version: 2,
    status: "MISSING",
  };
}

export function isCloudflareEvidenceBatchResumeMissingV2(
  value: unknown,
  expected: CloudflareEvidenceBatchResumeV2,
): boolean {
  const body = requireBatchObject(value);
  if (body.schema !== CLOUDFLARE_EVIDENCE_BATCH_RESUME_MISSING_SCHEMA_V2) return false;
  const missing = exactObject(body, [
    "batch_id",
    "delegation_sha256",
    "schema",
    "schema_version",
    "status",
  ]);
  requireBatchLiteral(missing, "schema", CLOUDFLARE_EVIDENCE_BATCH_RESUME_MISSING_SCHEMA_V2);
  requireBatchInteger(missing, "schema_version", 2);
  if (
    missing.status !== "MISSING" ||
    missing.batch_id !== expected.binding.batchId ||
    missing.delegation_sha256 !== expected.delegationSha256
  ) {
    batchFail("BATCH_RESUME_BINDING_INVALID");
  }
  return true;
}
