import { canonicalBytes, canonicalJson } from "./canonical";
import {
  parseEmbeddedActivationOperationCloudflareRequest,
  type ActivationOperationCloudflareRequest,
} from "./activation-operation-cloudflare-request";
import {
  type CloudflareDeploymentObservationResult,
  assertCloudflareDeploymentEvidenceSet,
  sanitizeCloudflareNetworkEvidence,
  sanitizeCloudflareServiceEvidence,
} from "./cloudflare-deployment-observation";
import {
  CLOUDFLARE_EVIDENCE_SLOT_COUNT,
  cloudflareEvidenceBatchBinding,
  type CloudflareEvidenceBatchBinding,
  type CloudflareEvidenceBatchBindingV2,
  type CloudflareEvidenceBatchSlotInput,
} from "./cloudflare-evidence-batch-contract";
import {
  BATCH_DIGEST,
  BATCH_TIMESTAMP,
  BATCH_UUID,
  batchFail,
  canonicalBatchTimestamp,
  requireBatchInteger,
  requireBatchLiteral,
  requireBatchObject,
  requireBatchObjectArray,
} from "./cloudflare-evidence-batch-codec";
import { SERVICE_AUTHORITY_ROLES } from "./service-authority";
import type { JsonObject } from "./types";
import { exactObject, requireString } from "./validation";

export {
  buildCloudflareEvidenceBatchResult,
  CLOUDFLARE_EVIDENCE_BATCH_RESULT_SCHEMA,
  parseCloudflareEvidenceBatchResult,
  type ConfirmedCloudflareEvidenceBatch,
} from "./cloudflare-evidence-batch-result";

export const CLOUDFLARE_EVIDENCE_BATCH_RPC_PATH = "/rpc/v1/cloudflare-evidence/batch" as const;
export const CLOUDFLARE_EVIDENCE_BATCH_RPC_PATH_V2 = "/rpc/v2/cloudflare-evidence/batch" as const;
export const CLOUDFLARE_EVIDENCE_BATCH_REQUEST_SCHEMA =
  "dpone.cloudflare-evidence-worm-batch-request.v1";
export const CLOUDFLARE_EVIDENCE_BATCH_REQUEST_SCHEMA_V2 =
  "dpone.cloudflare-evidence-worm-batch-request.v2";
export const MAX_CLOUDFLARE_EVIDENCE_BATCH_RPC_BYTES = 1_048_576;

export interface PreparedCloudflareEvidenceBatch {
  readonly binding: CloudflareEvidenceBatchBinding;
  readonly observation: JsonObject;
  readonly observedAt: string;
  readonly slots: readonly CloudflareEvidenceBatchSlotInput[];
}

export interface PreparedCloudflareEvidenceBatchV2
  extends Omit<PreparedCloudflareEvidenceBatch, "binding"> {
  readonly batchSealedAt: string;
  readonly binding: CloudflareEvidenceBatchBindingV2;
  readonly delegation: ActivationOperationCloudflareRequest;
}

/** Build the one transient-only batch request sent to the WORM trust boundary. */
export function buildCloudflareEvidenceBatchRequest(
  result: CloudflareDeploymentObservationResult,
): JsonObject {
  return {
    network_surface_evidence_entry: result.networkEvidenceEntry,
    observation: result.observation,
    schema: CLOUDFLARE_EVIDENCE_BATCH_REQUEST_SCHEMA,
    schema_version: 1,
    service_evidence_entries: [...result.evidenceEntries],
  };
}

/** Build an issuance-scoped request without changing the legacy v1 codec. */
export function buildCloudflareEvidenceBatchRequestV2(
  result: CloudflareDeploymentObservationResult,
  delegation: ActivationOperationCloudflareRequest,
  batchSealedAt: string,
): JsonObject {
  return {
    batch_sealed_at: batchSealedAt,
    delegation: delegation.document,
    delegation_sha256: delegation.delegationSha256,
    network_surface_evidence_entry: result.networkEvidenceEntry,
    observation: result.observation,
    schema: CLOUDFLARE_EVIDENCE_BATCH_REQUEST_SCHEMA_V2,
    schema_version: 2,
    service_evidence_entries: [...result.evidenceEntries],
  };
}

/**
 * Independently reparse every transient provider response, then produce only
 * sanitized slot bytes. Callers must never persist the supplied request.
 */
export async function prepareCloudflareEvidenceBatch(
  value: unknown,
): Promise<PreparedCloudflareEvidenceBatch> {
  const body = exactObject(value, [
    "network_surface_evidence_entry",
    "observation",
    "schema",
    "schema_version",
    "service_evidence_entries",
  ]);
  requireBatchLiteral(body, "schema", CLOUDFLARE_EVIDENCE_BATCH_REQUEST_SCHEMA);
  requireBatchInteger(body, "schema_version", 1);
  const prepared = await prepareBatchEvidence(body);
  return {
    binding: await cloudflareEvidenceBatchBinding(
      prepared.expectationSha256,
      prepared.observerWorkerVersionId,
      prepared.phase,
    ),
    observation: prepared.observation,
    observedAt: prepared.observedAt,
    slots: prepared.slots,
  };
}

/** Reparse the operation-issued v2 batch and derive its ordinal-bound ID. */
export async function prepareCloudflareEvidenceBatchV2(
  value: unknown,
): Promise<PreparedCloudflareEvidenceBatchV2> {
  const body = exactObject(value, [
    "batch_sealed_at",
    "delegation",
    "delegation_sha256",
    "network_surface_evidence_entry",
    "observation",
    "schema",
    "schema_version",
    "service_evidence_entries",
  ]);
  requireBatchLiteral(body, "schema", CLOUDFLARE_EVIDENCE_BATCH_REQUEST_SCHEMA_V2);
  requireBatchInteger(body, "schema_version", 2);
  const delegation = await parseEmbeddedActivationOperationCloudflareRequest(body.delegation);
  const prepared = await prepareBatchEvidence(body);
  const batchSealedAt = canonicalBatchTimestamp(
    requireString(body, "batch_sealed_at", 24, BATCH_TIMESTAMP),
  );
  if (
    body.delegation_sha256 !== delegation.delegationSha256 ||
    prepared.expectationSha256 !== delegation.binding.expectationSha256 ||
    prepared.observerWorkerVersionId !== delegation.binding.observerWorkerVersionId ||
    prepared.phase !== delegation.binding.phase ||
    Date.parse(delegation.committedAt) > Date.parse(prepared.observedAt) ||
    Date.parse(prepared.observedAt) > Date.parse(batchSealedAt) ||
    Date.parse(batchSealedAt) > Date.parse(delegation.freshUntil) ||
    Date.parse(batchSealedAt) - Date.parse(delegation.issuance.issuedAt) > 60_000
  ) {
    batchFail("BATCH_BINDING_INVALID");
  }
  return {
    batchSealedAt,
    binding: delegation.binding,
    delegation,
    observation: prepared.observation,
    observedAt: prepared.observedAt,
    slots: prepared.slots,
  };
}

async function prepareBatchEvidence(body: JsonObject): Promise<{
  readonly expectationSha256: string;
  readonly observation: JsonObject;
  readonly observedAt: string;
  readonly observerWorkerVersionId: string;
  readonly phase: "A0_PRE" | "A1_PRECOMMIT";
  readonly slots: readonly CloudflareEvidenceBatchSlotInput[];
}> {
  const observation = requireBatchObject(body.observation);
  const network = requireBatchObject(body.network_surface_evidence_entry);
  const transientServices = requireBatchObjectArray(
    body.service_evidence_entries,
    CLOUDFLARE_EVIDENCE_SLOT_COUNT - 1,
  );
  await assertCloudflareDeploymentEvidenceSet(observation, transientServices, network);
  const expectationSha256 = requireString(observation, "expectation_sha256", 71, BATCH_DIGEST);
  const observerWorkerVersionId = requireString(
    observation,
    "observer_worker_version_id",
    36,
    BATCH_UUID,
  );
  const phaseValue = requireString(observation, "phase", 12);
  if (phaseValue !== "A0_PRE" && phaseValue !== "A1_PRECOMMIT") {
    batchFail("BATCH_PHASE_INVALID");
  }
  const observedAt = canonicalBatchTimestamp(
    requireString(observation, "observed_at", 24, BATCH_TIMESTAMP),
  );
  const services = await Promise.all(
    transientServices.map(async (transient, slotIndex) => ({
      authorityRole: SERVICE_AUTHORITY_ROLES[slotIndex] ?? null,
      kind: "cloudflare_service_deployments" as const,
      sanitized: await sanitizeCloudflareServiceEvidence(transient),
      slotIndex,
    })),
  );
  return {
    expectationSha256,
    observation,
    observedAt,
    observerWorkerVersionId,
    phase: phaseValue,
    slots: Object.freeze([
      ...services,
      {
        authorityRole: null,
        kind: "cloudflare_network_surface",
        sanitized: await sanitizeCloudflareNetworkEvidence(network),
        slotIndex: services.length,
      },
    ]),
  };
}

export function canonicalCloudflareEvidenceBatchBytes(value: JsonObject): Uint8Array {
  const bytes = canonicalBytes(value);
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_CLOUDFLARE_EVIDENCE_BATCH_RPC_BYTES) {
    batchFail("BATCH_SIZE_INVALID");
  }
  return bytes;
}

export function assertCanonicalCloudflareEvidenceBatchText(value: string): JsonObject {
  const bytes = new TextEncoder().encode(value);
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_CLOUDFLARE_EVIDENCE_BATCH_RPC_BYTES) {
    batchFail("BATCH_SIZE_INVALID");
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(value);
  } catch {
    batchFail("BATCH_JSON_INVALID");
  }
  const object = requireBatchObject(decoded);
  if (canonicalJson(object) !== value) batchFail("BATCH_NONCANONICAL");
  return object;
}
