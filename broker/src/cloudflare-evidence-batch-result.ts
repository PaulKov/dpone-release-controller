import { assertSanitizedCloudflareEvidenceRecord } from "./cloudflare-deployment-observation";
import {
  type CloudflareEvidenceBatchBinding,
  type CloudflareEvidenceBatchContext,
  type CloudflareEvidenceBatchSlot,
  type ConfirmedCloudflareEvidence,
  CLOUDFLARE_EVIDENCE_SLOT_COUNT,
  cloudflareEvidenceWormKey,
} from "./cloudflare-evidence-batch-contract";
import {
  B2_OBSERVER_IDENTITY,
  BATCH_DIGEST,
  BATCH_RETENTION_MILLISECONDS,
  BATCH_TIMESTAMP,
  BATCH_UUID,
  WORM_IDENTITY,
  batchFail,
  canonicalBatchTimestamp,
  requireBatchInteger,
  requireBatchLiteral,
  requireBatchObject,
  requireBatchObjectArray,
} from "./cloudflare-evidence-batch-codec";
import { validateCloudflareEvidenceBatchObservation } from "./cloudflare-evidence-batch-context";
import { SERVICE_AUTHORITY_ROLES } from "./service-authority";
import type { ActivationWorm, JsonObject, JsonValue } from "./types";
import { exactObject, requireString } from "./validation";

export const CLOUDFLARE_EVIDENCE_BATCH_RESULT_SCHEMA =
  "dpone.cloudflare-evidence-worm-batch-result.v1";

export interface ConfirmedCloudflareEvidenceBatch {
  readonly b2ObserverServiceIdentity: string;
  readonly binding: CloudflareEvidenceBatchBinding;
  readonly committedAt: string;
  readonly network: ConfirmedCloudflareEvidence;
  readonly observation: JsonObject;
  readonly providerObservationSha256: string;
  readonly services: readonly ConfirmedCloudflareEvidence[];
  readonly wormWorkerVersionId: string;
  readonly wormServiceIdentity: string;
}

/** Build the canonical sanitized-only result returned by the WORM batch DO. */
export function buildCloudflareEvidenceBatchResult(
  context: CloudflareEvidenceBatchContext,
  slots: readonly CloudflareEvidenceBatchSlot[],
): JsonObject {
  const { binding, execution } = context;
  if (
    slots.length !== CLOUDFLARE_EVIDENCE_SLOT_COUNT ||
    !B2_OBSERVER_IDENTITY.test(execution.b2ObserverServiceIdentity) ||
    !WORM_IDENTITY.test(execution.wormServiceIdentity)
  ) {
    batchFail("BATCH_RESULT_INVALID");
  }
  const records = slots.map((slot, slotIndex) => {
    if (slot.slotIndex !== slotIndex || slot.status !== "CONFIRMED" || slot.worm === null) {
      batchFail("BATCH_RESULT_INVALID");
    }
    return {
      authority_role: slot.authorityRole,
      kind: slot.kind,
      record: slot.sanitized.record,
      record_id: slot.sanitized.recordId,
      record_sha256: slot.sanitized.recordSha256,
      slot_index: slot.slotIndex,
      worm: wormProjection(slot.worm),
    };
  });
  const providerObservationSha256 = records[0]?.record.provider_observation_sha256;
  const committedAt = slots[0]?.committedAt;
  if (
    typeof providerObservationSha256 !== "string" ||
    !BATCH_DIGEST.test(providerObservationSha256) ||
    providerObservationSha256 !== context.providerObservationSha256 ||
    typeof committedAt !== "string" ||
    committedAt !== context.committedAt ||
    slots.some((slot) => slot.committedAt !== committedAt)
  ) {
    batchFail("BATCH_RESULT_INVALID");
  }
  return {
    b2_observer_service_identity: execution.b2ObserverServiceIdentity,
    batch_id: binding.batchId,
    committed_at: canonicalBatchTimestamp(committedAt),
    expectation_sha256: binding.expectationSha256,
    observation: context.observation,
    observer_worker_version_id: binding.observerWorkerVersionId,
    phase: binding.phase,
    provider_observation_sha256: providerObservationSha256,
    records,
    schema: CLOUDFLARE_EVIDENCE_BATCH_RESULT_SCHEMA,
    schema_version: 1,
    worker_version_id: execution.wormWorkerVersionId,
    worm_service_identity: execution.wormServiceIdentity,
  };
}

/** Parse and cross-bind a sanitized result at the observer/client edge. */
export async function parseCloudflareEvidenceBatchResult(
  value: unknown,
  expected: CloudflareEvidenceBatchBinding,
  expectedWormWorkerVersionId: string,
  expectedB2ObserverServiceIdentity: string,
  expectedWormServiceIdentity: string,
): Promise<ConfirmedCloudflareEvidenceBatch> {
  const result = exactObject(value, [
    "b2_observer_service_identity",
    "batch_id",
    "committed_at",
    "expectation_sha256",
    "observation",
    "observer_worker_version_id",
    "phase",
    "provider_observation_sha256",
    "records",
    "schema",
    "schema_version",
    "worker_version_id",
    "worm_service_identity",
  ]);
  requireBatchLiteral(result, "schema", CLOUDFLARE_EVIDENCE_BATCH_RESULT_SCHEMA);
  requireBatchInteger(result, "schema_version", 1);
  if (
    result.batch_id !== expected.batchId ||
    result.expectation_sha256 !== expected.expectationSha256 ||
    result.observer_worker_version_id !== expected.observerWorkerVersionId ||
    result.phase !== expected.phase
  ) {
    batchFail("BATCH_RESULT_BINDING_INVALID");
  }
  const wormWorkerVersionId = requireString(result, "worker_version_id", 36, BATCH_UUID);
  if (
    wormWorkerVersionId !== expectedWormWorkerVersionId ||
    requireString(result, "worm_service_identity", 512, WORM_IDENTITY) !==
      expectedWormServiceIdentity
  ) {
    batchFail("BATCH_RESULT_WORKER_INVALID");
  }
  if (
    requireString(result, "b2_observer_service_identity", 512, B2_OBSERVER_IDENTITY) !==
    expectedB2ObserverServiceIdentity
  ) {
    batchFail("BATCH_RESULT_OBSERVER_INVALID");
  }
  const providerObservationSha256 = requireString(
    result,
    "provider_observation_sha256",
    71,
    BATCH_DIGEST,
  );
  const committedAt = canonicalBatchTimestamp(
    requireString(result, "committed_at", 24, BATCH_TIMESTAMP),
  );
  const records = requireBatchObjectArray(result.records, CLOUDFLARE_EVIDENCE_SLOT_COUNT);
  const parsed = await Promise.all(
    records.map((record, slotIndex) =>
      parseConfirmedRecord(record, slotIndex, expected, committedAt),
    ),
  );
  if (
    parsed.some((entry) => entry.record.provider_observation_sha256 !== providerObservationSha256)
  ) {
    batchFail("BATCH_RESULT_BINDING_INVALID");
  }
  const network = parsed.at(-1);
  if (network === undefined) batchFail("BATCH_RESULT_INVALID");
  const observation = await validateCloudflareEvidenceBatchObservation(
    requireBatchObject(result.observation),
    expected,
    requireString(requireBatchObject(result.observation), "observed_at", 24, BATCH_TIMESTAMP),
    parsed.map((entry, slotIndex) => ({
      authorityRole: SERVICE_AUTHORITY_ROLES[slotIndex] ?? null,
      kind:
        slotIndex === CLOUDFLARE_EVIDENCE_SLOT_COUNT - 1
          ? "cloudflare_network_surface"
          : "cloudflare_service_deployments",
      sanitized: entry,
      slotIndex,
    })),
  );
  if (observation.provider_observation_sha256 !== providerObservationSha256) {
    batchFail("BATCH_RESULT_BINDING_INVALID");
  }
  return {
    b2ObserverServiceIdentity: expectedB2ObserverServiceIdentity,
    binding: expected,
    committedAt,
    network,
    observation,
    providerObservationSha256,
    services: Object.freeze(parsed.slice(0, -1)),
    wormWorkerVersionId,
    wormServiceIdentity: expectedWormServiceIdentity,
  };
}

async function parseConfirmedRecord(
  value: JsonObject,
  slotIndex: number,
  expected: CloudflareEvidenceBatchBinding,
  committedAt: string,
): Promise<ConfirmedCloudflareEvidence> {
  const row = exactObject(value, [
    "authority_role",
    "kind",
    "record",
    "record_id",
    "record_sha256",
    "slot_index",
    "worm",
  ]);
  requireBatchInteger(row, "slot_index", slotIndex);
  const expectedRole = SERVICE_AUTHORITY_ROLES[slotIndex] ?? null;
  const expectedKind =
    expectedRole === null ? "cloudflare_network_surface" : "cloudflare_service_deployments";
  if (row.authority_role !== expectedRole || row.kind !== expectedKind) {
    batchFail("BATCH_RESULT_ORDER_INVALID");
  }
  const sanitized = await assertSanitizedCloudflareEvidenceRecord(row.record);
  if (
    row.record_id !== sanitized.recordId ||
    row.record_sha256 !== sanitized.recordSha256 ||
    sanitized.record.expectation_sha256 !== expected.expectationSha256 ||
    sanitized.record.observer_worker_version_id !== expected.observerWorkerVersionId ||
    sanitized.record.phase !== expected.phase
  ) {
    batchFail("BATCH_RESULT_BINDING_INVALID");
  }
  return {
    ...sanitized,
    worm: parseWorm(row.worm, sanitized, expected, expectedKind, committedAt),
  };
}

function parseWorm(
  value: JsonValue | undefined,
  sanitized: Awaited<ReturnType<typeof assertSanitizedCloudflareEvidenceRecord>>,
  expected: CloudflareEvidenceBatchBinding,
  kind: "cloudflare_network_surface" | "cloudflare_service_deployments",
  committedAt: string,
): ActivationWorm {
  const worm = exactObject(value, ["digest", "key", "retention_until", "version_id"]);
  const retentionUntil = canonicalBatchTimestamp(
    requireString(worm, "retention_until", 24, BATCH_TIMESTAMP),
  );
  const observedAt = canonicalBatchTimestamp(
    requireString(sanitized.record, "observed_at", 24, BATCH_TIMESTAMP),
  );
  const versionId = requireString(worm, "version_id", 512);
  if (
    worm.digest !== sanitized.recordSha256 ||
    worm.key !==
      cloudflareEvidenceWormKey(expected.observerWorkerVersionId, kind, sanitized.recordId) ||
    versionId.length === 0 ||
    Date.parse(committedAt) < Date.parse(observedAt) ||
    Date.parse(committedAt) - Date.parse(observedAt) > 60_000 ||
    Date.parse(retentionUntil) < Date.parse(committedAt) + BATCH_RETENTION_MILLISECONDS
  ) {
    batchFail("BATCH_RESULT_WORM_INVALID");
  }
  return {
    digest: sanitized.recordSha256,
    key: worm.key,
    retentionUntil,
    versionId,
  };
}

function wormProjection(worm: ActivationWorm): JsonObject {
  return {
    digest: worm.digest,
    key: worm.key,
    retention_until: worm.retentionUntil,
    version_id: worm.versionId,
  };
}
