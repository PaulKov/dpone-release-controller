import { canonicalJson } from "./canonical";
import type { ActivationOperationCloudflareRequest } from "./activation-operation-cloudflare-request";
import {
  assertSanitizedCloudflareEvidenceRecord,
  type SanitizedCloudflareEvidence,
} from "./cloudflare-deployment-observation";
import {
  CLOUDFLARE_EVIDENCE_SLOT_COUNT,
  cloudflareEvidenceWormKeyV2,
  type CloudflareEvidenceBatchContext,
  type CloudflareEvidenceBatchSlot,
  type ConfirmedCloudflareEvidence,
} from "./cloudflare-evidence-batch-contract";
import {
  BATCH_RETENTION_MILLISECONDS,
  BATCH_TIMESTAMP,
  BATCH_UUID,
  batchFail,
  canonicalBatchTimestamp,
  requireBatchInteger,
  requireBatchObject,
  requireBatchObjectArray,
} from "./cloudflare-evidence-batch-codec";
import {
  validateCloudflareBatchPins,
  type ActivationCloudflareBatchPins,
} from "./activation-operation-pins";
import { SERVICE_AUTHORITY_ROLES } from "./service-authority";
import type { ActivationWorm, JsonObject, JsonValue } from "./types";
import { exactObject, requireString } from "./validation";

const MAX_RESULT_BYTES = 1_048_576;
const VERSION_ID = /^[A-Za-z0-9._=-]{1,512}$/u;
const IDENTITY =
  /^cloudflare-worker:[0-9a-f]{32}\/[a-z0-9][a-z0-9-]{1,127}@[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;

export interface ConfirmedCloudflareEvidenceRecordV2 {
  readonly authorityRole: string | null;
  readonly evidence: ConfirmedCloudflareEvidence;
  readonly kind: "cloudflare_network_surface" | "cloudflare_service_deployments";
  readonly slotIndex: number;
}

export function buildCloudflareEvidenceBatchResultRecords(
  slots: readonly CloudflareEvidenceBatchSlot[],
  context: CloudflareEvidenceBatchContext,
): JsonObject[] {
  if (
    slots.length !== CLOUDFLARE_EVIDENCE_SLOT_COUNT ||
    slots.some(
      (slot, index) =>
        slot.slotIndex !== index ||
        slot.status !== "CONFIRMED" ||
        slot.worm === null ||
        slot.committedAt !== context.committedAt,
    )
  ) {
    batchFail("BATCH_RESULT_INVALID");
  }
  return slots.map((slot) => ({
    authority_role: slot.authorityRole,
    kind: slot.kind,
    record: slot.sanitized.record,
    record_id: slot.sanitized.recordId,
    record_sha256: slot.sanitized.recordSha256,
    slot_index: slot.slotIndex,
    worm: wormProjection(requireWorm(slot.worm)),
  }));
}

export async function parseCloudflareEvidenceBatchResultRecords(
  value: JsonValue | undefined,
  delegation: ActivationOperationCloudflareRequest,
  batchSealedAt: string,
  expected: {
    readonly cloudflareAccountId: string;
    readonly observedAt: string;
    readonly observerServiceIdentity: string;
  },
): Promise<readonly ConfirmedCloudflareEvidenceRecordV2[]> {
  const records = await Promise.all(
    requireBatchObjectArray(value, CLOUDFLARE_EVIDENCE_SLOT_COUNT).map((record, index) =>
      parseRecord(record, index, delegation, batchSealedAt, expected),
    ),
  );
  const fields = [
    records.map(({ evidence }) => evidence.recordId),
    records.map(({ evidence }) => evidence.recordSha256),
    records.map(({ evidence }) => evidence.worm.key),
    records.map(({ evidence }) => evidence.worm.versionId),
  ];
  if (fields.some((entries) => new Set(entries).size !== entries.length)) {
    batchFail("BATCH_RESULT_ALIAS_INVALID");
  }
  return Object.freeze(records);
}

export function parseCloudflareEvidenceBatchResultPins(
  value: JsonValue | undefined,
): ActivationCloudflareBatchPins {
  const pins = exactObject(value, ["b2_observer", "cloudflare_observer", "worm"]);
  const b2 = parsePin(pins.b2_observer);
  const cloudflare = parsePin(pins.cloudflare_observer);
  const worm = parsePin(pins.worm);
  const parsed: ActivationCloudflareBatchPins = {
    b2ObserverServiceIdentity: b2.serviceIdentity,
    b2ObserverWorkerVersionId: b2.workerVersionId,
    cloudflareObserverServiceIdentity: cloudflare.serviceIdentity,
    cloudflareObserverWorkerVersionId: cloudflare.workerVersionId,
    wormServiceIdentity: worm.serviceIdentity,
    wormWorkerVersionId: worm.workerVersionId,
  };
  validateCloudflareBatchPins(parsed);
  return parsed;
}

export function cloudflareEvidenceBatchResultPinsProjection(
  pins: ActivationCloudflareBatchPins,
): JsonObject {
  validateCloudflareBatchPins(pins);
  return {
    b2_observer: pinProjection(pins.b2ObserverServiceIdentity, pins.b2ObserverWorkerVersionId),
    cloudflare_observer: pinProjection(
      pins.cloudflareObserverServiceIdentity,
      pins.cloudflareObserverWorkerVersionId,
    ),
    worm: pinProjection(pins.wormServiceIdentity, pins.wormWorkerVersionId),
  };
}

export function assertCloudflareEvidenceBatchResultPins(
  actual: ActivationCloudflareBatchPins,
  expected: ActivationCloudflareBatchPins,
): void {
  if (
    (Object.keys(actual) as (keyof ActivationCloudflareBatchPins)[]).some(
      (key) => actual[key] !== expected[key],
    )
  ) {
    batchFail("BATCH_RESULT_WORKER_INVALID");
  }
}

export function assertCloudflareEvidenceBatchResultChronology(
  delegation: ActivationOperationCloudflareRequest,
  delegationCommittedAt: string,
  observedAt: string,
  batchSealedAt: string,
): void {
  const issued = Date.parse(delegation.issuance.issuedAt);
  const delegated = Date.parse(delegationCommittedAt);
  const observed = Date.parse(observedAt);
  const sealed = Date.parse(batchSealedAt);
  if (
    delegationCommittedAt !== delegation.committedAt ||
    issued > delegated ||
    delegated > observed ||
    observed > sealed ||
    sealed > Date.parse(delegation.freshUntil) ||
    sealed - issued > 60_000
  ) {
    batchFail("BATCH_RESULT_TIME_INVALID");
  }
}

export function decodeCanonicalCloudflareEvidenceBatchResultV2(value: Uint8Array): JsonObject {
  if (value.byteLength === 0 || value.byteLength > MAX_RESULT_BYTES) {
    batchFail("BATCH_RESULT_SIZE_INVALID");
  }
  const bytes = Uint8Array.from(value);
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const object = requireBatchObject(JSON.parse(text) as unknown);
    if (canonicalJson(object) !== text) throw new Error();
    return object;
  } catch {
    batchFail("BATCH_RESULT_NONCANONICAL");
  }
}

async function parseRecord(
  value: JsonObject,
  slotIndex: number,
  delegation: ActivationOperationCloudflareRequest,
  batchSealedAt: string,
  expected: {
    readonly cloudflareAccountId: string;
    readonly observedAt: string;
    readonly observerServiceIdentity: string;
  },
): Promise<ConfirmedCloudflareEvidenceRecordV2> {
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
  const authorityRole = SERVICE_AUTHORITY_ROLES[slotIndex] ?? null;
  const kind =
    authorityRole === null ? "cloudflare_network_surface" : "cloudflare_service_deployments";
  if (row.authority_role !== authorityRole || row.kind !== kind) {
    batchFail("BATCH_RESULT_ORDER_INVALID");
  }
  const sanitized = await assertSanitizedCloudflareEvidenceRecord(row.record);
  const binding = delegation.binding;
  if (
    row.record_id !== sanitized.recordId ||
    row.record_sha256 !== sanitized.recordSha256 ||
    sanitized.record.expectation_sha256 !== binding.expectationSha256 ||
    sanitized.record.cloudflare_account_id !== expected.cloudflareAccountId ||
    sanitized.record.observed_at !== expected.observedAt ||
    sanitized.record.observer_service_identity !== expected.observerServiceIdentity ||
    sanitized.record.observer_worker_version_id !== binding.observerWorkerVersionId ||
    sanitized.record.phase !== binding.phase
  ) {
    batchFail("BATCH_RESULT_BINDING_INVALID");
  }
  return {
    authorityRole,
    evidence: {
      ...sanitized,
      worm: parseWorm(row.worm, sanitized, delegation, kind, batchSealedAt),
    },
    kind,
    slotIndex,
  };
}

function parseWorm(
  value: JsonValue | undefined,
  sanitized: SanitizedCloudflareEvidence,
  delegation: ActivationOperationCloudflareRequest,
  kind: "cloudflare_network_surface" | "cloudflare_service_deployments",
  batchSealedAt: string,
): ActivationWorm {
  const worm = exactObject(value, ["digest", "key", "retention_until", "version_id"]);
  const retentionUntil = canonicalBatchTimestamp(
    requireString(worm, "retention_until", 24, BATCH_TIMESTAMP),
  );
  const versionId = requireString(worm, "version_id", 512, VERSION_ID);
  const expectedKey = cloudflareEvidenceWormKeyV2(
    delegation.binding.observerWorkerVersionId,
    delegation.binding.batchId,
    kind,
    sanitized.recordId,
  );
  if (
    worm.digest !== sanitized.recordSha256 ||
    worm.key !== expectedKey ||
    Date.parse(retentionUntil) < Date.parse(batchSealedAt) + BATCH_RETENTION_MILLISECONDS
  ) {
    batchFail("BATCH_RESULT_WORM_INVALID");
  }
  return { digest: sanitized.recordSha256, key: expectedKey, retentionUntil, versionId };
}

function parsePin(value: JsonValue | undefined): {
  readonly serviceIdentity: string;
  readonly workerVersionId: string;
} {
  const pin = exactObject(value, ["service_identity", "worker_version_id"]);
  return {
    serviceIdentity: requireString(pin, "service_identity", 512, IDENTITY),
    workerVersionId: requireString(pin, "worker_version_id", 36, BATCH_UUID),
  };
}

function pinProjection(serviceIdentity: string, workerVersionId: string): JsonObject {
  return { service_identity: serviceIdentity, worker_version_id: workerVersionId };
}

function wormProjection(worm: ActivationWorm): JsonObject {
  return {
    digest: worm.digest,
    key: worm.key,
    retention_until: worm.retentionUntil,
    version_id: worm.versionId,
  };
}

function requireWorm(value: ActivationWorm | null): ActivationWorm {
  if (value === null) batchFail("BATCH_RESULT_INVALID");
  return value;
}
