import { canonicalBytes, canonicalJson } from "./canonical";
import { assertSanitizedCloudflareEvidenceRecord } from "./cloudflare-deployment-observation";
import {
  assertSanitizedCloudflareProjectionBytes,
  decodeCanonicalBatchObject,
  type CloudflareEvidenceBatchRow,
} from "./cloudflare-evidence-batch-context";
import {
  CLOUDFLARE_EVIDENCE_SLOT_COUNT,
  cloudflareEvidenceWormKey,
  cloudflareEvidenceWormKeyV2,
  isCloudflareEvidenceBatchBindingV2,
  type AnyCloudflareEvidenceBatchBinding,
  type CloudflareEvidenceBatchSlot,
  type CloudflareEvidenceBatchSlotInput,
} from "./cloudflare-evidence-batch-contract";
import { BrokerError } from "./errors";
import { SERVICE_AUTHORITY_ROLES } from "./service-authority";
import type { ActivationWorm, JsonObject } from "./types";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const VERSION = /^[A-Za-z0-9._=-]{1,512}$/u;
const RETENTION_MILLISECONDS = 2557 * 86_400_000;
const MAX_SLOT_BYTES = 65_536;
const MAX_BATCH_BYTES = MAX_SLOT_BYTES * CLOUDFLARE_EVIDENCE_SLOT_COUNT;
export interface CloudflareEvidenceSlotRow extends Record<string, SqlStorageValue> {
  readonly absence_inventory_sha256: string | null;
  readonly authority_role: string | null;
  readonly canonical_bytes: ArrayBuffer;
  readonly committed_at: string;
  readonly expected_worm_key: string;
  readonly kind: string;
  readonly record_id: string;
  readonly record_sha256: string;
  readonly slot_index: number;
  readonly status: string;
  readonly writer_version_id: string | null;
  readonly worm_digest: string | null;
  readonly worm_key: string | null;
  readonly worm_retention_until: string | null;
  readonly worm_version_id: string | null;
}

export async function prepareCloudflareEvidenceSlots(
  inputs: readonly CloudflareEvidenceBatchSlotInput[],
  binding: AnyCloudflareEvidenceBatchBinding,
  observedAt: string,
): Promise<readonly CloudflareEvidenceBatchSlotInput[]> {
  if (inputs.length !== CLOUDFLARE_EVIDENCE_SLOT_COUNT) {
    throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_SLOT_COUNT_INVALID");
  }
  let totalBytes = 0;
  const prepared: CloudflareEvidenceBatchSlotInput[] = [];
  for (let index = 0; index < inputs.length; index += 1) {
    const input = requireSlotInput(inputs[index]);
    const expectedRole =
      index < SERVICE_AUTHORITY_ROLES.length ? SERVICE_AUTHORITY_ROLES[index] : null;
    if (
      input.slotIndex !== index ||
      input.authorityRole !== expectedRole ||
      input.kind !==
        (expectedRole === null ? "cloudflare_network_surface" : "cloudflare_service_deployments")
    ) {
      throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_SLOT_ORDER_INVALID");
    }
    const sanitized = await assertSanitizedCloudflareEvidenceRecord(input.sanitized.record);
    if (
      sanitized.recordId !== input.sanitized.recordId ||
      sanitized.recordSha256 !== input.sanitized.recordSha256 ||
      sanitized.record.expectation_sha256 !== binding.expectationSha256 ||
      sanitized.record.observer_worker_version_id !== binding.observerWorkerVersionId ||
      sanitized.record.phase !== binding.phase ||
      sanitized.record.observed_at !== observedAt ||
      (expectedRole !== null && sanitized.record.authority_role !== expectedRole)
    ) {
      throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_BINDING_INVALID");
    }
    const bytes = canonicalBytes(sanitized.record);
    assertSanitizedBytes(bytes);
    totalBytes += bytes.byteLength;
    prepared.push({ ...input, sanitized });
  }
  if (totalBytes > MAX_BATCH_BYTES) {
    throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_SIZE_INVALID");
  }
  assertUnique(prepared.map((slot) => slot.sanitized.recordId));
  assertUnique(prepared.map((slot) => slot.sanitized.recordSha256));
  return Object.freeze(prepared);
}

export function cloudflareProviderDigest(
  inputs: readonly CloudflareEvidenceBatchSlotInput[],
): string {
  const values = inputs.map((input) => input.sanitized.record.provider_observation_sha256);
  const first = values[0];
  if (typeof first !== "string" || !DIGEST.test(first) || values.some((value) => value !== first)) {
    throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_PROVIDER_DIGEST_INVALID");
  }
  return first;
}

export function validateCloudflareEvidenceWorm(
  row: CloudflareEvidenceSlotRow,
  worm: ActivationWorm,
): ActivationWorm {
  const expectedKey = row.expected_worm_key;
  const retentionMs = Date.parse(worm.retentionUntil);
  const committedMs = Date.parse(row.committed_at);
  if (
    worm.digest !== row.record_sha256 ||
    worm.key !== expectedKey ||
    !VERSION.test(worm.versionId) ||
    !Number.isFinite(retentionMs) ||
    new Date(retentionMs).toISOString() !== worm.retentionUntil ||
    retentionMs < committedMs + RETENTION_MILLISECONDS
  ) {
    throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_WORM_INVALID");
  }
  return worm;
}

export function decodeCloudflareEvidenceSlot(
  row: CloudflareEvidenceSlotRow,
): CloudflareEvidenceBatchSlot {
  const record = decodeRecord(row.canonical_bytes);
  return {
    authorityRole: row.authority_role,
    committedAt: row.committed_at,
    expectedWormKey: row.expected_worm_key,
    kind: row.kind as CloudflareEvidenceBatchSlot["kind"],
    sanitized: { record, recordId: row.record_id, recordSha256: row.record_sha256 },
    slotIndex: row.slot_index,
    status: row.status as CloudflareEvidenceBatchSlot["status"],
    writerVersionId: row.writer_version_id,
    worm:
      row.worm_digest === null
        ? null
        : {
            digest: row.worm_digest,
            key: requireStored(row.worm_key),
            retentionUntil: requireStored(row.worm_retention_until),
            versionId: requireStored(row.worm_version_id),
          },
  };
}

export function expectedCloudflareEvidenceWormKey(
  binding: AnyCloudflareEvidenceBatchBinding,
  kind: CloudflareEvidenceBatchSlot["kind"],
  recordId: string,
): string {
  return isCloudflareEvidenceBatchBindingV2(binding)
    ? cloudflareEvidenceWormKeyV2(binding.observerWorkerVersionId, binding.batchId, kind, recordId)
    : cloudflareEvidenceWormKey(binding.observerWorkerVersionId, kind, recordId);
}

export function assertStoredCloudflareEvidenceSlots(
  expected: readonly CloudflareEvidenceBatchSlotInput[],
  actual: readonly CloudflareEvidenceSlotRow[],
): void {
  if (
    actual.length !== expected.length ||
    actual.some((row, index) => {
      const slot = requireSlotInput(expected[index]);
      return (
        row.record_id !== slot.sanitized.recordId ||
        row.record_sha256 !== slot.sanitized.recordSha256 ||
        canonicalJson(decodeRecord(row.canonical_bytes)) !== canonicalJson(slot.sanitized.record)
      );
    })
  ) {
    throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_SEAL_CONFLICT");
  }
}

export function assertStoredCloudflareEvidenceWorm(
  row: CloudflareEvidenceSlotRow,
  worm: ActivationWorm,
): void {
  if (
    row.worm_digest !== worm.digest ||
    row.worm_key !== worm.key ||
    row.worm_version_id !== worm.versionId ||
    row.worm_retention_until !== worm.retentionUntil
  ) {
    throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_WORM_CONFLICT");
  }
}

export function validateCloudflareEvidenceBatchBinding(
  binding: AnyCloudflareEvidenceBatchBinding,
): void {
  if (
    !DIGEST.test(binding.batchId) ||
    !DIGEST.test(binding.expectationSha256) ||
    !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(binding.observerWorkerVersionId) ||
    (binding.phase !== "A0_PRE" && binding.phase !== "A1_PRECOMMIT")
  ) {
    throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_BINDING_INVALID");
  }
  if (
    isCloudflareEvidenceBatchBindingV2(binding) &&
    (!DIGEST.test(binding.activationIssuanceId) ||
      !Number.isSafeInteger(binding.activationIssuanceOrdinal) ||
      binding.activationIssuanceOrdinal < 1 ||
      binding.activationIssuanceOrdinal > 1_000_000 ||
      (binding.activationSequence === 0) !== (binding.phase === "A0_PRE"))
  ) {
    throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_BINDING_INVALID");
  }
}

export function assertCloudflareEvidenceBatchBinding(
  row: CloudflareEvidenceBatchRow,
  binding: AnyCloudflareEvidenceBatchBinding,
): void {
  const v2 = isCloudflareEvidenceBatchBindingV2(binding);
  if (
    row.batch_id !== binding.batchId ||
    row.binding_schema_version !== (v2 ? 2 : 1) ||
    row.activation_issuance_id !== (v2 ? binding.activationIssuanceId : null) ||
    row.activation_issuance_ordinal !== (v2 ? binding.activationIssuanceOrdinal : null) ||
    row.activation_sequence !== (v2 ? binding.activationSequence : null) ||
    row.expectation_sha256 !== binding.expectationSha256 ||
    row.observer_worker_version_id !== binding.observerWorkerVersionId ||
    row.phase !== binding.phase
  ) {
    throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_BINDING_CONFLICT");
  }
}

export function canonicalBatchTimestamp(value: string): string {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_TIME_INVALID");
  }
  return value;
}

export function assertCloudflareEvidenceBatchChronology(
  observedAt: string,
  committedAt: string,
): void {
  const observedMs = Date.parse(canonicalBatchTimestamp(observedAt));
  const committedMs = Date.parse(canonicalBatchTimestamp(committedAt));
  if (committedMs < observedMs || committedMs - observedMs > 60_000) {
    throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_TIME_INVALID");
  }
}

export function requireCloudflareEvidenceBatch(
  value: CloudflareEvidenceBatchRow | undefined,
): CloudflareEvidenceBatchRow {
  if (value === undefined) throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_MISSING");
  return value;
}

export function requireCloudflareEvidenceSlot(
  value: CloudflareEvidenceSlotRow | undefined,
): CloudflareEvidenceSlotRow {
  if (value === undefined) throw batchConflict("CLOUDFLARE_EVIDENCE_SLOT_MISSING");
  return value;
}

export function requireBatchDigest(value: string): void {
  if (!DIGEST.test(value)) throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_DIGEST_INVALID");
}

export function batchConflict(code: string): BrokerError {
  return new BrokerError(code, 409, false);
}

function requireSlotInput(
  value: CloudflareEvidenceBatchSlotInput | undefined,
): CloudflareEvidenceBatchSlotInput {
  if (value === undefined) {
    throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_SLOT_ORDER_INVALID");
  }
  return value;
}

function decodeRecord(value: ArrayBuffer): JsonObject {
  return decodeCanonicalBatchObject(value);
}

function assertSanitizedBytes(bytes: Uint8Array): void {
  assertSanitizedCloudflareProjectionBytes(bytes, MAX_SLOT_BYTES);
}

function requireStored(value: string | null): string {
  if (value === null) throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_STORED_INVALID");
  return value;
}

function assertUnique(values: readonly string[]): void {
  if (new Set(values).size !== values.length) {
    throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_ALIAS_FORBIDDEN");
  }
}
