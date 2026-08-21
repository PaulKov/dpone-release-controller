import {
  activationRecordV2AnchorVectorDigest,
  activationRecordV2BatchId,
} from "../src/activation-record-v2-service";
import { digestObject } from "../src/canonical";
import {
  cloudflareEvidenceWormKeyV2,
  type CloudflareEvidenceBatchContext,
  type CloudflareEvidenceBatchSlot,
} from "../src/cloudflare-evidence-batch-contract";
import { buildCloudflareEvidenceBatchResultV2 } from "../src/cloudflare-evidence-batch-result-v2";
import type { JsonObject } from "../src/types";
import { CLOUDFLARE_PINS } from "./activation-operation-effects.fixtures";
import { cloudflareEvidenceBatchFixture } from "./cloudflare-evidence-batch.fixtures";

const RETENTION = "2034-08-20T12:00:00.000Z";

export async function compactServiceAuthorityFixture(
  operation: JsonObject,
  sequence: 0 | 1,
  delegatedAt: string,
  observedAt: string,
  sealedAt: string,
  worstCase: boolean,
): Promise<{ readonly compact: JsonObject; readonly fullResult: JsonObject }> {
  const issuanceId = string(operation, "issuance_id");
  const issuanceOrdinal = integer(operation, "issuance_ordinal");
  const phase = sequence === 0 ? "A0_PRE" : "A1_PRECOMMIT";
  const source = await cloudflareEvidenceBatchFixture(phase, Date.parse(observedAt));
  const batchId = await activationRecordV2BatchId(issuanceId, issuanceOrdinal, sequence);
  const delegationSha256 = await digestObject({
    batch_id: batchId,
    committed_at: delegatedAt,
    issuance_id: issuanceId,
    issuance_ordinal: issuanceOrdinal,
    schema: "dpone.compact-v2-fixture-delegation.v1",
    sequence,
  });
  const context: CloudflareEvidenceBatchContext = {
    binding: {
      activationIssuanceId: issuanceId,
      activationIssuanceOrdinal: issuanceOrdinal,
      activationSequence: sequence,
      batchId,
      expectationSha256: source.binding.expectationSha256,
      observerWorkerVersionId: source.binding.observerWorkerVersionId,
      phase,
    },
    committedAt: sealedAt,
    execution: {
      b2ObserverServiceIdentity: CLOUDFLARE_PINS.b2ObserverServiceIdentity,
      b2ObserverWorkerVersionId: CLOUDFLARE_PINS.b2ObserverWorkerVersionId,
      wormServiceIdentity: CLOUDFLARE_PINS.wormServiceIdentity,
      wormWorkerVersionId: CLOUDFLARE_PINS.wormWorkerVersionId,
    },
    observation: source.observation,
    observedAt,
    operation: {
      authorityPins: { ...CLOUDFLARE_PINS },
      committedAt: delegatedAt,
      delegationSha256,
      freshUntil: string(operation, "fresh_until"),
      issuedAt: string(operation, "issued_at"),
    },
    providerObservationSha256: string(source.observation, "provider_observation_sha256"),
  };
  const slots: readonly CloudflareEvidenceBatchSlot[] = source.slots.map((slot, index) => {
    const key = cloudflareEvidenceWormKeyV2(
      source.binding.observerWorkerVersionId,
      batchId,
      slot.kind,
      slot.sanitized.recordId,
    );
    return {
      authorityRole: slot.authorityRole,
      committedAt: sealedAt,
      expectedWormKey: key,
      kind: slot.kind,
      sanitized: slot.sanitized,
      slotIndex: slot.slotIndex,
      status: "CONFIRMED",
      writerVersionId: CLOUDFLARE_PINS.wormWorkerVersionId,
      worm: {
        digest: slot.sanitized.recordSha256,
        key,
        retentionUntil: RETENTION,
        versionId: worstCase ? longVersion(30 + index) : `4_z-cloudflare-v2-${index}`,
      },
    };
  });
  const fullResult = buildCloudflareEvidenceBatchResultV2(context, slots);
  const fullRecords = array(fullResult.records);
  const records = fullRecords.map((candidate) => {
    const record = object(candidate);
    return {
      authority_role: record.authority_role ?? null,
      kind: record.kind ?? null,
      record_id: record.record_id ?? null,
      record_sha256: record.record_sha256 ?? null,
      slot_index: record.slot_index ?? null,
      worm: record.worm ?? null,
    };
  });
  const compact: JsonObject = {
    batch_id: batchId,
    batch_result_sha256: await digestObject(fullResult),
    batch_sealed_at: sealedAt,
    cloudflare_provider_observation_sha256: string(
      source.observation,
      "provider_observation_sha256",
    ),
    delegation_committed_at: delegatedAt,
    delegation_sha256: delegationSha256,
    expectation_sha256: source.binding.expectationSha256,
    observed_at: observedAt,
    phase,
    provider_observation_sha256: await digestObject({
      batch_id: batchId,
      records,
      schema: "dpone.compact-v2-fixture-provider-observation.v1",
    }),
    records,
    records_sha256: await activationRecordV2AnchorVectorDigest(records),
  };
  return { compact, fullResult };
}

function object(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("compact v2 service fixture object missing");
  }
  return value as JsonObject;
}

function array(value: unknown): JsonObject[] {
  if (!Array.isArray(value)) throw new Error("compact v2 service fixture array missing");
  return value.map(object);
}

function string(value: JsonObject, key: string): string {
  const candidate = value[key];
  if (typeof candidate !== "string") throw new Error(`compact v2 fixture ${key} missing`);
  return candidate;
}

function integer(value: JsonObject, key: string): number {
  const candidate = value[key];
  if (!Number.isSafeInteger(candidate)) throw new Error(`compact v2 fixture ${key} missing`);
  return Number(candidate);
}

function longVersion(index: number): string {
  const prefix = `v${index}_`;
  return prefix + "x".repeat(512 - prefix.length);
}
