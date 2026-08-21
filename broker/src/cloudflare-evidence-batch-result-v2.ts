import type { ActivationOperationCloudflareRequest } from "./activation-operation-cloudflare-request";
import {
  isCloudflareEvidenceBatchBindingV2,
  type CloudflareEvidenceBatchContext,
  type CloudflareEvidenceBatchSlot,
  type ConfirmedCloudflareEvidence,
} from "./cloudflare-evidence-batch-contract";
import {
  BATCH_DIGEST,
  BATCH_TIMESTAMP,
  batchFail,
  canonicalBatchTimestamp,
  requireBatchInteger,
  requireBatchLiteral,
  requireBatchObject,
} from "./cloudflare-evidence-batch-codec";
import { validateCloudflareEvidenceBatchObservation } from "./cloudflare-evidence-batch-context";
import {
  assertCloudflareEvidenceBatchResultChronology,
  assertCloudflareEvidenceBatchResultPins,
  buildCloudflareEvidenceBatchResultRecords,
  cloudflareEvidenceBatchResultPinsProjection,
  decodeCanonicalCloudflareEvidenceBatchResultV2,
  parseCloudflareEvidenceBatchResultPins,
  parseCloudflareEvidenceBatchResultRecords,
  type ConfirmedCloudflareEvidenceRecordV2,
} from "./cloudflare-evidence-batch-result-v2-codec";
import type { ActivationCloudflareBatchPins } from "./activation-operation-pins";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export const CLOUDFLARE_EVIDENCE_BATCH_RESULT_SCHEMA_V2 =
  "dpone.cloudflare-evidence-worm-batch-result.v2";

export type { ConfirmedCloudflareEvidenceRecordV2 } from "./cloudflare-evidence-batch-result-v2-codec";

export interface ConfirmedCloudflareEvidenceBatchV2 {
  readonly batchSealedAt: string;
  readonly binding: ActivationOperationCloudflareRequest["binding"];
  readonly delegationCommittedAt: string;
  readonly delegationSha256: string;
  readonly network: ConfirmedCloudflareEvidence;
  readonly observation: JsonObject;
  readonly pins: ActivationCloudflareBatchPins;
  readonly providerObservationSha256: string;
  readonly records: readonly ConfirmedCloudflareEvidenceRecordV2[];
  readonly services: readonly ConfirmedCloudflareEvidence[];
}

/** Build the closed operation-scoped result from the durable sanitized journal. */
export function buildCloudflareEvidenceBatchResultV2(
  context: CloudflareEvidenceBatchContext,
  slots: readonly CloudflareEvidenceBatchSlot[],
): JsonObject {
  const { binding, operation } = context;
  if (!isCloudflareEvidenceBatchBindingV2(binding) || operation === null) {
    batchFail("BATCH_RESULT_BINDING_INVALID");
  }
  return {
    activation_issuance_id: binding.activationIssuanceId,
    activation_issuance_ordinal: binding.activationIssuanceOrdinal,
    activation_sequence: binding.activationSequence,
    batch_id: binding.batchId,
    batch_sealed_at: canonicalBatchTimestamp(context.committedAt),
    delegation_committed_at: canonicalBatchTimestamp(operation.committedAt),
    delegation_sha256: operation.delegationSha256,
    expectation_sha256: binding.expectationSha256,
    observation: context.observation,
    phase: binding.phase,
    pins: cloudflareEvidenceBatchResultPinsProjection(operation.authorityPins),
    provider_observation_sha256: context.providerObservationSha256,
    records: buildCloudflareEvidenceBatchResultRecords(slots, context),
    schema: CLOUDFLARE_EVIDENCE_BATCH_RESULT_SCHEMA_V2,
    schema_version: 2,
  };
}

/** Parse exact bytes; the stored delegation is the only expected-authority input. */
export async function parseCloudflareEvidenceBatchResultV2(
  canonicalResultBytes: Uint8Array,
  delegation: ActivationOperationCloudflareRequest,
): Promise<ConfirmedCloudflareEvidenceBatchV2> {
  const result = exactObject(decodeCanonicalCloudflareEvidenceBatchResultV2(canonicalResultBytes), [
    "activation_issuance_id",
    "activation_issuance_ordinal",
    "activation_sequence",
    "batch_id",
    "batch_sealed_at",
    "delegation_committed_at",
    "delegation_sha256",
    "expectation_sha256",
    "observation",
    "phase",
    "pins",
    "provider_observation_sha256",
    "records",
    "schema",
    "schema_version",
  ]);
  requireBatchLiteral(result, "schema", CLOUDFLARE_EVIDENCE_BATCH_RESULT_SCHEMA_V2);
  requireBatchInteger(result, "schema_version", 2);
  const binding = delegation.binding;
  if (
    result.activation_issuance_id !== binding.activationIssuanceId ||
    requireInteger(result, "activation_issuance_ordinal", 1, 1_000_000) !==
      binding.activationIssuanceOrdinal ||
    requireInteger(result, "activation_sequence", 0, 1) !== binding.activationSequence ||
    result.batch_id !== binding.batchId ||
    result.delegation_sha256 !== delegation.delegationSha256 ||
    result.expectation_sha256 !== binding.expectationSha256 ||
    result.phase !== binding.phase
  ) {
    batchFail("BATCH_RESULT_BINDING_INVALID");
  }
  const pins = parseCloudflareEvidenceBatchResultPins(result.pins);
  assertCloudflareEvidenceBatchResultPins(pins, delegation.pins);
  const delegationCommittedAt = canonicalBatchTimestamp(
    requireString(result, "delegation_committed_at", 24, BATCH_TIMESTAMP),
  );
  const batchSealedAt = canonicalBatchTimestamp(
    requireString(result, "batch_sealed_at", 24, BATCH_TIMESTAMP),
  );
  const observationObject = requireBatchObject(result.observation);
  const observedAt = canonicalBatchTimestamp(
    requireString(observationObject, "observed_at", 24, BATCH_TIMESTAMP),
  );
  assertCloudflareEvidenceBatchResultChronology(
    delegation,
    delegationCommittedAt,
    observedAt,
    batchSealedAt,
  );
  const providerObservationSha256 = requireString(
    result,
    "provider_observation_sha256",
    71,
    BATCH_DIGEST,
  );
  const cloudflareAccountId = requireString(
    observationObject,
    "cloudflare_account_id",
    32,
    /^[0-9a-f]{32}$/u,
  );
  if (
    pins.cloudflareObserverServiceIdentity.slice("cloudflare-worker:".length, 50) !==
    cloudflareAccountId
  ) {
    batchFail("BATCH_RESULT_WORKER_INVALID");
  }
  const records = await parseCloudflareEvidenceBatchResultRecords(
    result.records,
    delegation,
    batchSealedAt,
    {
      cloudflareAccountId,
      observedAt,
      observerServiceIdentity: pins.cloudflareObserverServiceIdentity,
    },
  );
  if (
    records.some(
      ({ evidence }) => evidence.record.provider_observation_sha256 !== providerObservationSha256,
    )
  ) {
    batchFail("BATCH_RESULT_BINDING_INVALID");
  }
  const observation = await validateCloudflareEvidenceBatchObservation(
    observationObject,
    binding,
    observedAt,
    records.map(({ authorityRole, evidence, kind, slotIndex }) => ({
      authorityRole,
      kind,
      sanitized: evidence,
      slotIndex,
    })),
  );
  if (
    observation.provider_observation_sha256 !== providerObservationSha256 ||
    observation.observer_service_identity !== pins.cloudflareObserverServiceIdentity
  ) {
    batchFail("BATCH_RESULT_BINDING_INVALID");
  }
  const network = records.at(-1)?.evidence;
  if (network === undefined) batchFail("BATCH_RESULT_INVALID");
  return {
    batchSealedAt,
    binding,
    delegationCommittedAt,
    delegationSha256: delegation.delegationSha256,
    network,
    observation,
    pins,
    providerObservationSha256,
    records,
    services: Object.freeze(records.slice(0, -1).map(({ evidence }) => evidence)),
  };
}
