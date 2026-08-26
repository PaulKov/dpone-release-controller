import { canonicalBytes, sha256Hex } from "./canonical";
import type { ActivationOperationCloudflareRequest } from "./activation-operation-cloudflare-request";
import {
  validateCloudflareEvidenceBatchExecution,
  validateCloudflareEvidenceBatchObservation,
} from "./cloudflare-evidence-batch-context";
import {
  isCloudflareEvidenceBatchBindingV2,
  type AnyCloudflareEvidenceBatchBinding,
  type CloudflareEvidenceBatchExecution,
  type CloudflareEvidenceBatchSlotInput,
} from "./cloudflare-evidence-batch-contract";
import {
  assertCloudflareEvidenceBatchChronology,
  batchConflict,
  canonicalBatchTimestamp,
  cloudflareProviderDigest,
  prepareCloudflareEvidenceSlots,
  validateCloudflareEvidenceBatchBinding,
} from "./cloudflare-evidence-batch-validation";
import type { JsonObject } from "./types";

export interface PreparedCloudflareEvidenceBatchSeal {
  readonly committedAt: string;
  readonly observation: JsonObject;
  readonly observationBytes: Uint8Array;
  readonly observedAt: string;
  readonly providerObservationSha256: string;
  readonly sealSha256: string;
  readonly slots: readonly CloudflareEvidenceBatchSlotInput[];
}

/** Validate and own every sanitized byte before the SQL seal transaction. */
export async function prepareCloudflareEvidenceBatchSeal(input: {
  readonly binding: AnyCloudflareEvidenceBatchBinding;
  readonly committedAt: string;
  readonly execution: CloudflareEvidenceBatchExecution;
  readonly observation: JsonObject;
  readonly observedAt: string;
  readonly operation?: ActivationOperationCloudflareRequest;
  readonly slots: readonly CloudflareEvidenceBatchSlotInput[];
}): Promise<PreparedCloudflareEvidenceBatchSeal> {
  validateCloudflareEvidenceBatchBinding(input.binding);
  validateCloudflareEvidenceBatchExecution(input.execution);
  const observedAt = canonicalBatchTimestamp(input.observedAt);
  const committedAt = canonicalBatchTimestamp(input.committedAt);
  assertCloudflareEvidenceBatchChronology(observedAt, committedAt);
  const slots = await prepareCloudflareEvidenceSlots(input.slots, input.binding, observedAt);
  const observation = await validateCloudflareEvidenceBatchObservation(
    input.observation,
    input.binding,
    observedAt,
    slots,
  );
  assertOperationBinding(input, observation, observedAt, committedAt);
  const providerObservationSha256 = cloudflareProviderDigest(slots);
  const sealSha256 = `sha256:${await sha256Hex(
    canonicalBytes({
      activation_issuance: isCloudflareEvidenceBatchBindingV2(input.binding)
        ? {
            id: input.binding.activationIssuanceId,
            ordinal: input.binding.activationIssuanceOrdinal,
            sequence: input.binding.activationSequence,
          }
        : null,
      batch_id: input.binding.batchId,
      delegation_sha256: input.operation?.delegationSha256 ?? null,
      execution: {
        b2_observer_service_identity: input.execution.b2ObserverServiceIdentity,
        b2_observer_worker_version_id: input.execution.b2ObserverWorkerVersionId,
        worm_service_identity: input.execution.wormServiceIdentity,
        worm_worker_version_id: input.execution.wormWorkerVersionId,
      },
      provider_observation_sha256: providerObservationSha256,
      slots: slots.map((slot) => ({
        authority_role: slot.authorityRole,
        kind: slot.kind,
        record_id: slot.sanitized.recordId,
        record_sha256: slot.sanitized.recordSha256,
        slot_index: slot.slotIndex,
      })),
    }),
  )}`;
  return {
    committedAt,
    observation,
    observationBytes: canonicalBytes(observation),
    observedAt,
    providerObservationSha256,
    sealSha256,
    slots,
  };
}

function assertOperationBinding(
  input: Parameters<typeof prepareCloudflareEvidenceBatchSeal>[0],
  observation: JsonObject,
  observedAt: string,
  batchSealedAt: string,
): void {
  if (!isCloudflareEvidenceBatchBindingV2(input.binding)) {
    if (input.operation !== undefined)
      throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_BINDING_INVALID");
    return;
  }
  const operation = input.operation;
  if (operation === undefined) {
    throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_BINDING_INVALID");
  }
  if (
    operation.binding.batchId !== input.binding.batchId ||
    operation.pins.wormServiceIdentity !== input.execution.wormServiceIdentity ||
    operation.pins.wormWorkerVersionId !== input.execution.wormWorkerVersionId ||
    operation.pins.b2ObserverServiceIdentity !== input.execution.b2ObserverServiceIdentity ||
    operation.pins.b2ObserverWorkerVersionId !== input.execution.b2ObserverWorkerVersionId ||
    observation.observer_service_identity !== operation.pins.cloudflareObserverServiceIdentity ||
    Date.parse(operation.committedAt) > Date.parse(observedAt) ||
    Date.parse(observedAt) > Date.parse(batchSealedAt) ||
    Date.parse(batchSealedAt) > Date.parse(operation.freshUntil)
  ) {
    throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_BINDING_INVALID");
  }
}
