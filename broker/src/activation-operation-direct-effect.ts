import {
  expectedDirectOperationWormKey,
  operationEffectFail,
} from "./activation-operation-effects-validation";
import type { ActivationOperationExecutorPins } from "./activation-operation-pins";
import type { ActivationOperationSlotRow } from "./activation-operation-schema";
import {
  prepareWormExactObjectEffect,
  type PreparedWormExactObjectEffect,
  type WormExactObjectEffectPins,
} from "./worm-exact-object-effect-contract";

export async function prepareDirectOperationEffect(
  row: ActivationOperationSlotRow,
  ingressWorkerVersion: string,
  committedAt: string,
  pins: ActivationOperationExecutorPins,
): Promise<PreparedWormExactObjectEffect> {
  if (row.frozen_payload_bytes === null || row.frozen_payload_sha256 === null) {
    operationEffectFail("ACTIVATION_OPERATION_EFFECT_BINDING_INVALID");
  }
  return prepareWormExactObjectEffect({
    canonicalBytes: new Uint8Array(row.frozen_payload_bytes),
    committedAt,
    digest: row.frozen_payload_sha256,
    key: expectedDirectOperationWormKey(row, ingressWorkerVersion),
    pins: wormEffectPins(pins),
  });
}

export async function rebuildDirectOperationEffect(
  row: ActivationOperationSlotRow,
  ingressWorkerVersion: string,
): Promise<PreparedWormExactObjectEffect> {
  if (
    row.committed_at === null ||
    row.executor_service_identity === null ||
    row.executor_worker_version_id === null ||
    row.observer_service_identity === null ||
    row.observer_worker_version_id === null
  ) {
    operationEffectFail("ACTIVATION_OPERATION_EFFECT_BINDING_INVALID");
  }
  const prepared = await prepareDirectOperationEffect(row, ingressWorkerVersion, row.committed_at, {
    executorServiceIdentity: row.executor_service_identity,
    executorWorkerVersionId: row.executor_worker_version_id,
    observerServiceIdentity: row.observer_service_identity,
    observerWorkerVersionId: row.observer_worker_version_id,
  });
  if (prepared.effectId !== row.effect_id || prepared.key !== row.expected_worm_key) {
    operationEffectFail("ACTIVATION_OPERATION_EFFECT_BINDING_CONFLICT");
  }
  return prepared;
}

function wormEffectPins(pins: ActivationOperationExecutorPins): WormExactObjectEffectPins {
  return {
    executorServiceIdentity: pins.executorServiceIdentity,
    executorVersionId: pins.executorWorkerVersionId,
    observerServiceIdentity: pins.observerServiceIdentity,
    observerVersionId: pins.observerWorkerVersionId,
  };
}
