import { CLOUDFLARE_UUID } from "./cloudflare-ids";
import { BrokerError } from "./errors";
import type { ActivationOperationSlotRow } from "./activation-operation-schema";

const IDENTITY =
  /^cloudflare-worker:[0-9a-f]{32}\/[a-z0-9][a-z0-9-]{1,127}@[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;

export interface ActivationOperationExecutorPins {
  readonly executorServiceIdentity: string;
  readonly executorWorkerVersionId: string;
  readonly observerServiceIdentity: string;
  readonly observerWorkerVersionId: string;
}

export interface ActivationCloudflareBatchPins {
  readonly b2ObserverServiceIdentity: string;
  readonly b2ObserverWorkerVersionId: string;
  readonly cloudflareObserverServiceIdentity: string;
  readonly cloudflareObserverWorkerVersionId: string;
  readonly wormServiceIdentity: string;
  readonly wormWorkerVersionId: string;
}

export function validateOperationPins(pins: ActivationOperationExecutorPins): void {
  if (
    !validPinnedIdentity(pins.executorServiceIdentity, pins.executorWorkerVersionId) ||
    !validPinnedIdentity(pins.observerServiceIdentity, pins.observerWorkerVersionId) ||
    pins.executorServiceIdentity === pins.observerServiceIdentity
  ) {
    pinFail();
  }
}

export function validateCloudflareBatchPins(pins: ActivationCloudflareBatchPins): void {
  if (
    !validPinnedIdentity(
      pins.cloudflareObserverServiceIdentity,
      pins.cloudflareObserverWorkerVersionId,
    ) ||
    !validPinnedIdentity(pins.wormServiceIdentity, pins.wormWorkerVersionId) ||
    !validPinnedIdentity(pins.b2ObserverServiceIdentity, pins.b2ObserverWorkerVersionId) ||
    new Set([
      pins.cloudflareObserverServiceIdentity,
      pins.wormServiceIdentity,
      pins.b2ObserverServiceIdentity,
    ]).size !== 3
  ) {
    pinFail();
  }
}

export function assertOperationDelegation(
  row: ActivationOperationSlotRow,
  effectId: string,
  committedAt: string,
  pins: ActivationOperationExecutorPins,
): void {
  if (
    row.batch_id !== null ||
    row.effect_id !== effectId ||
    row.committed_at !== committedAt ||
    row.executor_service_identity !== pins.executorServiceIdentity ||
    row.executor_worker_version_id !== pins.executorWorkerVersionId ||
    row.observer_service_identity !== pins.observerServiceIdentity ||
    row.observer_worker_version_id !== pins.observerWorkerVersionId
  ) {
    bindingFail();
  }
}

export function assertCloudflareBatchDelegation(
  row: ActivationOperationSlotRow,
  batchId: string,
  committedAt: string,
  pins: ActivationCloudflareBatchPins,
): void {
  if (
    row.batch_id !== batchId ||
    row.committed_at !== committedAt ||
    row.cloudflare_observer_service_identity !== pins.cloudflareObserverServiceIdentity ||
    row.cloudflare_observer_worker_version_id !== pins.cloudflareObserverWorkerVersionId ||
    row.worm_service_identity !== pins.wormServiceIdentity ||
    row.worm_worker_version_id !== pins.wormWorkerVersionId ||
    row.b2_observer_service_identity !== pins.b2ObserverServiceIdentity ||
    row.b2_observer_worker_version_id !== pins.b2ObserverWorkerVersionId
  ) {
    bindingFail();
  }
}

export function assertCloudflareBatchResultPins(
  row: ActivationOperationSlotRow,
  pins: ActivationCloudflareBatchPins,
): void {
  assertCloudflareBatchDelegation(row, row.batch_id ?? "", row.committed_at ?? "", pins);
}

export function cloudflareBatchPinsSnapshot(
  pins: ActivationCloudflareBatchPins,
): ActivationCloudflareBatchPins {
  return { ...pins };
}

function validPinnedIdentity(identity: string, version: string): boolean {
  return (
    IDENTITY.test(identity) && CLOUDFLARE_UUID.test(version) && identity.endsWith(`@${version}`)
  );
}

function pinFail(): never {
  throw new BrokerError("ACTIVATION_OPERATION_EXECUTOR_PIN_INVALID", 409, false);
}

function bindingFail(): never {
  throw new BrokerError("ACTIVATION_OPERATION_EFFECT_BINDING_CONFLICT", 409, false);
}
