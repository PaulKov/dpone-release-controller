import { canonicalBytes, sha256Hex } from "./canonical";
import type { SanitizedCloudflareEvidence } from "./cloudflare-deployment-observation";
import type { ActivationWorm, JsonObject } from "./types";

export const CLOUDFLARE_EVIDENCE_BATCH_SCHEMA = "dpone.cloudflare-evidence-worm-batch-intent.v1";
export const CLOUDFLARE_EVIDENCE_BATCH_SCHEMA_V2 = "dpone.cloudflare-evidence-worm-batch-intent.v2";
export const CLOUDFLARE_EVIDENCE_SLOT_COUNT = 15;

export type CloudflareEvidenceKind =
  | "cloudflare_network_surface"
  | "cloudflare_service_deployments";

export interface CloudflareEvidenceBatchBinding {
  readonly batchId: string;
  readonly expectationSha256: string;
  readonly observerWorkerVersionId: string;
  readonly phase: string;
}

/** Operation-issued v2 identity. The broker ordinal prevents stale-batch aliasing. */
export interface CloudflareEvidenceBatchBindingV2 extends CloudflareEvidenceBatchBinding {
  readonly activationIssuanceId: string;
  readonly activationIssuanceOrdinal: number;
  readonly activationSequence: 0 | 1;
}

export type AnyCloudflareEvidenceBatchBinding =
  | CloudflareEvidenceBatchBinding
  | CloudflareEvidenceBatchBindingV2;

/** Immutable identities that are authorized to execute one sealed batch. */
export interface CloudflareEvidenceBatchExecution {
  readonly b2ObserverServiceIdentity: string;
  readonly b2ObserverWorkerVersionId: string;
  readonly wormServiceIdentity: string;
  readonly wormWorkerVersionId: string;
}

export interface CloudflareEvidenceBatchOperationContext {
  readonly authorityPins: {
    readonly b2ObserverServiceIdentity: string;
    readonly b2ObserverWorkerVersionId: string;
    readonly cloudflareObserverServiceIdentity: string;
    readonly cloudflareObserverWorkerVersionId: string;
    readonly wormServiceIdentity: string;
    readonly wormWorkerVersionId: string;
  };
  readonly committedAt: string;
  readonly delegationSha256: string;
  readonly freshUntil: string;
  readonly issuedAt: string;
}

/** Sanitized-only context durably frozen before the first B2 effect. */
export interface CloudflareEvidenceBatchContext {
  readonly binding: AnyCloudflareEvidenceBatchBinding;
  readonly committedAt: string;
  readonly execution: CloudflareEvidenceBatchExecution;
  readonly observation: JsonObject;
  readonly observedAt: string;
  readonly operation: CloudflareEvidenceBatchOperationContext | null;
  readonly providerObservationSha256: string;
}

export interface CloudflareEvidenceBatchSlotInput {
  readonly authorityRole: string | null;
  readonly kind: CloudflareEvidenceKind;
  readonly sanitized: SanitizedCloudflareEvidence;
  readonly slotIndex: number;
}

export interface ConfirmedCloudflareEvidence extends SanitizedCloudflareEvidence {
  readonly worm: ActivationWorm;
}

export interface CloudflareEvidenceBatchSlot {
  readonly authorityRole: string | null;
  readonly committedAt: string;
  readonly expectedWormKey: string;
  readonly kind: CloudflareEvidenceKind;
  readonly sanitized: SanitizedCloudflareEvidence;
  readonly slotIndex: number;
  readonly status: "ACCEPTED" | "ABSENT" | "CONFIRMED" | "IN_FLIGHT" | "PREPARED";
  readonly writerVersionId: string | null;
  readonly worm: ActivationWorm | null;
}

export interface CloudflareEvidenceBatchAction {
  readonly action: "CHECK_ABSENCE" | "COMPLETE" | "DISPATCH" | "RECONCILE";
  readonly slot: CloudflareEvidenceBatchSlot;
}

/**
 * Stable semantic batch identifier. Transport request IDs and clocks are
 * deliberately excluded so a fresh authenticated retry resolves the one
 * existing journal instead of creating an alternate evidence set.
 */
export async function cloudflareEvidenceBatchBinding(
  expectationSha256: string,
  observerWorkerVersionId: string,
  phase: string,
): Promise<CloudflareEvidenceBatchBinding> {
  const body: JsonObject = {
    expectation_sha256: expectationSha256,
    observer_worker_version_id: observerWorkerVersionId,
    phase,
    schema: CLOUDFLARE_EVIDENCE_BATCH_SCHEMA,
    schema_version: 1,
  };
  return {
    batchId: `sha256:${await sha256Hex(canonicalBytes(body))}`,
    expectationSha256,
    observerWorkerVersionId,
    phase,
  };
}

/** Derive an operation-scoped batch identity without transport or clock fields. */
export async function cloudflareEvidenceBatchBindingV2(
  activationIssuanceId: string,
  activationIssuanceOrdinal: number,
  activationSequence: 0 | 1,
  expectationSha256: string,
  observerWorkerVersionId: string,
  phase: string,
): Promise<CloudflareEvidenceBatchBindingV2> {
  const body: JsonObject = {
    activation_issuance_id: activationIssuanceId,
    activation_issuance_ordinal: activationIssuanceOrdinal,
    activation_sequence: activationSequence,
    schema: CLOUDFLARE_EVIDENCE_BATCH_SCHEMA_V2,
    schema_version: 2,
  };
  return {
    activationIssuanceId,
    activationIssuanceOrdinal,
    activationSequence,
    batchId: `sha256:${await sha256Hex(canonicalBytes(body))}`,
    expectationSha256,
    observerWorkerVersionId,
    phase,
  };
}

export function isCloudflareEvidenceBatchBindingV2(
  binding: AnyCloudflareEvidenceBatchBinding,
): binding is CloudflareEvidenceBatchBindingV2 {
  return "activationIssuanceId" in binding;
}

/** One deterministic immutable B2 key per sanitized evidence record. */
export function cloudflareEvidenceWormKey(
  observerWorkerVersionId: string,
  kind: CloudflareEvidenceKind,
  recordId: string,
): string {
  return (
    `receipts/v1/cloudflare-observations/${observerWorkerVersionId}/${kind}/` +
    `${recordId.slice("sha256:".length)}.json`
  );
}

/** Ordinal-scoped v2 key; different attempts can never alias one B2 object. */
export function cloudflareEvidenceWormKeyV2(
  observerWorkerVersionId: string,
  batchId: string,
  kind: CloudflareEvidenceKind,
  recordId: string,
): string {
  return (
    `receipts/v1/cloudflare-observations-v2/${observerWorkerVersionId}/` +
    `${batchId.slice("sha256:".length)}/${kind}/${recordId.slice("sha256:".length)}.json`
  );
}
