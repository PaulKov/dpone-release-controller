import type { JsonObject } from "./types";

export const ACTIVATION_OPERATION_INTENT_SCHEMA = "dpone.activation-operation-intent.v1";
export const ACTIVATION_OPERATION_ATTEMPT_SCHEMA = "dpone.activation-evidence-attempt.v1";
export const ACTIVATION_OPERATION_ISSUANCE_SCHEMA = "dpone.activation-evidence-issuance.v1";

export type ActivationOperationSequence = 0 | 1;
export type ActivationOperationSlotId =
  | "CLOUDFLARE_BATCH"
  | "CONTROLLER_ACTION"
  | "CONTROLLER_OIDC"
  | "TARGET_OIDC"
  | "TARGET_RULESET";
export type ActivationOperationSlotKind = "CLOUDFLARE_BATCH" | "DIRECT_WORM" | "READ_ONLY";
export type ActivationOperationIssuanceState =
  | "COLLECTING"
  | "CONFIRMED"
  | "DISPATCHED_HOLD"
  | "EFFECTS_PENDING"
  | "EXPIRED_UNDISPATCHED"
  | "FROZEN"
  | "HOLD"
  | "READY_TO_APPEND"
  | "RECORD_APPENDED"
  | "RESERVED"
  | "SUPERSEDED_STALE";

export interface ActivationOperationSlotDefinition {
  readonly slotId: ActivationOperationSlotId;
  readonly slotIndex: number;
  readonly slotKind: ActivationOperationSlotKind;
}

export interface ActivationOperationIdentity {
  readonly attemptId: string;
  readonly intentSha256: string;
  readonly semanticRequest: JsonObject;
  readonly semanticRequestBytes: Uint8Array;
  readonly sequence: ActivationOperationSequence;
  readonly workerVersionId: string;
}

export interface ActivationOperationIssuance {
  readonly attemptId: string;
  readonly freshUntil: string;
  readonly internalRequestId: string;
  readonly issuanceId: string;
  readonly issuedAt: string;
  readonly ordinal: number;
  readonly sequence: ActivationOperationSequence;
  readonly state: ActivationOperationIssuanceState;
}

const A0_SLOTS: readonly ActivationOperationSlotDefinition[] = Object.freeze([
  { slotId: "CONTROLLER_ACTION", slotIndex: 0, slotKind: "READ_ONLY" },
  { slotId: "CONTROLLER_OIDC", slotIndex: 1, slotKind: "DIRECT_WORM" },
  { slotId: "TARGET_OIDC", slotIndex: 2, slotKind: "DIRECT_WORM" },
  { slotId: "TARGET_RULESET", slotIndex: 3, slotKind: "DIRECT_WORM" },
  { slotId: "CLOUDFLARE_BATCH", slotIndex: 4, slotKind: "CLOUDFLARE_BATCH" },
]);
const A1_SLOTS: readonly ActivationOperationSlotDefinition[] = Object.freeze([
  { slotId: "CLOUDFLARE_BATCH", slotIndex: 0, slotKind: "CLOUDFLARE_BATCH" },
]);

export function activationOperationSlotRoster(
  sequence: ActivationOperationSequence,
): readonly ActivationOperationSlotDefinition[] {
  return sequence === 0 ? A0_SLOTS : A1_SLOTS;
}
