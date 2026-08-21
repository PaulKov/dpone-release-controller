import type { ActivationOperationIssuanceState } from "./activation-operation-contract";
import type {
  ActivationOperationIssuanceRow,
  ActivationOperationSlotRow,
} from "./activation-operation-schema";
import {
  operationStoreFail,
  requireCanonicalOperationTimestamp,
} from "./activation-operation-store-validation";

export type ActivationOperationStaleDisposition = "EXPIRED_UNDISPATCHED" | "SUPERSEDED_STALE";

/**
 * Classify a stale issuance without treating an ambiguous or partial effect as retryable.
 * A new ordinal is safe only before the first durable dispatch. Confirmed
 * evidence is immutable input for the same issuance and must be resumed.
 */
export function classifyStaleActivationIssuance(
  issuanceState: ActivationOperationIssuanceState,
  slots: readonly ActivationOperationSlotRow[],
): ActivationOperationStaleDisposition {
  if (
    issuanceState === "CONFIRMED" ||
    issuanceState === "HOLD" ||
    issuanceState === "RECORD_APPENDED"
  ) {
    operationStoreFail("ACTIVATION_OPERATION_REISSUE_BLOCKED");
  }
  const effects = slots.filter((slot) => slot.slot_kind !== "READ_ONLY");
  if (effects.length === 0) operationStoreFail("ACTIVATION_OPERATION_SLOT_ROSTER_INVALID", 500);
  const hasDispatchedEffect = effects.some((slot) =>
    ["CONFIRMED", "DELEGATED_IN_FLIGHT", "DISPATCHED_HOLD", "HOLD"].includes(slot.state),
  );
  if (!hasDispatchedEffect) return "EXPIRED_UNDISPATCHED";
  operationStoreFail("ACTIVATION_OPERATION_REISSUE_BLOCKED");
}

export function assertActivationIssuanceExpired(
  row: ActivationOperationIssuanceRow,
  nowMs: number,
): void {
  requireCanonicalOperationTimestamp(row.fresh_until);
  if (nowMs <= Date.parse(row.fresh_until)) {
    operationStoreFail("ACTIVATION_OPERATION_ISSUANCE_FRESH");
  }
}
