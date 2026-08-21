import {
  activationOperationSlotRoster,
  type ActivationOperationIdentity,
} from "./activation-operation-contract";

export interface ActivationOperationIssuanceIdentity {
  readonly internalRequestId: string;
  readonly issuanceId: string;
}

/** Persist one issuance and its complete, sequence-specific slot roster. */
export function insertActivationOperationIssuance(
  sql: SqlStorage,
  identity: ActivationOperationIdentity,
  ordinal: number,
  issuance: ActivationOperationIssuanceIdentity,
  issuedAt: string,
  freshUntil: string,
): void {
  sql.exec(
    `INSERT INTO activation_operation_issuances(
       attempt_id, ordinal, issuance_id, internal_request_id,
       issued_at, fresh_until, state
     ) VALUES (?, ?, ?, ?, ?, ?, 'RESERVED')`,
    identity.attemptId,
    ordinal,
    issuance.issuanceId,
    issuance.internalRequestId,
    issuedAt,
    freshUntil,
  );
  for (const slot of activationOperationSlotRoster(identity.sequence)) {
    sql.exec(
      `INSERT INTO activation_operation_slots(
         issuance_id, slot_id, slot_kind, slot_index, state
       ) VALUES (?, ?, ?, ?, 'PREPARED')`,
      issuance.issuanceId,
      slot.slotId,
      slot.slotKind,
      slot.slotIndex,
    );
  }
}

/** Mark a reserved issuance as collecting before any provider read. */
export function collectActivationOperationIssuance(sql: SqlStorage, issuanceId: string): void {
  sql.exec(
    `UPDATE activation_operation_issuances SET state = 'COLLECTING'
     WHERE issuance_id = ? AND state = 'RESERVED'`,
    issuanceId,
  );
}
