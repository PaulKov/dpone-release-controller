import { activationOperationSlotRoster } from "./activation-operation-contract";
import type { ActivationOperationEffectQueries } from "./activation-operation-effect-queries";

/** Exact roster gate between frozen evidence and activation-record construction. */
export class ActivationOperationReadiness {
  public constructor(
    private readonly sql: SqlStorage,
    private readonly queries: ActivationOperationEffectQueries,
  ) {}

  public readyToAppend(issuanceId: string): boolean {
    this.queries.requireCurrent(issuanceId, true);
    const rows = this.queries.slots(issuanceId);
    const expected = activationOperationSlotRoster(this.queries.sequence(issuanceId));
    const ready =
      rows.length === expected.length &&
      rows.every((row, index) => {
        const definition = expected[index];
        if (definition === undefined) return false;
        return (
          row.slot_id === definition.slotId &&
          row.slot_index === definition.slotIndex &&
          row.slot_kind === definition.slotKind &&
          (row.slot_kind === "READ_ONLY" ? row.state === "FROZEN" : row.state === "CONFIRMED")
        );
      });
    const issuance = this.queries.requireCurrent(issuanceId, true);
    const recordCommittedMs =
      issuance.record_committed_at === null ? Number.NaN : Date.parse(issuance.record_committed_at);
    const recordReady =
      ready &&
      Number.isFinite(recordCommittedMs) &&
      rows.every(
        (row) =>
          (row.observed_at === null || Date.parse(row.observed_at) <= recordCommittedMs) &&
          (row.committed_at === null || Date.parse(row.committed_at) <= recordCommittedMs),
      );
    if (recordReady) {
      this.sql.exec(
        `UPDATE activation_operation_issuances SET state = 'READY_TO_APPEND'
         WHERE issuance_id = ?
           AND state IN ('COLLECTING', 'FROZEN', 'EFFECTS_PENDING', 'DISPATCHED_HOLD')`,
        issuanceId,
      );
    }
    return recordReady;
  }
}
