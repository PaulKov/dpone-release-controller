import type { ActivationOperationSequence } from "./activation-operation-contract";
import type { ActivationOperationCloudflareExpectedIssuance } from "./activation-operation-cloudflare-request";
import { operationEffectFail } from "./activation-operation-effects-validation";
import type {
  ActivationOperationIssuanceRow,
  ActivationOperationSlotRow,
} from "./activation-operation-schema";
import type { ActivationWorm } from "./types";

/** Closed SQL projection shared by direct and Cloudflare operation coordinators. */
export class ActivationOperationEffectQueries {
  public constructor(private readonly sql: SqlStorage) {}

  public slot(issuanceId: string, slotId: string): ActivationOperationSlotRow | undefined {
    return this.sql
      .exec<ActivationOperationSlotRow>(
        `SELECT * FROM activation_operation_slots WHERE issuance_id = ? AND slot_id = ?`,
        issuanceId,
        slotId,
      )
      .toArray()[0];
  }

  public slots(issuanceId: string): readonly ActivationOperationSlotRow[] {
    return this.sql
      .exec<ActivationOperationSlotRow>(
        `SELECT * FROM activation_operation_slots WHERE issuance_id = ? ORDER BY slot_index`,
        issuanceId,
      )
      .toArray();
  }

  public anchors(issuanceId: string): readonly Record<string, SqlStorageValue>[] {
    return this.sql
      .exec(
        `SELECT * FROM activation_cloudflare_anchors WHERE issuance_id = ? ORDER BY slot_index`,
        issuanceId,
      )
      .toArray();
  }

  public ingressWorkerVersion(issuanceId: string): string {
    const row = this.sql
      .exec<{ readonly worker_version_id: string }>(
        `SELECT intent.worker_version_id AS worker_version_id
         FROM activation_operation_intents AS intent
         JOIN activation_operation_issuances AS issuance
           ON issuance.attempt_id = intent.attempt_id
         WHERE issuance.issuance_id = ?`,
        issuanceId,
      )
      .toArray()[0];
    if (row === undefined) operationEffectFail("ACTIVATION_OPERATION_ISSUANCE_MISSING", 500);
    return row.worker_version_id;
  }

  public sequence(issuanceId: string): ActivationOperationSequence {
    const row = this.sql
      .exec<{ readonly sequence: number }>(
        `SELECT intent.sequence AS sequence
         FROM activation_operation_intents AS intent
         JOIN activation_operation_issuances AS issuance
           ON issuance.attempt_id = intent.attempt_id
         WHERE issuance.issuance_id = ?`,
        issuanceId,
      )
      .toArray()[0];
    if (row === undefined || (row.sequence !== 0 && row.sequence !== 1)) {
      operationEffectFail("ACTIVATION_OPERATION_ISSUANCE_MISSING", 500);
    }
    return row.sequence;
  }

  public cloudflareIssuance(issuanceId: string): ActivationOperationCloudflareExpectedIssuance {
    const row = this.sql
      .exec<{
        readonly internal_request_id: string;
        readonly issuance_id: string;
        readonly issued_at: string;
        readonly fresh_until: string;
        readonly ordinal: number;
        readonly sequence: number;
        readonly worker_version_id: string;
      }>(
        `SELECT issuance.internal_request_id, issuance.issuance_id, issuance.issued_at,
                issuance.fresh_until, issuance.ordinal,
                intent.sequence, intent.worker_version_id
         FROM activation_operation_issuances AS issuance
         JOIN activation_operation_intents AS intent ON intent.attempt_id = issuance.attempt_id
         WHERE issuance.issuance_id = ?`,
        issuanceId,
      )
      .toArray()[0];
    if (row === undefined || (row.sequence !== 0 && row.sequence !== 1)) {
      operationEffectFail("ACTIVATION_OPERATION_ISSUANCE_MISSING", 500);
    }
    return {
      ingressWorkerVersionId: row.worker_version_id,
      internalRequestId: row.internal_request_id,
      issuanceId: row.issuance_id,
      issuedAt: row.issued_at,
      ordinal: row.ordinal,
      sequence: row.sequence,
      freshUntil: row.fresh_until,
    };
  }

  public expireIssuance(issuanceId: string): void {
    const hasDispatch = this.slots(issuanceId).some((slot) =>
      ["CONFIRMED", "DELEGATED_IN_FLIGHT", "DISPATCHED_HOLD", "HOLD"].includes(slot.state),
    );
    this.sql.exec(
      `UPDATE activation_operation_issuances SET state = ?
       WHERE issuance_id = ? AND state IN (
         'RESERVED', 'COLLECTING', 'FROZEN', 'EFFECTS_PENDING', 'READY_TO_APPEND'
       )`,
      hasDispatch ? "DISPATCHED_HOLD" : "EXPIRED_UNDISPATCHED",
      issuanceId,
    );
  }

  public confirmDirect(
    row: ActivationOperationSlotRow,
    resultBytes: Uint8Array,
    resultSha256: string,
    worm: ActivationWorm,
  ): void {
    this.sql.exec(
      `UPDATE activation_operation_slots SET
         result_bytes = ?, result_sha256 = ?, worm_digest = ?, worm_key = ?,
         worm_version_id = ?, worm_retention_until = ?, state = 'CONFIRMED'
       WHERE issuance_id = ? AND slot_id = ? AND state = 'DELEGATED_IN_FLIGHT'`,
      resultBytes.buffer,
      resultSha256,
      worm.digest,
      worm.key,
      worm.versionId,
      worm.retentionUntil,
      row.issuance_id,
      row.slot_id,
    );
  }

  public requireCurrent(
    issuanceId: string,
    allowDispatchedHold: boolean,
  ): ActivationOperationIssuanceRow {
    const row = requireIssuance(this.issuance(issuanceId));
    const current = this.sql
      .exec<{ readonly issuance_id: string }>(
        `SELECT issuance_id FROM activation_operation_issuances
         WHERE attempt_id = ? ORDER BY ordinal DESC LIMIT 1`,
        row.attempt_id,
      )
      .toArray()[0];
    const allowed = new Set([
      "COLLECTING",
      "EFFECTS_PENDING",
      "FROZEN",
      "READY_TO_APPEND",
      "RESERVED",
      ...(allowDispatchedHold ? ["DISPATCHED_HOLD"] : []),
    ]);
    if (current?.issuance_id !== row.issuance_id || !allowed.has(row.state)) {
      operationEffectFail("ACTIVATION_OPERATION_ISSUANCE_STALE");
    }
    return row;
  }

  private issuance(issuanceId: string): ActivationOperationIssuanceRow | undefined {
    return this.sql
      .exec<ActivationOperationIssuanceRow>(
        `SELECT * FROM activation_operation_issuances WHERE issuance_id = ?`,
        issuanceId,
      )
      .toArray()[0];
  }
}

function requireIssuance(
  value: ActivationOperationIssuanceRow | undefined,
): ActivationOperationIssuanceRow {
  if (value === undefined) operationEffectFail("ACTIVATION_OPERATION_ISSUANCE_MISSING", 500);
  return value;
}
