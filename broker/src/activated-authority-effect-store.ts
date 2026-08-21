import { parseActivationProofEffectReservation } from "./activated-authority-effect";
import {
  AUTHORITY_EFFECT_SELECT,
  decodeEffectBytes as decode,
  decodeNullableEffectBytes as decodeNullable,
  ensureAuthorityEffectSchema,
  requiredEffectNumber as requiredNumber,
  requiredEffectObject as requiredObject,
  requiredEffectString as requiredString,
} from "./activated-authority-effect-storage";
import { canonicalBytes, canonicalJson, sha256Hex } from "./canonical";
import { LIMITS } from "./config";
import { BrokerError } from "./errors";
import type { JsonObject } from "./types";

export type AuthorityEffectStatus =
  | "CANCELLED_UNDISPATCHED"
  | "CONFIRMED"
  | "DISPATCHED_HOLD"
  | "EXPIRED_UNDISPATCHED"
  | "RESERVED"
  | "SEALED";

export interface AuthorityEffectRow extends Record<string, SqlStorageValue> {
  readonly canonical_bytes: ArrayBuffer;
  readonly created_at: string;
  readonly expires_at: string;
  readonly head_generation: number;
  readonly head_record_id: string;
  readonly head_record_sha256: string;
  readonly intent_sha256: string;
  readonly operation: "ACTIVATION_PROOF";
  readonly request_id: string;
  readonly reservation_id: string;
  readonly result_bytes: ArrayBuffer | null;
  readonly result_sha256: string | null;
  readonly status: AuthorityEffectStatus;
}

/** Owns exact one-use effect transitions under the account-global head. */
export class ActivatedAuthorityEffectStore {
  private readonly sql: SqlStorage;

  public constructor(private readonly storage: DurableObjectStorage) {
    this.sql = storage.sql;
    ensureAuthorityEffectSchema(this.sql);
  }

  public async reserve(value: unknown): Promise<AuthorityEffectRow> {
    const reservation = await parseActivationProofEffectReservation(value);
    const head = requiredObject(reservation, "head");
    const bytes = canonicalBytes(reservation);
    let resolved: AuthorityEffectRow | undefined;
    this.storage.transactionSync(() => {
      this.expireUndispatched(Date.now());
      const existing = this.find(requiredString(reservation, "reservation_id"));
      if (existing !== undefined) {
        if (
          existing.head_generation !== requiredNumber(head, "generation") ||
          existing.head_record_id !== requiredString(head, "record_id") ||
          existing.head_record_sha256 !== requiredString(head, "record_sha256") ||
          existing.intent_sha256 !== requiredString(reservation, "intent_sha256")
        ) {
          throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_CONFLICT", 409, false);
        }
        if (
          existing.status === "RESERVED" ||
          existing.status === "EXPIRED_UNDISPATCHED" ||
          existing.status === "CANCELLED_UNDISPATCHED"
        ) {
          this.replaceUndispatched(existing, reservation, bytes);
          resolved = this.find(existing.reservation_id);
        } else {
          resolved = existing;
        }
        return;
      }
      if (this.pendingHeadCount() !== 0) {
        throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_ADVANCE_PENDING", 503, true);
      }
      this.assertCurrentHead(head);
      this.sql.exec(
        `INSERT INTO authority_effect_reservations(
          reservation_id, canonical_bytes, head_generation, head_record_id,
          head_record_sha256, operation, intent_sha256, request_id,
          created_at, expires_at, status
        ) VALUES (?, ?, ?, ?, ?, 'ACTIVATION_PROOF', ?, ?, ?, ?, 'RESERVED')`,
        requiredString(reservation, "reservation_id"),
        Uint8Array.from(bytes).buffer,
        requiredNumber(head, "generation"),
        requiredString(head, "record_id"),
        requiredString(head, "record_sha256"),
        requiredString(reservation, "intent_sha256"),
        requiredString(reservation, "request_id"),
        requiredString(reservation, "created_at"),
        requiredString(reservation, "expires_at"),
      );
      resolved = this.find(requiredString(reservation, "reservation_id"));
    });
    if (resolved === undefined) {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_STORE_FAILED", 500, false);
    }
    return resolved;
  }

  public dispatch(reservationId: string, nowMs: number): AuthorityEffectRow {
    this.storage.transactionSync(() => {
      const row = this.require(reservationId);
      if (row.status === "DISPATCHED_HOLD" || row.status === "CONFIRMED") return;
      if (row.status !== "SEALED" || Date.parse(row.expires_at) < nowMs) {
        if (row.status === "RESERVED" || row.status === "SEALED") {
          this.sql.exec(
            `UPDATE authority_effect_reservations
             SET status = 'EXPIRED_UNDISPATCHED', result_bytes = NULL, result_sha256 = NULL
             WHERE reservation_id = ?`,
            reservationId,
          );
        }
        return;
      }
      this.sql.exec(
        "UPDATE authority_effect_reservations SET status = 'DISPATCHED_HOLD' WHERE reservation_id = ? AND status = 'SEALED'",
        reservationId,
      );
    });
    const dispatched = this.require(reservationId);
    if (dispatched.status !== "DISPATCHED_HOLD" && dispatched.status !== "CONFIRMED") {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_NOT_DISPATCHABLE", 409, false);
    }
    return dispatched;
  }

  public async seal(reservationId: string, canonicalResult: string): Promise<AuthorityEffectRow> {
    const bytes = new TextEncoder().encode(canonicalResult);
    if (bytes.byteLength === 0 || bytes.byteLength > LIMITS.bodyBytes) {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RESULT_SIZE_INVALID", 413, false);
    }
    let decoded: unknown;
    try {
      decoded = JSON.parse(canonicalResult);
    } catch {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RESULT_INVALID", 409, false);
    }
    if (
      decoded === null ||
      typeof decoded !== "object" ||
      Array.isArray(decoded) ||
      canonicalJson(decoded) !== canonicalResult
    ) {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RESULT_INVALID", 409, false);
    }
    const digest = `sha256:${await sha256Hex(bytes)}`;
    this.storage.transactionSync(() => {
      const row = this.require(reservationId);
      if (
        row.status === "SEALED" ||
        row.status === "DISPATCHED_HOLD" ||
        row.status === "CONFIRMED"
      ) {
        if (row.result_sha256 !== digest || decodeNullable(row.result_bytes) !== canonicalResult) {
          throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_CONFLICT", 409, false);
        }
        return;
      }
      if (row.status !== "RESERVED") {
        throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_NOT_SEALABLE", 409, false);
      }
      this.sql.exec(
        `UPDATE authority_effect_reservations
         SET status = 'SEALED', result_bytes = ?, result_sha256 = ? WHERE reservation_id = ?`,
        Uint8Array.from(bytes).buffer,
        digest,
        reservationId,
      );
    });
    return this.require(reservationId);
  }

  public confirm(reservationId: string, resultSha256: string): AuthorityEffectRow {
    if (!/^sha256:[0-9a-f]{64}$/u.test(resultSha256)) {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RESULT_INVALID", 409, false);
    }
    this.storage.transactionSync(() => {
      const row = this.require(reservationId);
      if (row.status === "CONFIRMED") {
        if (row.result_sha256 !== resultSha256) {
          throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_CONFLICT", 409, false);
        }
        return;
      }
      if (row.status !== "DISPATCHED_HOLD" || row.result_sha256 !== resultSha256) {
        throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_NOT_DISPATCHED", 409, false);
      }
      this.sql.exec(
        "UPDATE authority_effect_reservations SET status = 'CONFIRMED' WHERE reservation_id = ?",
        reservationId,
      );
    });
    return this.require(reservationId);
  }

  public cancelUndispatched(reservationId: string): AuthorityEffectRow {
    this.storage.transactionSync(() => {
      const row = this.require(reservationId);
      if (row.status === "CANCELLED_UNDISPATCHED") return;
      if (row.status !== "RESERVED" && row.status !== "SEALED") {
        throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_ALREADY_DISPATCHED", 409, false);
      }
      this.sql.exec(
        `UPDATE authority_effect_reservations
         SET status = 'CANCELLED_UNDISPATCHED', result_bytes = NULL, result_sha256 = NULL
         WHERE reservation_id = ?`,
        reservationId,
      );
    });
    return this.require(reservationId);
  }

  public find(reservationId: string): AuthorityEffectRow | undefined {
    return this.sql
      .exec<AuthorityEffectRow>(
        `${AUTHORITY_EFFECT_SELECT} WHERE reservation_id = ?`,
        reservationId,
      )
      .toArray()[0];
  }

  public async reservation(row: AuthorityEffectRow): Promise<JsonObject> {
    const text = decode(row.canonical_bytes);
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_STORED_INVALID", 503, false);
    }
    const reservation = await parseActivationProofEffectReservation(value);
    if (text !== canonicalJson(reservation) || reservation.reservation_id !== row.reservation_id) {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_STORED_INVALID", 503, false);
    }
    return reservation;
  }

  public async rearmAfterObservedAbsent(
    reservationId: string,
    replacementValue: unknown,
  ): Promise<AuthorityEffectRow> {
    const replacement = await parseActivationProofEffectReservation(replacementValue);
    const bytes = canonicalBytes(replacement);
    this.storage.transactionSync(() => {
      const row = this.require(reservationId);
      if (
        row.status !== "DISPATCHED_HOLD" ||
        replacement.reservation_id !== reservationId ||
        replacement.intent_sha256 !== row.intent_sha256
      ) {
        throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_REARM_INVALID", 409, false);
      }
      this.replaceUndispatched(row, replacement, bytes);
    });
    return this.require(reservationId);
  }

  public resultCanonical(row: AuthorityEffectRow): string | undefined {
    return row.result_bytes === null ? undefined : decode(row.result_bytes);
  }

  private require(reservationId: string): AuthorityEffectRow {
    const row = this.find(reservationId);
    if (row === undefined) {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_MISSING", 409, false);
    }
    return row;
  }

  private expireUndispatched(nowMs: number): void {
    this.sql.exec(
      `UPDATE authority_effect_reservations SET status = 'EXPIRED_UNDISPATCHED'
       WHERE status = 'RESERVED' AND expires_at < ?`,
      new Date(nowMs).toISOString(),
    );
  }

  private pendingHeadCount(): number {
    return this.sql
      .exec<{
        readonly count: number;
      }>(
        "SELECT COUNT(*) AS count FROM activated_authority_heads WHERE mirror_state != 'CONFIRMED'",
      )
      .one().count;
  }

  private assertCurrentHead(head: JsonObject): void {
    const current = this.sql
      .exec<{
        readonly generation: number;
        readonly record_id: string;
        readonly record_sha256: string;
      }>(
        `SELECT generation, record_id, record_sha256 FROM activated_authority_heads
         WHERE mirror_state = 'CONFIRMED' ORDER BY generation DESC LIMIT 1`,
      )
      .toArray()[0];
    if (
      current?.generation !== requiredNumber(head, "generation") ||
      current.record_id !== requiredString(head, "record_id") ||
      current.record_sha256 !== requiredString(head, "record_sha256")
    ) {
      throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_STALE", 409, false);
    }
  }

  private replaceUndispatched(
    row: AuthorityEffectRow,
    reservation: JsonObject,
    bytes: Uint8Array,
  ): void {
    const head = requiredObject(reservation, "head");
    if (
      row.head_generation !== requiredNumber(head, "generation") ||
      row.head_record_id !== requiredString(head, "record_id") ||
      row.head_record_sha256 !== requiredString(head, "record_sha256")
    ) {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_REARM_INVALID", 409, false);
    }
    this.sql.exec(
      `UPDATE authority_effect_reservations SET
        canonical_bytes = ?, request_id = ?, created_at = ?, expires_at = ?,
        status = 'RESERVED', result_bytes = NULL, result_sha256 = NULL
       WHERE reservation_id = ?`,
      Uint8Array.from(bytes).buffer,
      requiredString(reservation, "request_id"),
      requiredString(reservation, "created_at"),
      requiredString(reservation, "expires_at"),
      row.reservation_id,
    );
  }
}

export { ensureAuthorityEffectSchema } from "./activated-authority-effect-storage";
