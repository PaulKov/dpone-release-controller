import { validateVersionId } from "./b2-inventory";
import { BrokerError } from "./errors";
import type { ActivationWorm } from "./types";
import {
  assertWormExactObjectEffectPins,
  canonicalEffectTimestamp,
  effectError,
  prepareWormExactObjectEffect,
  type ConfirmedWormExactObjectEffect,
  type PreparedWormExactObjectEffect,
  type WormExactObjectEffectAction,
  type WormExactObjectEffectInput,
  type WormExactObjectEffectPins,
  type WormExactObjectEffectSnapshot,
} from "./worm-exact-object-effect-contract";
import {
  copyStoredBytes,
  equalStoredBytes,
  initializeWormExactObjectEffectSchema,
  type WormExactObjectEffectRow,
} from "./worm-exact-object-effect-storage";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const HOLD_CODE = /^[A-Z][A-Z0-9_]{0,127}$/u;
const RETENTION_MILLISECONDS = 2557 * 86_400_000;

/** Durable singleton state machine for one exact append-only object effect. */
export class WormExactObjectEffectStore {
  private readonly sql: SqlStorage;

  public constructor(private readonly storage: DurableObjectStorage) {
    this.sql = storage.sql;
    initializeWormExactObjectEffectSchema(this.sql);
  }

  /** Atomically persists exact bytes and every identity field before any effect. */
  public async seal(input: WormExactObjectEffectInput): Promise<WormExactObjectEffectSnapshot> {
    const prepared = await prepareWormExactObjectEffect(input);
    this.storage.transactionSync(() => {
      const current = this.row();
      if (current !== undefined) {
        this.assertSameSeal(current, prepared);
        return;
      }
      this.sql.exec(
        `INSERT INTO worm_exact_object_effect(
          singleton, effect_id, canonical_bytes, committed_at, digest, object_key,
          executor_service_identity, executor_version_id,
          observer_service_identity, observer_version_id, status
        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED')`,
        prepared.effectId,
        Uint8Array.from(prepared.canonicalBytes).buffer,
        prepared.committedAt,
        prepared.digest,
        prepared.key,
        prepared.pins.executorServiceIdentity,
        prepared.pins.executorVersionId,
        prepared.pins.observerServiceIdentity,
        prepared.pins.observerVersionId,
      );
    });
    return this.snapshot(prepared.effectId, prepared.pins);
  }

  /** Returns the next legal action; ABSENT is atomically consumed into IN_FLIGHT. */
  public next(effectId: string, pins: WormExactObjectEffectPins): WormExactObjectEffectAction {
    let effect: WormExactObjectEffectSnapshot | undefined;
    let dispatchClaimed = false;
    this.storage.transactionSync(() => {
      let row = this.requireBound(effectId, pins);
      if (row.status === "ABSENT") {
        this.sql.exec(
          `UPDATE worm_exact_object_effect SET status = 'IN_FLIGHT'
           WHERE singleton = 1 AND status = 'ABSENT'`,
        );
        row = this.requireBound(effectId, pins);
        dispatchClaimed = true;
      }
      effect = decodeSnapshot(row);
    });
    const resolved = requiredSnapshot(effect);
    return { action: actionFor(resolved.status, dispatchClaimed), effect: resolved };
  }

  public markAbsent(
    effectId: string,
    pins: WormExactObjectEffectPins,
    inventoryDigest: string,
  ): void {
    if (!DIGEST.test(inventoryDigest)) {
      throw effectError("WORM_EXACT_OBJECT_EFFECT_ABSENCE_INVALID");
    }
    this.storage.transactionSync(() => {
      const row = this.requireBound(effectId, pins);
      if (row.status === "PREPARED") {
        this.sql.exec(
          `UPDATE worm_exact_object_effect
           SET absence_inventory_digest = ?, status = 'ABSENT'
           WHERE singleton = 1 AND status = 'PREPARED'`,
          inventoryDigest,
        );
        return;
      }
      if (row.absence_inventory_digest !== inventoryDigest) {
        throw effectError("WORM_EXACT_OBJECT_EFFECT_ABSENCE_CONFLICT");
      }
    });
  }

  public accept(effectId: string, pins: WormExactObjectEffectPins, writerVersionId: string): void {
    validateVersionId(writerVersionId);
    this.storage.transactionSync(() => {
      const row = this.requireBound(effectId, pins);
      if (row.status === "CONFIRMED") {
        if (row.worm_version_id !== writerVersionId) throw versionConflict();
        return;
      }
      if (row.status === "ACCEPTED") {
        if (row.writer_version_id !== writerVersionId) throw versionConflict();
        return;
      }
      if (row.status !== "IN_FLIGHT" && row.status !== "DISPATCHED_HOLD") {
        throw effectError("WORM_EXACT_OBJECT_EFFECT_NOT_DISPATCHED");
      }
      if (row.writer_version_id !== null && row.writer_version_id !== writerVersionId) {
        throw versionConflict();
      }
      this.sql.exec(
        `UPDATE worm_exact_object_effect
         SET writer_version_id = ?, status = 'ACCEPTED' WHERE singleton = 1`,
        writerVersionId,
      );
    });
  }

  /** Permanently removes every post-dispatch path back to writer invocation. */
  public markDispatchedHold(effectId: string, pins: WormExactObjectEffectPins): void {
    this.storage.transactionSync(() => {
      const row = this.requireBound(effectId, pins);
      if (row.status === "DISPATCHED_HOLD" || row.status === "CONFIRMED" || row.status === "HOLD") {
        return;
      }
      if (row.status !== "IN_FLIGHT" && row.status !== "ACCEPTED") {
        throw effectError("WORM_EXACT_OBJECT_EFFECT_NOT_DISPATCHED");
      }
      this.sql.exec(
        `UPDATE worm_exact_object_effect SET status = 'DISPATCHED_HOLD'
         WHERE singleton = 1`,
      );
    });
  }

  public confirm(effectId: string, pins: WormExactObjectEffectPins, worm: ActivationWorm): void {
    this.storage.transactionSync(() => {
      const row = this.requireBound(effectId, pins);
      validateWorm(row, worm);
      if (row.status === "CONFIRMED") return;
      if (
        row.status !== "IN_FLIGHT" &&
        row.status !== "ACCEPTED" &&
        row.status !== "DISPATCHED_HOLD"
      ) {
        throw effectError("WORM_EXACT_OBJECT_EFFECT_NOT_DISPATCHED");
      }
      if (row.writer_version_id !== null && row.writer_version_id !== worm.versionId) {
        throw versionConflict();
      }
      this.sql.exec(
        `UPDATE worm_exact_object_effect
         SET worm_version_id = ?, worm_retention_until = ?, status = 'CONFIRMED'
         WHERE singleton = 1`,
        worm.versionId,
        worm.retentionUntil,
      );
    });
  }

  public hold(effectId: string, pins: WormExactObjectEffectPins, code: string): void {
    if (!HOLD_CODE.test(code)) throw effectError("WORM_EXACT_OBJECT_EFFECT_HOLD_CODE_INVALID");
    this.storage.transactionSync(() => {
      const row = this.requireBound(effectId, pins);
      if (row.status === "CONFIRMED") return;
      if (row.status === "HOLD") {
        if (row.hold_code !== code) {
          throw effectError("WORM_EXACT_OBJECT_EFFECT_HOLD_CONFLICT");
        }
        return;
      }
      this.sql.exec(
        `UPDATE worm_exact_object_effect SET status = 'HOLD', hold_code = ?
         WHERE singleton = 1`,
        code,
      );
    });
  }

  public snapshot(
    effectId: string,
    pins: WormExactObjectEffectPins,
  ): WormExactObjectEffectSnapshot {
    return decodeSnapshot(this.requireBound(effectId, pins));
  }

  public confirmed(
    effectId: string,
    pins: WormExactObjectEffectPins,
  ): ConfirmedWormExactObjectEffect {
    const effect = this.snapshot(effectId, pins);
    if (
      effect.status !== "CONFIRMED" ||
      effect.absenceInventoryDigest === null ||
      effect.worm === null
    ) {
      throw effectError("WORM_EXACT_OBJECT_EFFECT_PENDING", true);
    }
    return Object.freeze({
      absenceInventoryDigest: effect.absenceInventoryDigest,
      committedAt: effect.committedAt,
      digest: effect.digest,
      effectId: effect.effectId,
      key: effect.key,
      pins: effect.pins,
      status: "CONFIRMED",
      worm: Object.freeze({ ...effect.worm }),
    });
  }

  private row(): WormExactObjectEffectRow | undefined {
    return this.sql
      .exec<WormExactObjectEffectRow>(`SELECT * FROM worm_exact_object_effect WHERE singleton = 1`)
      .toArray()[0];
  }

  private requireBound(
    effectId: string,
    pins: WormExactObjectEffectPins,
  ): WormExactObjectEffectRow {
    assertWormExactObjectEffectPins(pins);
    const row = this.row();
    if (row === undefined) throw effectError("WORM_EXACT_OBJECT_EFFECT_MISSING");
    if (
      row.effect_id !== effectId ||
      row.executor_service_identity !== pins.executorServiceIdentity ||
      row.executor_version_id !== pins.executorVersionId ||
      row.observer_service_identity !== pins.observerServiceIdentity ||
      row.observer_version_id !== pins.observerVersionId
    ) {
      throw effectError("WORM_EXACT_OBJECT_EFFECT_PIN_CONFLICT");
    }
    return row;
  }

  private assertSameSeal(
    row: WormExactObjectEffectRow,
    prepared: PreparedWormExactObjectEffect,
  ): void {
    if (
      row.effect_id !== prepared.effectId ||
      row.committed_at !== prepared.committedAt ||
      row.digest !== prepared.digest ||
      row.object_key !== prepared.key ||
      row.executor_service_identity !== prepared.pins.executorServiceIdentity ||
      row.executor_version_id !== prepared.pins.executorVersionId ||
      row.observer_service_identity !== prepared.pins.observerServiceIdentity ||
      row.observer_version_id !== prepared.pins.observerVersionId ||
      !equalStoredBytes(row.canonical_bytes, prepared.canonicalBytes)
    ) {
      throw effectError("WORM_EXACT_OBJECT_EFFECT_SEAL_CONFLICT");
    }
  }
}

function decodeSnapshot(row: WormExactObjectEffectRow): WormExactObjectEffectSnapshot {
  const pins = Object.freeze({
    executorServiceIdentity: row.executor_service_identity,
    executorVersionId: row.executor_version_id,
    observerServiceIdentity: row.observer_service_identity,
    observerVersionId: row.observer_version_id,
  });
  return {
    absenceInventoryDigest: row.absence_inventory_digest,
    canonicalBytes: copyStoredBytes(row.canonical_bytes),
    committedAt: row.committed_at,
    digest: row.digest,
    effectId: row.effect_id,
    holdCode: row.hold_code,
    key: row.object_key,
    pins,
    status: row.status,
    writerVersionId: row.writer_version_id,
    worm:
      row.worm_version_id === null || row.worm_retention_until === null
        ? null
        : {
            digest: row.digest,
            key: row.object_key,
            retentionUntil: row.worm_retention_until,
            versionId: row.worm_version_id,
          },
  };
}

function actionFor(
  status: WormExactObjectEffectSnapshot["status"],
  dispatchClaimed: boolean,
): WormExactObjectEffectAction["action"] {
  if (status === "PREPARED") return "CHECK_ABSENCE";
  if (status === "IN_FLIGHT") return dispatchClaimed ? "DISPATCH" : "RECONCILE";
  if (status === "ACCEPTED" || status === "DISPATCHED_HOLD") return "RECONCILE";
  if (status === "CONFIRMED") return "COMPLETE";
  if (status === "HOLD") return "STOP_HOLD";
  throw effectError("WORM_EXACT_OBJECT_EFFECT_STATE_INVALID");
}

function validateWorm(row: WormExactObjectEffectRow, worm: ActivationWorm): void {
  validateVersionId(worm.versionId);
  const retentionUntil = canonicalEffectTimestamp(worm.retentionUntil);
  if (
    worm.digest !== row.digest ||
    worm.key !== row.object_key ||
    Date.parse(retentionUntil) < Date.parse(row.committed_at) + RETENTION_MILLISECONDS ||
    (row.status === "CONFIRMED" &&
      (row.worm_version_id !== worm.versionId || row.worm_retention_until !== retentionUntil))
  ) {
    throw effectError("WORM_EXACT_OBJECT_EFFECT_CONFIRMATION_CONFLICT");
  }
}

function requiredSnapshot(
  value: WormExactObjectEffectSnapshot | undefined,
): WormExactObjectEffectSnapshot {
  if (value === undefined)
    throw new BrokerError("WORM_EXACT_OBJECT_EFFECT_STORE_FAILED", 500, false);
  return value;
}

function versionConflict(): BrokerError {
  return effectError("WORM_EXACT_OBJECT_EFFECT_WRITER_VERSION_CONFLICT");
}
