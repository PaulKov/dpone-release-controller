import { BrokerError } from "./errors";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

type EffectReplayState = "CANCELLED" | "CONSUMED" | "PREPARED";

interface EffectReplayRow extends Record<string, SqlStorageValue> {
  readonly claims_digest: string;
  readonly expires_at: number;
  readonly jti_hash: string;
  readonly journal_terminal_at: number | null;
  readonly request_id: string;
  readonly reservation_id: string;
  readonly state: EffectReplayState;
}

const EFFECT_REPLAY_MAX_ROWS = 10_000;
const TERMINAL_TOMBSTONE_GRACE_MS = 7 * 86_400_000;

interface EffectReplayBinding {
  readonly claimsDigest: string;
  readonly expiresAt: number;
  readonly jtiHash: string;
  readonly requestId: string;
  readonly reservationId: string;
}

export interface EffectReplayObservation {
  readonly requestId: string;
  readonly reservationId: string;
  readonly state: "ABSENT" | EffectReplayState;
}

/** Persistent prepare/commit/tombstone state for one effect-linked OIDC use. */
export class EffectReplayStore {
  public constructor(private readonly storage: DurableObjectStorage) {
    storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS oidc_effect_jti (
        jti_hash TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL,
        prepared_at INTEGER NOT NULL,
        terminal_at INTEGER,
        journal_terminal_at INTEGER,
        request_id TEXT NOT NULL UNIQUE,
        reservation_id TEXT NOT NULL,
        claims_digest TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('PREPARED','CONSUMED','CANCELLED'))
      ) STRICT;
      CREATE INDEX IF NOT EXISTS oidc_effect_reservation
        ON oidc_effect_jti(reservation_id);
    `);
  }

  public prepare(value: JsonObject): EffectReplayObservation {
    const binding = parseEffectReplayBinding(value);
    if (binding.expiresAt * 1000 <= Date.now()) {
      throw new BrokerError("OIDC_EXPIRED", 401, false);
    }
    let result: EffectReplayObservation | undefined;
    this.storage.transactionSync(() => {
      this.pruneTerminalTombstones(Date.now());
      if (hasOrdinaryCollision(this.storage, binding.jtiHash, binding.requestId)) {
        throw new BrokerError("OIDC_REPLAY", 409, false);
      }
      const existing = effectRows(this.storage, binding);
      if (existing.length !== 0) {
        const row = exactEffectRow(existing, binding);
        if (row.state !== "PREPARED") {
          throw new BrokerError("OIDC_REPLAY", 409, false);
        }
        result = effectObservation(row);
        return;
      }
      const count = this.storage.sql
        .exec<{ readonly count: number }>("SELECT COUNT(*) AS count FROM oidc_effect_jti")
        .one().count;
      if (count >= EFFECT_REPLAY_MAX_ROWS) {
        throw new BrokerError("OIDC_REPLAY_CAPACITY_EXHAUSTED", 503, false);
      }
      this.storage.sql.exec(
        `INSERT INTO oidc_effect_jti(
          jti_hash, expires_at, prepared_at, terminal_at, journal_terminal_at, request_id,
          reservation_id, claims_digest, state
        ) VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, 'PREPARED')`,
        binding.jtiHash,
        binding.expiresAt,
        Date.now(),
        binding.requestId,
        binding.reservationId,
        binding.claimsDigest,
      );
      result = observationFromBinding(binding, "PREPARED");
    });
    return requiredResult(result);
  }

  public commit(value: JsonObject): EffectReplayObservation {
    return this.transition(value, "CONSUMED");
  }

  public cancel(value: JsonObject): EffectReplayObservation {
    return this.transition(value, "CANCELLED");
  }

  public observe(value: JsonObject): EffectReplayObservation {
    const binding = parseEffectReplayBinding(value);
    const rows = effectRows(this.storage, binding);
    return rows.length === 0
      ? observationFromBinding(binding, "ABSENT")
      : effectObservation(exactEffectRow(rows, binding));
  }

  /** Marks the linked head effect terminal before bounded tombstone cleanup is eligible. */
  public markJournalTerminal(value: JsonObject): EffectReplayObservation {
    const binding = parseEffectReplayBinding(value);
    let result: EffectReplayObservation | undefined;
    this.storage.transactionSync(() => {
      const row = exactEffectRow(effectRows(this.storage, binding), binding);
      if (row.state !== "CANCELLED" && row.state !== "CONSUMED") {
        throw new BrokerError("OIDC_REPLAY_JOURNAL_NONTERMINAL", 409, false);
      }
      this.storage.sql.exec(
        `UPDATE oidc_effect_jti SET journal_terminal_at = COALESCE(journal_terminal_at, ?)
         WHERE jti_hash = ?`,
        Date.now(),
        binding.jtiHash,
      );
      result = effectObservation(exactEffectRow(effectRows(this.storage, binding), binding));
    });
    return requiredResult(result);
  }

  private transition(
    value: JsonObject,
    terminal: "CANCELLED" | "CONSUMED",
  ): EffectReplayObservation {
    const binding = parseEffectReplayBinding(value);
    let result: EffectReplayObservation | undefined;
    this.storage.transactionSync(() => {
      const row = exactEffectRow(effectRows(this.storage, binding), binding);
      if (row.state === terminal) {
        result = effectObservation(row);
        return;
      }
      if (row.state !== "PREPARED") {
        throw new BrokerError("OIDC_REPLAY_RECONCILIATION_CONFLICT", 409, false);
      }
      this.storage.sql.exec(
        `UPDATE oidc_effect_jti SET state = ?, terminal_at = ?
         WHERE jti_hash = ? AND state = 'PREPARED'`,
        terminal,
        Date.now(),
        binding.jtiHash,
      );
      result = effectObservation(exactEffectRow(effectRows(this.storage, binding), binding));
    });
    return requiredResult(result);
  }

  private pruneTerminalTombstones(nowMs: number): void {
    this.storage.sql.exec(
      `DELETE FROM oidc_effect_jti
       WHERE journal_terminal_at IS NOT NULL
         AND journal_terminal_at < ?
         AND expires_at < ?`,
      nowMs - TERMINAL_TOMBSTONE_GRACE_MS,
      Math.floor((nowMs - TERMINAL_TOMBSTONE_GRACE_MS) / 1000),
    );
  }
}

export function effectReplayBindingBody(
  jtiSha256: string,
  expiresAt: number,
  requestId: string,
  claimsDigest: string,
  reservationId: string,
): JsonObject {
  return {
    claims_digest: claimsDigest,
    expires_at: expiresAt,
    jti_sha256: jtiSha256,
    request_id: requestId,
    reservation_id: reservationId,
  };
}

export function hasEffectReplayCollision(
  storage: DurableObjectStorage,
  jtiHash: string,
  requestId: string,
): boolean {
  return (
    storage.sql
      .exec<{ readonly count: number }>(
        `SELECT COUNT(*) AS count FROM oidc_effect_jti
         WHERE jti_hash = ? OR request_id = ?`,
        jtiHash,
        requestId,
      )
      .one().count !== 0
  );
}

function parseEffectReplayBinding(value: JsonObject): EffectReplayBinding {
  const body = exactObject(value, [
    "claims_digest",
    "expires_at",
    "jti_sha256",
    "request_id",
    "reservation_id",
  ]);
  return {
    claimsDigest: requireString(body, "claims_digest", 71, /^sha256:[0-9a-f]{64}$/u),
    expiresAt: requireInteger(body, "expires_at", 1),
    jtiHash: requireString(body, "jti_sha256", 71, /^sha256:[0-9a-f]{64}$/u).slice(7),
    requestId: requireString(body, "request_id", 128),
    reservationId: requireString(body, "reservation_id", 71, /^sha256:[0-9a-f]{64}$/u),
  };
}

function effectRows(
  storage: DurableObjectStorage,
  binding: EffectReplayBinding,
): EffectReplayRow[] {
  return storage.sql
    .exec<EffectReplayRow>(
      `SELECT jti_hash, claims_digest, expires_at, journal_terminal_at,
              request_id, reservation_id, state
       FROM oidc_effect_jti WHERE jti_hash = ? OR request_id = ?`,
      binding.jtiHash,
      binding.requestId,
    )
    .toArray();
}

function exactEffectRow(rows: EffectReplayRow[], binding: EffectReplayBinding): EffectReplayRow {
  const row = rows[0];
  if (
    rows.length !== 1 ||
    row?.jti_hash !== binding.jtiHash ||
    row.claims_digest !== binding.claimsDigest ||
    row.expires_at !== binding.expiresAt ||
    row.request_id !== binding.requestId ||
    row.reservation_id !== binding.reservationId
  ) {
    throw new BrokerError("OIDC_REPLAY_RECONCILIATION_CONFLICT", 409, false);
  }
  return row;
}

function effectObservation(row: EffectReplayRow): EffectReplayObservation {
  return {
    requestId: row.request_id,
    reservationId: row.reservation_id,
    state: row.state,
  };
}

function observationFromBinding(
  binding: EffectReplayBinding,
  state: "ABSENT" | EffectReplayState,
): EffectReplayObservation {
  return {
    requestId: binding.requestId,
    reservationId: binding.reservationId,
    state,
  };
}

function hasOrdinaryCollision(
  storage: DurableObjectStorage,
  jtiHash: string,
  requestId: string,
): boolean {
  return (
    storage.sql
      .exec<{ readonly count: number }>(
        `SELECT COUNT(*) AS count FROM oidc_jti
         WHERE jti_hash = ? OR request_id = ?`,
        jtiHash,
        requestId,
      )
      .one().count !== 0
  );
}

function requiredResult(value: EffectReplayObservation | undefined): EffectReplayObservation {
  if (value === undefined) {
    throw new BrokerError("OIDC_REPLAY_STORE_FAILED", 500, false);
  }
  return value;
}
