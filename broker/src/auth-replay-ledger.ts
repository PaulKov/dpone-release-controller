import { DurableObject } from "cloudflare:workers";

import {
  EffectReplayStore,
  effectReplayBindingBody,
  hasEffectReplayCollision,
  type EffectReplayObservation,
} from "./auth-replay-effect-store";
import { sha256Hex } from "./canonical";
import { BrokerError, errorResponse } from "./errors";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

interface ReplayRow extends Record<string, SqlStorageValue> {
  readonly claims_digest: string;
  readonly expires_at: number;
  readonly jti_hash: string;
  readonly request_id: string;
}

export interface ReplayConsumption {
  readonly consumed: true;
  readonly replayed: boolean;
  readonly requestId: string;
}

export interface ReplayObservation {
  readonly consumed: boolean;
  readonly requestId: string;
}

export const ADMIN_REPLAY_LEDGER_NAME = "admin-access-v1";

export { effectReplayBindingBody };
export type { EffectReplayObservation };

export class AuthReplayLedger extends DurableObject<Record<string, never>> {
  private readonly effectReplays: EffectReplayStore;

  public constructor(ctx: DurableObjectState, env: Record<string, never>) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS oidc_jti (
        jti_hash TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL,
        used_at INTEGER NOT NULL,
        request_id TEXT NOT NULL UNIQUE,
        claims_digest TEXT NOT NULL
      ) STRICT;
      CREATE INDEX IF NOT EXISTS oidc_jti_expiry ON oidc_jti(expires_at);
    `);
    this.effectReplays = new EffectReplayStore(this.ctx.storage);
  }

  /**
   * Strict one-shot admission retained for existing GitHub OIDC callers.
   * Prefer {@link consumeOnce} in new call sites so replay policy is explicit.
   */
  public consume(value: JsonObject): Promise<ReplayConsumption> {
    return this.consumeOnce(value);
  }

  /** Consumes one verified authority exactly once, rejecting every duplicate. */
  public consumeOnce(value: JsonObject): Promise<ReplayConsumption> {
    return consumeReplay(this.ctx.storage, value, false);
  }

  /**
   * Gives the admin activation route exact, response-loss-safe idempotence.
   *
   * This policy is bound to the deterministic admin Durable Object name rather
   * than to a caller-supplied mode or scope field. A duplicate is accepted only
   * when every persisted replay binding is byte-for-byte identical.
   */
  public consumeIdempotentExact(value: JsonObject): Promise<ReplayConsumption> {
    if (this.ctx.id.name !== ADMIN_REPLAY_LEDGER_NAME) {
      throw new BrokerError("AUTH_REPLAY_POLICY_FORBIDDEN", 409, false);
    }
    return consumeReplay(this.ctx.storage, value, true);
  }

  /** Reconciles an ambiguous dispatch from hashes already sealed in its journal. */
  public observeConsumedExact(value: JsonObject): ReplayObservation {
    const body = exactObject(value, ["claims_digest", "expires_at", "jti_sha256", "request_id"]);
    const jtiHash = requireString(body, "jti_sha256", 71, /^sha256:[0-9a-f]{64}$/u).slice(7);
    const claimsDigest = requireString(body, "claims_digest", 71, /^sha256:[0-9a-f]{64}$/u);
    const expiresAt = requireInteger(body, "expires_at", 1);
    const suppliedRequestId = requireString(body, "request_id", 128);
    const rows = this.ctx.storage.sql
      .exec<ReplayRow>(
        `SELECT jti_hash, claims_digest, expires_at, request_id FROM oidc_jti
         WHERE jti_hash = ? OR request_id = ?`,
        jtiHash,
        suppliedRequestId,
      )
      .toArray();
    if (rows.length === 0) return { consumed: false, requestId: suppliedRequestId };
    const row = rows[0];
    if (
      rows.length !== 1 ||
      row?.jti_hash !== jtiHash ||
      row.claims_digest !== claimsDigest ||
      row.expires_at !== expiresAt ||
      row.request_id !== suppliedRequestId
    ) {
      throw new BrokerError("OIDC_REPLAY_RECONCILIATION_CONFLICT", 409, false);
    }
    return { consumed: true, requestId: suppliedRequestId };
  }

  /** Durably prepares one effect-linked JTI before the head journal marks dispatch. */
  public prepareEffectExact(value: JsonObject): EffectReplayObservation {
    this.requireEffectLedger();
    return this.effectReplays.prepare(value);
  }

  /** Commits a previously prepared effect without accepting an unjournaled consume. */
  public commitPreparedEffectExact(value: JsonObject): EffectReplayObservation {
    this.requireEffectLedger();
    return this.effectReplays.commit(value);
  }

  /** Cancels only a still-prepared effect, fencing a late original commit. */
  public cancelPreparedEffectExact(value: JsonObject): EffectReplayObservation {
    this.requireEffectLedger();
    return this.effectReplays.cancel(value);
  }

  /** Reads one exact effect tombstone without changing replay authority. */
  public observePreparedEffectExact(value: JsonObject): EffectReplayObservation {
    this.requireEffectLedger();
    return this.effectReplays.observe(value);
  }

  /** Makes only a terminal linked effect eligible for bounded tombstone cleanup. */
  public markEffectJournalTerminalExact(value: JsonObject): EffectReplayObservation {
    this.requireEffectLedger();
    return this.effectReplays.markJournalTerminal(value);
  }

  public override fetch(request: Request): Response {
    const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
    return errorResponse(new BrokerError("INTERNAL_RPC_REQUIRED", 404, false), requestId);
  }

  private requireEffectLedger(): void {
    if (this.ctx.id.name !== "github-oidc-v1") {
      throw new BrokerError("AUTH_REPLAY_POLICY_FORBIDDEN", 409, false);
    }
  }
}

async function consumeReplay(
  storage: DurableObjectStorage,
  value: JsonObject,
  allowExactReplay: boolean,
): Promise<ReplayConsumption> {
  const body = exactObject(value, ["claims_digest", "expires_at", "jti", "request_id"]);
  const jti = requireString(body, "jti", 256);
  const expiresAt = requireInteger(body, "expires_at", 1);
  const claimsDigest = requireString(body, "claims_digest", 71, /^sha256:[0-9a-f]{64}$/u);
  const suppliedRequestId = requireString(body, "request_id", 128);
  const now = Date.now();
  if (expiresAt * 1000 <= now) {
    throw new BrokerError("OIDC_EXPIRED", 401, false);
  }
  const jtiHash = await sha256Hex(jti);
  let replayed = false;
  storage.transactionSync(() => {
    if (hasEffectReplayCollision(storage, jtiHash, suppliedRequestId)) {
      throw new BrokerError("OIDC_REPLAY", 409, false);
    }
    const existing = storage.sql
      .exec<ReplayRow>(
        `SELECT jti_hash, claims_digest, expires_at, request_id
         FROM oidc_jti
         WHERE jti_hash = ? OR request_id = ?`,
        jtiHash,
        suppliedRequestId,
      )
      .toArray();
    if (existing.length > 0) {
      const row = existing[0];
      if (
        allowExactReplay &&
        existing.length === 1 &&
        row?.jti_hash === jtiHash &&
        row.claims_digest === claimsDigest &&
        row.expires_at === expiresAt &&
        row.request_id === suppliedRequestId
      ) {
        replayed = true;
        return;
      }
      throw new BrokerError("OIDC_REPLAY", 409, false);
    }
    storage.sql.exec(
      "INSERT INTO oidc_jti(jti_hash, expires_at, used_at, request_id, claims_digest) VALUES (?, ?, ?, ?, ?)",
      jtiHash,
      expiresAt,
      now,
      suppliedRequestId,
      claimsDigest,
    );
  });
  return { consumed: true, replayed, requestId: suppliedRequestId };
}

export function replayRequestBody(
  jti: string,
  expiresAt: number,
  requestId: string,
  claimsDigest: string,
): JsonObject {
  return {
    claims_digest: claimsDigest,
    expires_at: expiresAt,
    jti,
    request_id: requestId,
  };
}

export function replayObservationBody(
  jtiSha256: string,
  expiresAt: number,
  requestId: string,
  claimsDigest: string,
): JsonObject {
  return {
    claims_digest: claimsDigest,
    expires_at: expiresAt,
    jti_sha256: jtiSha256,
    request_id: requestId,
  };
}
