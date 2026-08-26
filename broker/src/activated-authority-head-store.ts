import {
  activatedAuthorityHeadKey,
  activatedAuthorityHeadRecordSha256,
  parseActivatedAuthorityHead,
} from "./activated-authority-head";
import { ensureAuthorityEffectSchema } from "./activated-authority-effect-store";
import { canonicalBytes, canonicalJson } from "./canonical";
import { LIMITS } from "./config";
import { BrokerError } from "./errors";
import type { ActivationWorm, JsonObject, JsonValue } from "./types";
import { exactObject } from "./validation";

export interface ActivatedAuthorityHeadRow extends Record<string, SqlStorageValue> {
  readonly activated_record_id: string;
  readonly activated_record_sha256: string;
  readonly activated_service_authorities_sha256: string;
  readonly canonical_bytes: ArrayBuffer;
  readonly committed_at: string;
  readonly generation: number;
  readonly ingress_worker_version_id: string;
  readonly mirror_state: "CONFIRMED" | "DISPATCHED_HOLD" | "PREPARED";
  readonly record_id: string;
  readonly record_sha256: string;
  readonly request_digest: string;
  readonly worm_key: string | null;
  readonly worm_retention_until: string | null;
  readonly worm_version_id: string | null;
}

/** Append-only account-global head and effect-reservation persistence. */
export class ActivatedAuthorityHeadStore {
  private readonly sql: SqlStorage;

  public constructor(private readonly storage: DurableObjectStorage) {
    this.sql = storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS activated_authority_heads (
        generation INTEGER PRIMARY KEY CHECK(generation >= 1),
        request_digest TEXT NOT NULL UNIQUE,
        record_id TEXT NOT NULL UNIQUE,
        record_sha256 TEXT NOT NULL UNIQUE,
        canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 65536),
        activated_record_id TEXT NOT NULL UNIQUE,
        activated_record_sha256 TEXT NOT NULL UNIQUE,
        activated_service_authorities_sha256 TEXT NOT NULL,
        ingress_worker_version_id TEXT NOT NULL UNIQUE,
        committed_at TEXT NOT NULL,
        mirror_state TEXT NOT NULL CHECK(mirror_state IN ('PREPARED','DISPATCHED_HOLD','CONFIRMED')),
        worm_key TEXT,
        worm_version_id TEXT,
        worm_retention_until TEXT,
        CHECK (
          (mirror_state != 'CONFIRMED' AND worm_key IS NULL AND worm_version_id IS NULL AND worm_retention_until IS NULL)
          OR
          (mirror_state = 'CONFIRMED' AND worm_key IS NOT NULL AND worm_version_id IS NOT NULL AND worm_retention_until IS NOT NULL)
        )
      ) STRICT;
      CREATE UNIQUE INDEX IF NOT EXISTS one_pending_activated_authority_head
      ON activated_authority_heads((1)) WHERE mirror_state != 'CONFIRMED';
    `);
    ensureAuthorityEffectSchema(this.sql);
  }

  public async reserveHead(input: {
    readonly activatedRecordId: string;
    readonly activatedRecordSha256: string;
    readonly activatedServiceAuthoritiesSha256: string;
    readonly committedAt: string;
    readonly generation: number;
    readonly head: JsonObject;
    readonly ingressWorkerVersionId: string;
    readonly recordId: string;
    readonly recordSha256: string;
    readonly requestDigest: string;
  }): Promise<ActivatedAuthorityHeadRow> {
    const head = await parseActivatedAuthorityHead(input.head);
    const bytes = canonicalBytes(head);
    if (bytes.byteLength === 0 || bytes.byteLength > LIMITS.bodyBytes) {
      throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_SIZE_INVALID", 413, false);
    }
    const activated = exactObject(head.activated, ["record_id", "record_sha256", "worm"]);
    if (
      canonicalJson(head) !== canonicalJson(input.head) ||
      (await activatedAuthorityHeadRecordSha256(head)) !== input.recordSha256 ||
      head.record_id !== input.recordId ||
      activated.record_id !== input.activatedRecordId ||
      activated.record_sha256 !== input.activatedRecordSha256 ||
      head.activated_service_authorities_sha256 !== input.activatedServiceAuthoritiesSha256 ||
      head.ingress_worker_version_id !== input.ingressWorkerVersionId ||
      head.committed_at !== input.committedAt
    ) {
      throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_BINDING_INVALID", 409, false);
    }
    let resolved: ActivatedAuthorityHeadRow | undefined;
    this.storage.transactionSync(() => {
      const sameRequest = this.findByRequest(input.requestDigest);
      if (sameRequest !== undefined) {
        assertSameReservedHead(sameRequest, input);
        resolved = sameRequest;
        return;
      }
      this.sql.exec(
        `UPDATE authority_effect_reservations
         SET status = 'EXPIRED_UNDISPATCHED', result_bytes = NULL, result_sha256 = NULL
         WHERE status IN ('RESERVED','SEALED') AND expires_at < ?`,
        new Date(Date.now()).toISOString(),
      );
      if (this.pending() !== undefined || this.hasNonterminalEffect()) {
        throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_ADVANCE_BLOCKED", 409, false);
      }
      if (
        this.hasActivatedRecord(input.activatedRecordId, input.activatedRecordSha256) ||
        this.hasIngressVersion(input.ingressWorkerVersionId)
      ) {
        throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_ROLLBACK_FORBIDDEN", 409, false);
      }
      const current = this.current();
      if (input.generation !== (current?.generation ?? 0) + 1) {
        throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_GENERATION_INVALID", 409, false);
      }
      assertPrevious(input.head.previous, current);
      this.sql.exec(
        `INSERT INTO activated_authority_heads(
          generation, request_digest, record_id, record_sha256, canonical_bytes,
          activated_record_id, activated_record_sha256,
          activated_service_authorities_sha256, ingress_worker_version_id,
          committed_at, mirror_state
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED')`,
        input.generation,
        input.requestDigest,
        input.recordId,
        input.recordSha256,
        Uint8Array.from(bytes).buffer,
        input.activatedRecordId,
        input.activatedRecordSha256,
        input.activatedServiceAuthoritiesSha256,
        input.ingressWorkerVersionId,
        input.committedAt,
      );
      resolved = this.find(input.generation);
    });
    if (resolved === undefined)
      throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_STORE_FAILED", 500, false);
    return resolved;
  }

  public markDispatched(generation: number): ActivatedAuthorityHeadRow {
    this.storage.transactionSync(() => {
      const row = this.require(generation);
      if (row.mirror_state === "PREPARED") {
        this.sql.exec(
          "UPDATE activated_authority_heads SET mirror_state = 'DISPATCHED_HOLD' WHERE generation = ?",
          generation,
        );
      }
    });
    return this.require(generation);
  }

  public async confirm(
    generation: number,
    worm: ActivationWorm,
  ): Promise<ActivatedAuthorityHeadRow> {
    const pending = this.require(generation);
    const decoded: unknown = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(pending.canonical_bytes),
    );
    const head = await parseActivatedAuthorityHead(decoded);
    const expectedKey = await activatedAuthorityHeadKey(head);
    const retentionMs = Date.parse(worm.retentionUntil);
    if (
      worm.key !== expectedKey ||
      !/^sha256:[0-9a-f]{64}$/u.test(worm.digest) ||
      !/^[A-Za-z0-9._=-]{1,512}$/u.test(worm.versionId) ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(worm.retentionUntil) ||
      !Number.isFinite(retentionMs) ||
      new Date(retentionMs).toISOString() !== worm.retentionUntil ||
      retentionMs < Date.parse(pending.committed_at) + 2557 * 86_400_000
    ) {
      throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_WORM_CONFLICT", 409, false);
    }
    this.storage.transactionSync(() => {
      const row = this.require(generation);
      if (row.mirror_state === "CONFIRMED") {
        assertSameWorm(row, worm);
        return;
      }
      if (row.mirror_state !== "DISPATCHED_HOLD" || row.record_sha256 !== worm.digest) {
        throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_CONFIRM_INVALID", 409, false);
      }
      this.sql.exec(
        `UPDATE activated_authority_heads
         SET mirror_state = 'CONFIRMED', worm_key = ?, worm_version_id = ?, worm_retention_until = ?
         WHERE generation = ? AND mirror_state = 'DISPATCHED_HOLD'`,
        worm.key,
        worm.versionId,
        worm.retentionUntil,
        generation,
      );
    });
    return this.require(generation);
  }

  public current(): ActivatedAuthorityHeadRow | undefined {
    return this.sql
      .exec<ActivatedAuthorityHeadRow>(
        `${HEAD_SELECT} WHERE mirror_state = 'CONFIRMED' ORDER BY generation DESC LIMIT 1`,
      )
      .toArray()[0];
  }

  public pending(): ActivatedAuthorityHeadRow | undefined {
    return this.sql
      .exec<ActivatedAuthorityHeadRow>(`${HEAD_SELECT} WHERE mirror_state != 'CONFIRMED' LIMIT 1`)
      .toArray()[0];
  }

  public find(generation: number): ActivatedAuthorityHeadRow | undefined {
    return this.sql
      .exec<ActivatedAuthorityHeadRow>(`${HEAD_SELECT} WHERE generation = ?`, generation)
      .toArray()[0];
  }

  public findByRequest(requestDigest: string): ActivatedAuthorityHeadRow | undefined {
    return this.sql
      .exec<ActivatedAuthorityHeadRow>(`${HEAD_SELECT} WHERE request_digest = ?`, requestDigest)
      .toArray()[0];
  }

  private require(generation: number): ActivatedAuthorityHeadRow {
    const row = this.find(generation);
    if (row === undefined) throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_MISSING", 503, false);
    return row;
  }

  private hasNonterminalEffect(): boolean {
    return (
      this.sql
        .exec<{ readonly count: number }>(
          `SELECT COUNT(*) AS count FROM authority_effect_reservations
           WHERE status IN ('RESERVED','SEALED','DISPATCHED_HOLD')`,
        )
        .one().count > 0
    );
  }

  private hasActivatedRecord(recordId: string, recordSha256: string): boolean {
    return (
      this.sql
        .exec<{ readonly count: number }>(
          `SELECT COUNT(*) AS count FROM activated_authority_heads
           WHERE activated_record_id = ? OR activated_record_sha256 = ?`,
          recordId,
          recordSha256,
        )
        .one().count > 0
    );
  }

  private hasIngressVersion(workerVersionId: string): boolean {
    return (
      this.sql
        .exec<{
          readonly count: number;
        }>(
          "SELECT COUNT(*) AS count FROM activated_authority_heads WHERE ingress_worker_version_id = ?",
          workerVersionId,
        )
        .one().count > 0
    );
  }
}

const HEAD_SELECT = `SELECT generation, request_digest, record_id, record_sha256,
  canonical_bytes, activated_record_id, activated_record_sha256,
  activated_service_authorities_sha256, ingress_worker_version_id, committed_at,
  mirror_state, worm_key, worm_version_id, worm_retention_until
  FROM activated_authority_heads`;

function assertSameReservedHead(
  row: ActivatedAuthorityHeadRow,
  input: {
    readonly generation: number;
    readonly recordId: string;
    readonly recordSha256: string;
    readonly activatedRecordId: string;
    readonly activatedRecordSha256: string;
    readonly activatedServiceAuthoritiesSha256: string;
    readonly committedAt: string;
    readonly ingressWorkerVersionId: string;
    readonly head: JsonObject;
  },
): void {
  if (
    row.generation !== input.generation ||
    row.record_id !== input.recordId ||
    row.record_sha256 !== input.recordSha256 ||
    row.activated_record_id !== input.activatedRecordId ||
    row.activated_record_sha256 !== input.activatedRecordSha256 ||
    row.activated_service_authorities_sha256 !== input.activatedServiceAuthoritiesSha256 ||
    row.committed_at !== input.committedAt ||
    new TextDecoder("utf-8", { fatal: true }).decode(row.canonical_bytes) !==
      canonicalJson(input.head) ||
    row.ingress_worker_version_id !== input.ingressWorkerVersionId
  ) {
    throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_APPEND_CONFLICT", 409, false);
  }
}

function assertSameWorm(row: ActivatedAuthorityHeadRow, worm: ActivationWorm): void {
  if (
    row.record_sha256 !== worm.digest ||
    row.worm_key !== worm.key ||
    row.worm_version_id !== worm.versionId ||
    row.worm_retention_until !== worm.retentionUntil
  ) {
    throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_WORM_CONFLICT", 409, false);
  }
}

function assertPrevious(
  value: JsonValue | undefined,
  current: ActivatedAuthorityHeadRow | undefined,
): void {
  if (current === undefined) {
    if (value !== "GENESIS") {
      throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_PREVIOUS_INVALID", 409, false);
    }
    return;
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_PREVIOUS_INVALID", 409, false);
  }
  const keys = Object.keys(value).sort();
  if (
    keys.join(",") !== "generation,record_id,record_sha256" ||
    value.generation !== current.generation ||
    value.record_id !== current.record_id ||
    value.record_sha256 !== current.record_sha256
  ) {
    throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_PREVIOUS_INVALID", 409, false);
  }
}
