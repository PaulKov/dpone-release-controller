import { canonicalBytes, sha256Hex } from "./canonical";
import { LIMITS } from "./config";
import { BrokerError } from "./errors";
import { ACTIVATED_RECORD_SCHEMA, PROVISIONED_RECORD_SCHEMA } from "./activation-contract";
import { assertActivationRecordDigest } from "./activation-records";
import { initializeActivationRegistrySchema } from "./activation-registry-schema";
import { validateActivationWorm } from "./activation-worm-binding";
import type { ActivationWorm, JsonObject } from "./types";

export interface ActivationRow extends Record<string, SqlStorageValue> {
  readonly canonical_bytes: ArrayBuffer;
  readonly committed_at: string;
  readonly operation_issuance_id: string | null;
  readonly record_digest: string;
  readonly record_id: string;
  readonly request_digest: string;
  readonly sequence: number;
  readonly worm_key: string | null;
  readonly worm_retention_until: string | null;
  readonly worm_version_id: string | null;
}

export interface PreparedActivationRecord {
  readonly bytes: Uint8Array;
  readonly committedAt: string;
  readonly operationIssuanceId: string | null;
  readonly recordDigest: string;
  readonly recordId: string;
  readonly requestDigest: string;
  readonly sequence: 0 | 1;
}

/**
 * Atomic append-only persistence for one version-scoped activation registry.
 *
 * Network I/O deliberately lives outside this class. Callers append canonical
 * bytes first, mirror those exact bytes, and then atomically bind the confirmed
 * immutable-object version. An ambiguous mirror response can therefore be
 * recovered without rebuilding or replacing the activation record.
 */
export class ActivationRecordStore {
  private readonly sql: SqlStorage;

  public constructor(private readonly storage: DurableObjectStorage) {
    this.sql = storage.sql;
    initializeActivationRegistrySchema(this.sql);
  }

  public async append(
    sequence: 0 | 1,
    requestDigest: string,
    record: JsonObject,
    committedAt: string,
    operationIssuanceId: string | null = null,
  ): Promise<ActivationRow> {
    const prepared = await this.prepare(
      sequence,
      requestDigest,
      record,
      committedAt,
      operationIssuanceId,
    );
    let resolved: ActivationRow | undefined;
    this.storage.transactionSync(() => {
      resolved = this.appendPrepared(prepared);
    });
    if (resolved === undefined) {
      throw new BrokerError("ACTIVATION_COMMIT_FAILED", 500, false);
    }
    return resolved;
  }

  public async prepare(
    sequence: 0 | 1,
    requestDigest: string,
    record: JsonObject,
    committedAt: string,
    operationIssuanceId: string | null,
  ): Promise<PreparedActivationRecord> {
    const bytes = canonicalBytes(record);
    if (bytes.byteLength === 0 || bytes.byteLength > LIMITS.bodyBytes) {
      throw new BrokerError("ACTIVATION_RECORD_SIZE_INVALID", 413, false);
    }
    const recordId = requireRecordId(record);
    if (
      record.sequence !== sequence ||
      record.schema_version !== 1 ||
      record.committed_at !== committedAt ||
      record.schema !== (sequence === 0 ? PROVISIONED_RECORD_SCHEMA : ACTIVATED_RECORD_SCHEMA)
    ) {
      throw new BrokerError("ACTIVATION_RECORD_BINDING_INVALID", 500, false);
    }
    await assertActivationRecordDigest(record, recordId);
    const recordDigest = `sha256:${await sha256Hex(bytes)}`;
    return {
      bytes: Uint8Array.from(bytes),
      committedAt,
      operationIssuanceId,
      recordDigest,
      recordId,
      requestDigest,
      sequence,
    };
  }

  /** Append a previously validated snapshot inside the caller's transaction. */
  public appendPrepared(prepared: PreparedActivationRecord): ActivationRow {
    const existing = this.find(prepared.sequence);
    if (existing !== undefined) {
      assertIdempotent(
        existing,
        prepared.requestDigest,
        prepared.recordId,
        prepared.recordDigest,
        prepared.bytes,
        prepared.committedAt,
        prepared.operationIssuanceId,
      );
      return existing;
    }
    this.sql.exec(
      `INSERT INTO activation_records(
        sequence, operation_issuance_id, request_digest, record_id, record_digest,
        canonical_bytes, committed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      prepared.sequence,
      prepared.operationIssuanceId,
      prepared.requestDigest,
      prepared.recordId,
      prepared.recordDigest,
      prepared.bytes.buffer,
      prepared.committedAt,
    );
    const inserted = this.find(prepared.sequence);
    if (inserted === undefined) {
      throw new BrokerError("ACTIVATION_COMMIT_FAILED", 500, false);
    }
    return inserted;
  }

  public confirm(sequence: 0 | 1, worm: ActivationWorm): ActivationRow {
    const existing = this.find(sequence);
    if (existing === undefined) {
      throw new BrokerError("ACTIVATION_RECORD_LOST", 500, false);
    }
    const envelope = decodeEnvelope(existing.canonical_bytes);
    const validatedWorm = validateActivationWorm(
      worm,
      envelope,
      existing.record_digest,
      sequence,
      existing.committed_at,
    );
    let resolved: ActivationRow | undefined;
    this.storage.transactionSync(() => {
      resolved = this.confirmPrepared(sequence, validatedWorm);
    });
    if (resolved === undefined) {
      throw new BrokerError("ACTIVATION_COMMIT_FAILED", 500, false);
    }
    return resolved;
  }

  /** Bind a validated WORM pointer inside the caller's transaction. */
  public confirmPrepared(sequence: 0 | 1, worm: ActivationWorm): ActivationRow {
    const current = this.find(sequence);
    if (current === undefined) {
      throw new BrokerError("ACTIVATION_RECORD_LOST", 500, false);
    }
    if (current.worm_version_id !== null) {
      assertSameWorm(current, worm);
      return current;
    }
    this.sql.exec(
      `UPDATE activation_records
       SET worm_key = ?, worm_version_id = ?, worm_retention_until = ?
       WHERE sequence = ? AND worm_version_id IS NULL`,
      worm.key,
      worm.versionId,
      worm.retentionUntil,
      sequence,
    );
    const resolved = this.find(sequence);
    if (resolved === undefined) {
      throw new BrokerError("ACTIVATION_COMMIT_FAILED", 500, false);
    }
    return resolved;
  }

  public requireConfirmed(sequence: 0 | 1): ActivationRow {
    const row = this.find(sequence);
    if (row === undefined) {
      throw new BrokerError("ACTIVATION_WORM_PENDING", 503, true);
    }
    if (
      row.worm_key === null ||
      row.worm_version_id === null ||
      row.worm_retention_until === null
    ) {
      throw new BrokerError("ACTIVATION_WORM_PENDING", 503, true);
    }
    return row;
  }

  public assertIdempotent(row: ActivationRow, requestDigest: string): void {
    if (row.request_digest !== requestDigest) {
      throw new BrokerError("ACTIVATION_APPEND_ONLY_CONFLICT", 409, false);
    }
  }

  public findByIssuance(operationIssuanceId: string): ActivationRow | undefined {
    return this.sql
      .exec<ActivationRow>(
        `SELECT sequence, operation_issuance_id, request_digest, record_id, record_digest,
                canonical_bytes, committed_at, worm_key, worm_version_id,
                worm_retention_until
         FROM activation_records WHERE operation_issuance_id = ?`,
        operationIssuanceId,
      )
      .toArray()[0];
  }

  public find(sequence: 0 | 1): ActivationRow | undefined {
    return this.sql
      .exec<ActivationRow>(
        `SELECT sequence, operation_issuance_id, request_digest, record_id, record_digest,
                canonical_bytes, committed_at, worm_key, worm_version_id,
                worm_retention_until
         FROM activation_records WHERE sequence = ?`,
        sequence,
      )
      .toArray()[0];
  }
}

function decodeEnvelope(value: ArrayBuffer): JsonObject {
  try {
    const decoded: unknown = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(value)),
    );
    if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) {
      throw new Error("object required");
    }
    return decoded as JsonObject;
  } catch {
    throw new BrokerError("ACTIVATION_STORED_BYTES_INVALID", 500, false);
  }
}

function requireRecordId(record: JsonObject): string {
  const value = record.record_id;
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(value)) {
    throw new BrokerError("ACTIVATION_RECORD_ID_INVALID", 500, false);
  }
  return value;
}

function assertIdempotent(
  row: ActivationRow,
  requestDigest: string,
  recordId: string,
  recordDigest: string,
  bytes: Uint8Array,
  committedAt: string,
  operationIssuanceId: string | null,
): void {
  if (
    row.request_digest !== requestDigest ||
    row.operation_issuance_id !== operationIssuanceId ||
    row.record_id !== recordId ||
    row.record_digest !== recordDigest ||
    row.committed_at !== committedAt ||
    !sameBytes(new Uint8Array(row.canonical_bytes), bytes)
  ) {
    throw new BrokerError("ACTIVATION_APPEND_ONLY_CONFLICT", 409, false);
  }
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function assertSameWorm(row: ActivationRow, worm: ActivationWorm): void {
  if (
    row.record_digest !== worm.digest ||
    row.worm_key !== worm.key ||
    row.worm_version_id !== worm.versionId ||
    row.worm_retention_until !== worm.retentionUntil
  ) {
    throw new BrokerError("ACTIVATION_WORM_VERSION_CONFLICT", 500, false);
  }
}
