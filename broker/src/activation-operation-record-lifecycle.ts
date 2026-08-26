import { ActivationRecordStore, type ActivationRow } from "./activation-record-store";
import { provisionedRecordServicePin } from "./activation-schema";
import {
  assertSameActivationOperationRecordSource,
  loadActivationOperationRecordSource,
  type ActivationOperationRecordSource,
} from "./activation-operation-record-source";
import type { ActivationOperationIssuanceRow } from "./activation-operation-schema";
import { decodeCanonicalObject } from "./activation-registry-codec";
import { expectedActivationWormKey } from "./activation-worm-binding";
import { sha256Hex } from "./canonical";
import { BrokerError } from "./errors";
import type { JsonObject } from "./types";
import {
  prepareWormExactObjectEffect,
  type PreparedWormExactObjectEffect,
} from "./worm-exact-object-effect-contract";
import { parseWormExactObjectEffectResult } from "./worm-exact-object-effect-result";

export interface ActivationOperationRecordMaterializer {
  materialize(source: ActivationOperationRecordSource): Promise<JsonObject>;
}

export interface ActivationRecordWormAction {
  readonly action: "COMPLETE" | "EXECUTE_EFFECT";
  readonly effect: PreparedWormExactObjectEffect;
  readonly requestId: string;
}

/** Atomic bridge from a final evidence roster to one immutable activation record. */
export class ActivationOperationRecordLifecycle {
  private readonly records: ActivationRecordStore;
  private readonly sql: SqlStorage;

  public constructor(
    private readonly storage: DurableObjectStorage,
    private readonly materializer: ActivationOperationRecordMaterializer,
  ) {
    this.records = new ActivationRecordStore(storage);
    this.sql = storage.sql;
  }

  public async freezeAndAppend(issuanceId: string): Promise<ActivationRow> {
    const existing = this.records.findByIssuance(issuanceId);
    if (existing !== undefined) {
      const context = this.requireRecordContext(issuanceId, ["CONFIRMED", "RECORD_APPENDED"]);
      assertRecordContext(existing, context);
      return existing;
    }
    const source = loadActivationOperationRecordSource(this.sql, issuanceId);
    if (source.issuance.state !== "READY_TO_APPEND") lifecycleFail("ACTIVATION_RECORD_NOT_READY");
    const record = await this.materializer.materialize(source);
    const prepared = await this.records.prepare(
      source.sequence,
      source.intent.intent_sha256,
      record,
      requiredRecordTime(source.issuance),
      issuanceId,
    );
    let resolved: ActivationRow | undefined;
    this.storage.transactionSync(() => {
      const fenced = loadActivationOperationRecordSource(this.sql, issuanceId);
      assertSameActivationOperationRecordSource(source, fenced);
      if (fenced.issuance.state === "RECORD_APPENDED" || fenced.issuance.state === "CONFIRMED") {
        const concurrent = requireRecord(this.records.findByIssuance(issuanceId));
        const concurrentContext = this.requireRecordContext(issuanceId, [
          "CONFIRMED",
          "RECORD_APPENDED",
        ]);
        resolved = this.records.appendPrepared(prepared);
        assertSameRecord(concurrent, requireRecord(resolved));
        assertRecordContext(concurrent, concurrentContext);
        return;
      }
      if (fenced.issuance.state !== "READY_TO_APPEND") {
        lifecycleFail("ACTIVATION_RECORD_NOT_READY");
      }
      const appended = this.records.appendPrepared(prepared);
      const ready = this.requireRecordContext(issuanceId, ["READY_TO_APPEND"]);
      assertRecordContext(appended, ready);
      resolved = appended;
      this.sql.exec(
        `UPDATE activation_operation_issuances SET state = 'RECORD_APPENDED'
         WHERE issuance_id = ? AND state = 'READY_TO_APPEND'`,
        issuanceId,
      );
      this.requireRecordContext(issuanceId, ["RECORD_APPENDED"]);
    });
    return requireRecord(resolved);
  }

  public async nextRecordWorm(issuanceId: string): Promise<ActivationRecordWormAction> {
    const context = this.requireRecordContext(issuanceId, ["CONFIRMED", "RECORD_APPENDED"]);
    const record = requireRecord(this.records.findByIssuance(issuanceId));
    assertRecordContext(record, context);
    const effect = await this.prepareRecordEffect(record, context);
    if (context.issuance.state === "CONFIRMED") {
      const resultBytes = requiredResultBytes(context.issuance);
      const resultSha256 = `sha256:${await sha256Hex(resultBytes)}`;
      assertStoredResult(context.issuance, resultBytes, resultSha256);
      const confirmed = parseWormExactObjectEffectResult(resultBytes, effect);
      this.records.confirmPrepared(context.sequence, confirmed.worm);
    }
    return {
      action: context.issuance.state === "CONFIRMED" ? "COMPLETE" : "EXECUTE_EFFECT",
      effect,
      requestId: context.issuance.internal_request_id,
    };
  }

  public async confirmRecordWorm(
    issuanceId: string,
    canonicalResultBytes: Uint8Array,
  ): Promise<ActivationRow> {
    const resultBytes = boundedResult(canonicalResultBytes);
    const context = this.requireRecordContext(issuanceId, ["CONFIRMED", "RECORD_APPENDED"]);
    const record = requireRecord(this.records.findByIssuance(issuanceId));
    assertRecordContext(record, context);
    const effect = await this.prepareRecordEffect(record, context);
    const confirmed = parseWormExactObjectEffectResult(resultBytes, effect);
    const resultSha256 = `sha256:${await sha256Hex(resultBytes)}`;
    let resolved: ActivationRow | undefined;
    this.storage.transactionSync(() => {
      const fenced = this.requireRecordContext(issuanceId, ["CONFIRMED", "RECORD_APPENDED"]);
      const current = requireRecord(this.records.findByIssuance(issuanceId));
      assertRecordContext(current, fenced);
      assertSameRecord(record, current);
      if (fenced.issuance.state === "CONFIRMED") {
        assertStoredResult(fenced.issuance, resultBytes, resultSha256);
        resolved = this.records.confirmPrepared(context.sequence, confirmed.worm);
        return;
      }
      resolved = this.records.confirmPrepared(context.sequence, confirmed.worm);
      this.sql.exec(
        `UPDATE activation_operation_issuances SET
           record_worm_result_bytes = ?, record_worm_result_sha256 = ?, state = 'CONFIRMED'
         WHERE issuance_id = ? AND state = 'RECORD_APPENDED'`,
        resultBytes.buffer,
        resultSha256,
        issuanceId,
      );
      this.sql.exec(
        `UPDATE activation_operation_intents SET state = 'CONFIRMED'
         WHERE attempt_id = ? AND state = 'OPEN'`,
        context.issuance.attempt_id,
      );
      const confirmedContext = this.requireRecordContext(issuanceId, ["CONFIRMED"]);
      assertStoredResult(confirmedContext.issuance, resultBytes, resultSha256);
    });
    return requireRecord(resolved);
  }

  private async prepareRecordEffect(
    record: ActivationRow,
    context: ActivationRecordContext,
  ): Promise<PreparedWormExactObjectEffect> {
    const envelope = decodeCanonicalObject(new Uint8Array(record.canonical_bytes));
    const provisioned =
      context.sequence === 0
        ? envelope
        : decodeCanonicalObject(new Uint8Array(this.records.requireConfirmed(0).canonical_bytes));
    const executor = provisionedRecordServicePin(provisioned, "worm_mirror");
    const observer = provisionedRecordServicePin(provisioned, "worm_version_observer");
    return prepareWormExactObjectEffect({
      canonicalBytes: new Uint8Array(record.canonical_bytes),
      committedAt: record.committed_at,
      digest: record.record_digest,
      key: expectedActivationWormKey(envelope, record.record_digest, context.sequence),
      pins: {
        executorServiceIdentity: executor.serviceIdentity,
        executorVersionId: executor.versionId,
        observerServiceIdentity: observer.serviceIdentity,
        observerVersionId: observer.versionId,
      },
    });
  }

  private requireRecordContext(
    issuanceId: string,
    allowedStates: readonly string[],
  ): ActivationRecordContext {
    const row = this.sql
      .exec<ActivationRecordContextRow>(
        `SELECT issuance.*, intent.sequence, intent.intent_sha256,
                intent.worker_version_id, intent.state AS intent_state
         FROM activation_operation_issuances AS issuance
         JOIN activation_operation_intents AS intent ON intent.attempt_id = issuance.attempt_id
         WHERE issuance.issuance_id = ?`,
        issuanceId,
      )
      .toArray()[0];
    if (row === undefined || (row.sequence !== 0 && row.sequence !== 1)) {
      lifecycleFail("ACTIVATION_OPERATION_ISSUANCE_MISSING", 500);
    }
    const latest = this.sql
      .exec<{ readonly issuance_id: string }>(
        `SELECT issuance_id FROM activation_operation_issuances
         WHERE attempt_id = ? ORDER BY ordinal DESC LIMIT 1`,
        row.attempt_id,
      )
      .toArray()[0];
    if (latest?.issuance_id !== issuanceId || !allowedStates.includes(row.state)) {
      lifecycleFail("ACTIVATION_OPERATION_ISSUANCE_STALE");
    }
    const statesAgree =
      row.state === "CONFIRMED" ? row.intent_state === "CONFIRMED" : row.intent_state === "OPEN";
    if (!statesAgree) lifecycleFail("ACTIVATION_OPERATION_INTENT_STATE_CONFLICT", 500);
    return { issuance: row, sequence: row.sequence };
  }
}

interface ActivationRecordContext {
  readonly issuance: ActivationRecordContextRow;
  readonly sequence: 0 | 1;
}

interface ActivationRecordContextRow extends ActivationOperationIssuanceRow {
  readonly intent_sha256: string;
  readonly intent_state: string;
  readonly sequence: number;
  readonly worker_version_id: string;
}

function requiredRecordTime(issuance: ActivationOperationIssuanceRow): string {
  if (issuance.record_committed_at === null) {
    lifecycleFail("ACTIVATION_OPERATION_RECORD_TIME_MISSING", 500);
  }
  return issuance.record_committed_at;
}

function requiredResultBytes(issuance: ActivationOperationIssuanceRow): Uint8Array {
  if (issuance.record_worm_result_bytes === null) {
    lifecycleFail("ACTIVATION_RECORD_WORM_RESULT_MISSING", 500);
  }
  return boundedResult(new Uint8Array(issuance.record_worm_result_bytes));
}

function boundedResult(bytes: Uint8Array): Uint8Array {
  if (bytes.byteLength < 1 || bytes.byteLength > 65_536) {
    lifecycleFail("ACTIVATION_RECORD_WORM_RESULT_SIZE_INVALID", 413);
  }
  return Uint8Array.from(bytes);
}

function assertStoredResult(
  issuance: ActivationOperationIssuanceRow,
  bytes: Uint8Array,
  digest: string,
): void {
  if (
    issuance.record_worm_result_bytes === null ||
    issuance.record_worm_result_sha256 !== digest ||
    !sameBytes(new Uint8Array(issuance.record_worm_result_bytes), bytes)
  ) {
    lifecycleFail("ACTIVATION_RECORD_WORM_RESULT_CONFLICT");
  }
}

function assertSameRecord(expected: ActivationRow, actual: ActivationRow): void {
  if (
    expected.operation_issuance_id !== actual.operation_issuance_id ||
    expected.record_id !== actual.record_id ||
    expected.record_digest !== actual.record_digest ||
    expected.committed_at !== actual.committed_at ||
    !sameBytes(new Uint8Array(expected.canonical_bytes), new Uint8Array(actual.canonical_bytes))
  ) {
    lifecycleFail("ACTIVATION_RECORD_APPEND_CONFLICT");
  }
}

function assertRecordContext(record: ActivationRow, context: ActivationRecordContext): void {
  const envelope = decodeCanonicalObject(new Uint8Array(record.canonical_bytes));
  if (
    record.operation_issuance_id !== context.issuance.issuance_id ||
    record.sequence !== context.sequence ||
    record.request_digest !== context.issuance.intent_sha256 ||
    record.committed_at !== requiredRecordTime(context.issuance) ||
    envelope.request_id !== context.issuance.internal_request_id ||
    envelopeWorkerVersion(envelope, context.sequence) !== context.issuance.worker_version_id
  ) {
    lifecycleFail("ACTIVATION_RECORD_CONTEXT_CONFLICT", 500);
  }
}

function envelopeWorkerVersion(envelope: JsonObject, sequence: 0 | 1): unknown {
  const container = sequence === 0 ? envelope.evidence : envelope.provisioned;
  if (container === null || typeof container !== "object" || Array.isArray(container)) return null;
  const source = sequence === 0 ? container.broker : container;
  if (source === null || typeof source !== "object" || Array.isArray(source)) return null;
  return source.worker_version_id;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function requireRecord(value: ActivationRow | undefined): ActivationRow {
  if (value === undefined) lifecycleFail("ACTIVATION_RECORD_LOST", 500);
  return value;
}

function lifecycleFail(code: string, status = 409): never {
  throw new BrokerError(code, status, false);
}
