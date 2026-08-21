import { activationOperationSlotRoster } from "./activation-operation-contract";
import type {
  ActivationOperationIntentRow,
  ActivationOperationIssuanceRow,
  ActivationOperationSlotRow,
} from "./activation-operation-schema";
import { canonicalBytes, canonicalJson } from "./canonical";
import { decodeCanonicalObject } from "./activation-registry-codec";
import { BrokerError } from "./errors";
import { ownExactUint8Array } from "./exact-uint8array";
import type { JsonObject } from "./types";

export interface ActivationOperationRecordSource {
  readonly anchors: readonly Record<string, SqlStorageValue>[];
  readonly binding: string;
  readonly intent: ActivationOperationIntentRow;
  readonly issuance: ActivationOperationIssuanceRow;
  readonly semanticRequest: JsonObject;
  readonly semanticRequestBytes: Uint8Array;
  readonly sequence: 0 | 1;
  readonly slots: readonly ActivationOperationSlotRow[];
}

/** Load an owned, exact final evidence roster for activation-record materialization. */
export function loadActivationOperationRecordSource(
  sql: SqlStorage,
  issuanceId: string,
): ActivationOperationRecordSource {
  const issuance = requireIssuance(
    sql
      .exec<ActivationOperationIssuanceRow>(
        `SELECT * FROM activation_operation_issuances WHERE issuance_id = ?`,
        issuanceId,
      )
      .toArray()[0],
  );
  const latest = sql
    .exec<{ readonly issuance_id: string }>(
      `SELECT issuance_id FROM activation_operation_issuances
       WHERE attempt_id = ? ORDER BY ordinal DESC LIMIT 1`,
      issuance.attempt_id,
    )
    .toArray()[0];
  if (latest?.issuance_id !== issuanceId) sourceFail("ACTIVATION_OPERATION_ISSUANCE_STALE");
  const intent = sql
    .exec<ActivationOperationIntentRow>(
      `SELECT * FROM activation_operation_intents WHERE attempt_id = ?`,
      issuance.attempt_id,
    )
    .toArray()[0];
  if (intent === undefined || (intent.sequence !== 0 && intent.sequence !== 1)) {
    sourceFail("ACTIVATION_OPERATION_INTENT_MISSING", 500);
  }
  const sequence = requireSequence(intent.sequence);
  if (issuance.record_committed_at === null) {
    sourceFail("ACTIVATION_OPERATION_RECORD_TIME_MISSING", 500);
  }
  const semanticRequestBytes = recordSourceBytes(
    new Uint8Array(intent.semantic_request_bytes),
    65_536,
  );
  const slots = sql
    .exec<ActivationOperationSlotRow>(
      `SELECT * FROM activation_operation_slots WHERE issuance_id = ? ORDER BY slot_index`,
      issuanceId,
    )
    .toArray()
    .map(cloneSlot);
  assertFinalRoster(slots, sequence);
  const anchors = sql
    .exec(
      `SELECT * FROM activation_cloudflare_anchors
       WHERE issuance_id = ? ORDER BY slot_index`,
      issuanceId,
    )
    .toArray()
    .map((anchor) => ({ ...anchor }));
  if (anchors.length !== 15) sourceFail("ACTIVATION_OPERATION_ANCHOR_ROSTER_INVALID", 500);
  const source = {
    anchors,
    intent: { ...intent, semantic_request_bytes: exactBuffer(semanticRequestBytes) },
    issuance: { ...issuance },
    semanticRequest: decodeCanonicalObject(semanticRequestBytes),
    semanticRequestBytes,
    sequence,
    slots,
  };
  return { ...source, binding: sourceBinding(source) };
}

export function assertSameActivationOperationRecordSource(
  expected: ActivationOperationRecordSource,
  actual: ActivationOperationRecordSource,
): void {
  const expectedBinding = sourceBinding(expected);
  const actualBinding = sourceBinding(actual);
  if (
    expected.binding !== expectedBinding ||
    actual.binding !== actualBinding ||
    expectedBinding !== actualBinding
  ) {
    sourceFail("ACTIVATION_OPERATION_RECORD_SOURCE_CONFLICT");
  }
  if (
    !sameBytes(expected.semanticRequestBytes, actual.semanticRequestBytes) ||
    !sameBytes(canonicalBytes(expected.semanticRequest), expected.semanticRequestBytes) ||
    !sameBytes(canonicalBytes(actual.semanticRequest), actual.semanticRequestBytes) ||
    !sameBytes(
      new Uint8Array(expected.intent.semantic_request_bytes),
      expected.semanticRequestBytes,
    ) ||
    !sameBytes(new Uint8Array(actual.intent.semantic_request_bytes), actual.semanticRequestBytes)
  ) {
    sourceFail("ACTIVATION_OPERATION_RECORD_SOURCE_CONFLICT");
  }
  for (let index = 0; index < expected.slots.length; index += 1) {
    const left = expected.slots[index];
    const right = actual.slots[index];
    if (
      left === undefined ||
      right === undefined ||
      !sameNullableBuffer(left.provider_request_bytes, right.provider_request_bytes) ||
      !sameNullableBuffer(left.frozen_payload_bytes, right.frozen_payload_bytes) ||
      !sameNullableBuffer(left.result_bytes, right.result_bytes)
    ) {
      sourceFail("ACTIVATION_OPERATION_RECORD_SOURCE_CONFLICT");
    }
  }
}

function assertFinalRoster(rows: readonly ActivationOperationSlotRow[], sequence: 0 | 1): void {
  const expected = activationOperationSlotRoster(sequence);
  if (
    rows.length !== expected.length ||
    rows.some((row, index) => {
      const definition = expected[index];
      return (
        row.slot_id !== definition?.slotId ||
        row.slot_kind !== definition.slotKind ||
        row.slot_index !== definition.slotIndex ||
        (row.slot_kind === "READ_ONLY" ? row.state !== "FROZEN" : row.state !== "CONFIRMED")
      );
    })
  ) {
    sourceFail("ACTIVATION_OPERATION_SLOT_ROSTER_INVALID", 500);
  }
}

function sourceBinding(source: Omit<ActivationOperationRecordSource, "binding">): string {
  return canonicalJson({
    anchors: source.anchors,
    intent: {
      attempt_id: source.intent.attempt_id,
      intent_sha256: source.intent.intent_sha256,
      sequence: source.intent.sequence,
      worker_version_id: source.intent.worker_version_id,
    },
    issuance: {
      fresh_until: source.issuance.fresh_until,
      internal_request_id: source.issuance.internal_request_id,
      issuance_id: source.issuance.issuance_id,
      issued_at: source.issuance.issued_at,
      ordinal: source.issuance.ordinal,
      record_committed_at: source.issuance.record_committed_at,
    },
    slots: source.slots.map(slotBinding),
  });
}

function slotBinding(row: ActivationOperationSlotRow): JsonObject {
  return {
    batch_id: row.batch_id,
    b2_observer_service_identity: row.b2_observer_service_identity,
    b2_observer_worker_version_id: row.b2_observer_worker_version_id,
    cloudflare_observer_service_identity: row.cloudflare_observer_service_identity,
    cloudflare_observer_worker_version_id: row.cloudflare_observer_worker_version_id,
    committed_at: row.committed_at,
    effect_id: row.effect_id,
    executor_service_identity: row.executor_service_identity,
    executor_worker_version_id: row.executor_worker_version_id,
    expected_worm_key: row.expected_worm_key,
    frozen_payload_sha256: row.frozen_payload_sha256,
    observed_at: row.observed_at,
    observer_service_identity: row.observer_service_identity,
    observer_worker_version_id: row.observer_worker_version_id,
    provider_request_sha256: row.provider_request_sha256,
    result_sha256: row.result_sha256,
    slot_id: row.slot_id,
    slot_index: row.slot_index,
    slot_kind: row.slot_kind,
    state: row.state,
    worm_digest: row.worm_digest,
    worm_key: row.worm_key,
    worm_retention_until: row.worm_retention_until,
    worm_service_identity: row.worm_service_identity,
    worm_version_id: row.worm_version_id,
    worm_worker_version_id: row.worm_worker_version_id,
  };
}

function cloneSlot(row: ActivationOperationSlotRow): ActivationOperationSlotRow {
  return {
    ...row,
    frozen_payload_bytes: cloneNullableBuffer(row.frozen_payload_bytes),
    provider_request_bytes: cloneNullableBuffer(row.provider_request_bytes),
    result_bytes: cloneNullableBuffer(row.result_bytes),
  };
}

function cloneNullableBuffer(value: ArrayBuffer | null): ArrayBuffer | null {
  return value === null ? null : value.slice(0);
}

function sameNullableBuffer(left: ArrayBuffer | null, right: ArrayBuffer | null): boolean {
  return left === null
    ? right === null
    : right !== null && sameBytes(new Uint8Array(left), new Uint8Array(right));
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function recordSourceBytes(bytes: unknown, maximum: number): Uint8Array<ArrayBuffer> {
  return ownExactUint8Array(bytes, {
    code: "ACTIVATION_OPERATION_RECORD_SOURCE_SIZE_INVALID",
    invalidStatus: 413,
    maximum,
    minimum: 1,
    sizeStatus: 413,
  });
}

function exactBuffer(bytes: Uint8Array): ArrayBuffer {
  return recordSourceBytes(bytes, 65_536).buffer;
}

function requireSequence(value: number): 0 | 1 {
  if (value !== 0 && value !== 1) sourceFail("ACTIVATION_OPERATION_SEQUENCE_INVALID", 500);
  return value;
}

function requireIssuance(
  value: ActivationOperationIssuanceRow | undefined,
): ActivationOperationIssuanceRow {
  if (value === undefined) sourceFail("ACTIVATION_OPERATION_ISSUANCE_MISSING", 500);
  return value;
}

function sourceFail(code: string, status = 409): never {
  throw new BrokerError(code, status, false);
}
