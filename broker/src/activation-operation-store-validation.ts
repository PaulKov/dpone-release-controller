import {
  ACTIVATION_OPERATION_ATTEMPT_SCHEMA,
  type ActivationOperationIdentity,
  type ActivationOperationIssuance,
  type ActivationOperationSequence,
} from "./activation-operation-contract";
import type {
  ActivationOperationIntentRow,
  ActivationOperationIssuanceRow,
  ActivationOperationSlotRow,
} from "./activation-operation-schema";
import { canonicalBytes, digestObject, sha256Hex, timingSafeEqual } from "./canonical";
import { BrokerError } from "./errors";
import { ownExactUint8Array } from "./exact-uint8array";

export function operationIssuanceView(
  row: ActivationOperationIssuanceRow,
  sequence: ActivationOperationSequence,
): ActivationOperationIssuance {
  return {
    attemptId: row.attempt_id,
    freshUntil: row.fresh_until,
    internalRequestId: row.internal_request_id,
    issuanceId: row.issuance_id,
    issuedAt: row.issued_at,
    ordinal: row.ordinal,
    sequence,
    state: row.state,
  };
}

export function assertSameOperationIntent(
  row: ActivationOperationIntentRow,
  identity: ActivationOperationIdentity,
): void {
  if (
    row.attempt_id !== identity.attemptId ||
    row.intent_sha256 !== identity.intentSha256 ||
    row.worker_version_id !== identity.workerVersionId ||
    !operationBytesEqual(new Uint8Array(row.semantic_request_bytes), identity.semanticRequestBytes)
  ) {
    operationStoreFail("ACTIVATION_OPERATION_INTENT_CONFLICT");
  }
}

export async function validateOperationIdentity(
  identity: ActivationOperationIdentity,
  semanticRequestBytes: Uint8Array,
): Promise<ActivationOperationIdentity> {
  const semanticObjectBytes = canonicalBytes(identity.semanticRequest);
  if (!operationBytesEqual(semanticObjectBytes, semanticRequestBytes)) {
    operationStoreFail("ACTIVATION_OPERATION_IDENTITY_INVALID");
  }
  const intentSha256 = `sha256:${await sha256Hex(semanticRequestBytes)}`;
  const attemptId = await digestObject({
    intent_sha256: intentSha256,
    schema: ACTIVATION_OPERATION_ATTEMPT_SCHEMA,
    schema_version: 1,
    sequence: identity.sequence,
    worker_version_id: identity.workerVersionId,
  });
  if (intentSha256 !== identity.intentSha256 || attemptId !== identity.attemptId) {
    operationStoreFail("ACTIVATION_OPERATION_IDENTITY_INVALID");
  }
  return { ...identity, semanticRequestBytes };
}

export async function operationBytesDigest(bytes: Uint8Array): Promise<string> {
  return `sha256:${await sha256Hex(bytes)}`;
}

export function boundedOperationSnapshot(bytes: Uint8Array, maximum: number): Uint8Array {
  return ownExactUint8Array(bytes, {
    code: "ACTIVATION_OPERATION_SLOT_SIZE_INVALID",
    invalidStatus: 413,
    maximum,
    minimum: 1,
    sizeStatus: 413,
  });
}

export function assertStoredOperationBytes(
  stored: ArrayBuffer | null,
  storedDigest: string | null,
  expected: Uint8Array,
  expectedDigest: string,
): void {
  if (
    stored === null ||
    storedDigest === null ||
    !timingSafeEqual(storedDigest, expectedDigest) ||
    !operationBytesEqual(new Uint8Array(stored), expected)
  ) {
    operationStoreFail("ACTIVATION_OPERATION_SLOT_RESULT_CONFLICT");
  }
}

export function canonicalOperationTimestamp(milliseconds: number): string {
  if (!Number.isSafeInteger(milliseconds)) operationStoreFail("ACTIVATION_OPERATION_TIME_INVALID");
  try {
    return new Date(milliseconds).toISOString();
  } catch {
    operationStoreFail("ACTIVATION_OPERATION_TIME_INVALID");
  }
}

export function requireCanonicalOperationTimestamp(value: string): void {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    operationStoreFail("ACTIVATION_OPERATION_TIME_INVALID");
  }
}

export function requireOperationIssuance(
  value: ActivationOperationIssuanceRow | undefined,
): ActivationOperationIssuanceRow {
  if (value === undefined) operationStoreFail("ACTIVATION_OPERATION_ISSUANCE_MISSING", 500);
  return value;
}

export function requireOperationStoreSlot(
  value: ActivationOperationSlotRow | undefined,
): ActivationOperationSlotRow {
  if (value === undefined) operationStoreFail("ACTIVATION_OPERATION_SLOT_MISSING", 500);
  return value;
}

export function operationStoreFail(code: string, status = 409): never {
  throw new BrokerError(code, status, false);
}

export function operationBytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}
