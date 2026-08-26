import { canonicalBytes, canonicalJson } from "./canonical";
import {
  ACTIVATION_RECORD_V2_LIMITS,
  type ActivationRecordV2Budget,
} from "./activation-record-v2-contract";
import { BrokerError } from "./errors";
import { ownExactUint8Array } from "./exact-uint8array";
import { parseStrictJsonObject } from "./strict-json";
import type { JsonObject, JsonValue } from "./types";

export const ACTIVATION_RECORD_V2_DIGEST = /^sha256:[0-9a-f]{64}$/u;
export const ACTIVATION_RECORD_V2_UUID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;
export const ACTIVATION_RECORD_V2_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
export const ACTIVATION_RECORD_V2_VERSION = /^[A-Za-z0-9._=-]{1,512}$/u;

const INVALID = "ACTIVATION_RECORD_V2_INVALID";
/** Decode canonical bytes only after enforcing the outer byte cap and owning the input. */
export function decodeActivationRecordV2Bytes(input: Uint8Array): {
  readonly budget: ActivationRecordV2Budget;
  readonly bytes: Uint8Array;
  readonly document: JsonObject;
} {
  const bytes = ownedBoundedBytes(input);
  const document = parseStrictJsonObject(
    bytes,
    INVALID,
    ACTIVATION_RECORD_V2_LIMITS.depth,
    ACTIVATION_RECORD_V2_LIMITS.nodes,
  );
  const budget = activationRecordV2Budget(document);
  const text = decodeUtf8(bytes);
  if (budget.bytes !== bytes.byteLength || canonicalJson(document) !== text) {
    recordV2Fail("ACTIVATION_RECORD_V2_NONCANONICAL");
  }
  return { budget, bytes, document };
}

/** Snapshot one builder input without retaining references to caller-owned objects. */
export function snapshotActivationRecordV2Data(input: JsonObject): JsonObject {
  const budget = activationRecordV2Budget(input);
  if (budget.bytes < 1 || budget.bytes > ACTIVATION_RECORD_V2_LIMITS.bytes) {
    recordV2Fail("ACTIVATION_RECORD_V2_SIZE_INVALID", 413);
  }
  return decodeActivationRecordV2Bytes(canonicalBytes(input)).document;
}

/** Iterative exact canonical budget used by both parsers and build-time fixtures. */
export function activationRecordV2Budget(root: JsonValue): ActivationRecordV2Budget {
  const pending: { readonly depth: number; readonly value: unknown }[] = [
    { depth: 0, value: root },
  ];
  let bytes = 0;
  let depth = 0;
  let maxKeyBytes = 0;
  let maxStringBytes = 0;
  let nodes = 0;
  try {
    while (pending.length > 0) {
      const current = pending.pop();
      if (current === undefined) recordV2Fail(INVALID, 500);
      nodes += 1;
      depth = Math.max(depth, current.depth);
      assertBudget(bytes, depth, maxKeyBytes, maxStringBytes, nodes);
      const value = current.value;
      if (value === null || typeof value === "boolean" || typeof value === "number") {
        bytes += scalarBytes(value);
      } else if (typeof value === "string") {
        const length = utf8Bytes(value);
        maxStringBytes = Math.max(maxStringBytes, length);
        bytes += scalarBytes(value);
      } else if (Array.isArray(value)) {
        if (Object.getPrototypeOf(value) !== Array.prototype) recordV2Fail(INVALID);
        const descriptors = Object.getOwnPropertyDescriptors(value);
        const length = arrayLength(
          Reflect.getOwnPropertyDescriptor(value, "length"),
          Reflect.ownKeys(value),
        );
        bytes += 2 + Math.max(0, length - 1);
        assertChildren(current.depth, length, nodes, pending.length);
        for (let index = length - 1; index >= 0; index -= 1) {
          const child: unknown = descriptors[String(index)]?.value;
          if (child === undefined) recordV2Fail(INVALID);
          pending.push({ depth: current.depth + 1, value: child });
        }
      } else if (typeof value === "object") {
        if (Object.getPrototypeOf(value) !== Object.prototype) recordV2Fail(INVALID);
        const descriptors = Object.getOwnPropertyDescriptors(value);
        const keys = Object.keys(value);
        if (
          Reflect.ownKeys(value).length !== keys.length ||
          keys.some(
            (key) => descriptors[key]?.get !== undefined || descriptors[key]?.set !== undefined,
          )
        ) {
          recordV2Fail(INVALID);
        }
        bytes += 2 + Math.max(0, keys.length - 1);
        assertChildren(current.depth, keys.length, nodes, pending.length);
        for (let index = keys.length - 1; index >= 0; index -= 1) {
          const key = keys[index];
          if (key === undefined) recordV2Fail(INVALID, 500);
          const keyBytes = utf8Bytes(key);
          maxKeyBytes = Math.max(maxKeyBytes, keyBytes);
          bytes += scalarBytes(key) + 1;
          const child: unknown = descriptors[key]?.value;
          if (child === undefined) recordV2Fail(INVALID);
          pending.push({ depth: current.depth + 1, value: child });
        }
      } else {
        recordV2Fail(INVALID);
      }
      assertBudget(bytes, depth, maxKeyBytes, maxStringBytes, nodes);
    }
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    recordV2Fail(INVALID);
  }
  return { bytes, depth, maxKeyBytes, maxStringBytes, nodes };
}

export function exactRecordV2Object(value: unknown, fields: readonly string[]): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) recordV2Fail(INVALID);
  const object = value as JsonObject;
  const actual = Object.keys(object).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    recordV2Fail(INVALID);
  }
  return object;
}

export function exactRecordV2Array(value: unknown, length: number): readonly unknown[] {
  if (!Array.isArray(value) || value.length !== length) recordV2Fail(INVALID);
  const items: readonly unknown[] = value;
  return items;
}

export function recordV2String(
  object: JsonObject,
  key: string,
  pattern?: RegExp,
  maximumBytes: number = ACTIVATION_RECORD_V2_LIMITS.stringBytes,
): string {
  const value = object[key];
  if (
    typeof value !== "string" ||
    utf8Bytes(value) > maximumBytes ||
    (pattern !== undefined && !fullMatch(pattern, value))
  ) {
    recordV2Fail(INVALID);
  }
  return value;
}

export function recordV2Digest(object: JsonObject, key: string): string {
  return recordV2String(object, key, ACTIVATION_RECORD_V2_DIGEST, 71);
}

export function recordV2Timestamp(object: JsonObject, key: string): string {
  const value = recordV2String(object, key, ACTIVATION_RECORD_V2_TIMESTAMP, 24);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    recordV2Fail(INVALID);
  }
  return value;
}

export function recordV2Integer(
  object: JsonObject,
  key: string,
  minimum: number,
  maximum: number,
): number {
  const value = object[key];
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    recordV2Fail(INVALID);
  }
  return Number(value);
}

export function recordV2Literal(object: JsonObject, key: string, expected: string | number): void {
  if (object[key] !== expected) recordV2Fail(INVALID);
}

export function freezeRecordV2Json<T extends JsonValue>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const child of Array.isArray(value) ? value : Object.values(value)) {
      freezeRecordV2Json(child);
    }
    Object.freeze(value);
  }
  return value;
}

export function recordV2Fail(code = INVALID, status = 409): never {
  throw new BrokerError(code, status, false);
}

function ownedBoundedBytes(input: Uint8Array): Uint8Array {
  return ownExactUint8Array(input, {
    code: "ACTIVATION_RECORD_V2_SIZE_INVALID",
    invalidStatus: 413,
    maximum: ACTIVATION_RECORD_V2_LIMITS.bytes,
    minimum: 1,
    sizeStatus: 413,
  });
}

function arrayLength(
  lengthDescriptor: PropertyDescriptor | undefined,
  ownKeys: readonly PropertyKey[],
): number {
  const length: unknown = lengthDescriptor?.value;
  if (
    !Number.isSafeInteger(length) ||
    Number(length) < 0 ||
    ownKeys.length !== Number(length) + 1 ||
    ownKeys.some(
      (key) =>
        typeof key !== "string" ||
        (key !== "length" && !isCanonicalArrayIndex(key, Number(length))),
    )
  ) {
    recordV2Fail(INVALID);
  }
  return Number(length);
}

function isCanonicalArrayIndex(key: string, length: number): boolean {
  if (!/^(?:0|[1-9][0-9]*)$/u.test(key)) return false;
  const index = Number(key);
  return Number.isSafeInteger(index) && index >= 0 && index < length && String(index) === key;
}

function assertChildren(
  parentDepth: number,
  children: number,
  visited: number,
  pending: number,
): void {
  if (
    children > 0 &&
    (parentDepth + 1 > ACTIVATION_RECORD_V2_LIMITS.depth ||
      visited + pending + children > ACTIVATION_RECORD_V2_LIMITS.nodes)
  ) {
    recordV2Fail("ACTIVATION_RECORD_V2_BUDGET_EXCEEDED", 413);
  }
}

function assertBudget(
  bytes: number,
  depth: number,
  maxKeyBytes: number,
  maxStringBytes: number,
  nodes: number,
): void {
  if (
    bytes > ACTIVATION_RECORD_V2_LIMITS.bytes ||
    depth > ACTIVATION_RECORD_V2_LIMITS.depth ||
    maxKeyBytes > ACTIVATION_RECORD_V2_LIMITS.keyBytes ||
    maxStringBytes > ACTIVATION_RECORD_V2_LIMITS.stringBytes ||
    nodes > ACTIVATION_RECORD_V2_LIMITS.nodes
  ) {
    recordV2Fail("ACTIVATION_RECORD_V2_BUDGET_EXCEEDED", 413);
  }
}

function scalarBytes(value: string | number | boolean | null): number {
  if (typeof value === "number" && !Number.isSafeInteger(value)) recordV2Fail(INVALID);
  return utf8Bytes(JSON.stringify(Object.is(value, -0) ? 0 : value));
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function fullMatch(pattern: RegExp, value: string): boolean {
  pattern.lastIndex = 0;
  return pattern.exec(value)?.[0] === value;
}

function decodeUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    recordV2Fail(INVALID);
  }
}
