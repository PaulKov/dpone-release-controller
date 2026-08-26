import { PUBLIC_V2_MAX_BYTES } from "./bytes";
import { CandidatePublicV2Error, candidateAssert } from "./error";
import type { CandidateJsonObject } from "./types";

export { PUBLIC_V2_MAX_BYTES };

const MAX_DEPTH = 32;
const MAX_NODES = 100_000;
const MAX_MAPPING_ENTRIES = 1_024;
const MAX_SEQUENCE_ITEMS = 4_096;
const MAX_KEY_BYTES = 128;
const MAX_STRING_BYTES = 1_048_576;

interface EncodingBudget {
  bytes: number;
  nodes: number;
}

/**
 * Encode the strict, data-only, cross-language public-v2 JSON subset.
 * Every fragment is charged before append against the public byte ceiling.
 */
export function canonicalPublicV2(value: unknown): string {
  try {
    assertPlainObject(value, "PUBLIC_V2_CANONICAL_ROOT_INVALID");
    const budget: EncodingBudget = { bytes: 0, nodes: MAX_NODES };
    const encoded = encodeValue(value, 0, budget);
    candidateAssert(budget.bytes >= 1, "PUBLIC_V2_CANONICAL_SIZE_INVALID");
    return encoded;
  } catch (error) {
    if (error instanceof CandidatePublicV2Error) throw error;
    throw new CandidatePublicV2Error("PUBLIC_V2_CANONICAL_OBJECT_INVALID");
  }
}

export function canonicalPublicV2Bytes(value: unknown): Uint8Array {
  const bytes = new TextEncoder().encode(canonicalPublicV2(value));
  candidateAssert(bytes.byteLength <= PUBLIC_V2_MAX_BYTES, "PUBLIC_V2_CANONICAL_SIZE_INVALID");
  return bytes;
}

/** Produce a detached, plain-data snapshot through the strict byte parser. */
export function canonicalPublicV2Snapshot(value: unknown): CandidateJsonObject {
  return parseCanonicalPublicV2(canonicalPublicV2Bytes(value));
}

/** Parse only strict UTF-8 bytes that are already the one canonical form. */
export function parseCanonicalPublicV2(bytes: Uint8Array): CandidateJsonObject {
  assertBoundedRaw(bytes);
  candidateAssert(
    !(bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf),
    "PUBLIC_V2_BOM_INVALID",
  );
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new CandidatePublicV2Error("PUBLIC_V2_UTF8_INVALID");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new CandidatePublicV2Error("PUBLIC_V2_JSON_INVALID");
  }
  assertPlainObject(parsed, "PUBLIC_V2_CANONICAL_ROOT_INVALID");
  candidateAssert(equalBytes(canonicalPublicV2Bytes(parsed), bytes), "PUBLIC_V2_NOT_CANONICAL");
  return parsed;
}

function encodeValue(value: unknown, depth: number, budget: EncodingBudget): string {
  candidateAssert(depth <= MAX_DEPTH, "PUBLIC_V2_CANONICAL_TOO_DEEP");
  budget.nodes -= 1;
  candidateAssert(budget.nodes >= 0, "PUBLIC_V2_CANONICAL_TOO_COMPLEX");
  if (value === null) return appendAscii("null", budget);
  if (typeof value === "boolean") return appendAscii(value ? "true" : "false", budget);
  if (typeof value === "string") return encodeString(value, budget);
  if (typeof value === "number") {
    candidateAssert(Number.isSafeInteger(value), "PUBLIC_V2_CANONICAL_NUMBER_INVALID");
    return appendAscii(Object.is(value, -0) ? "0" : String(value), budget);
  }
  if (Array.isArray(value)) return encodeArray(value, depth, budget);
  assertPlainObject(value, "PUBLIC_V2_CANONICAL_TYPE_INVALID");
  return encodeObject(value, depth, budget);
}

function encodeArray(value: unknown[], depth: number, budget: EncodingBudget): string {
  assertDenseDataArray(value);
  const parts = [appendAscii("[", budget)];
  for (let index = 0; index < value.length; index += 1) {
    if (index > 0) parts.push(appendAscii(",", budget));
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    candidateAssert(descriptor !== undefined && "value" in descriptor, "PUBLIC_V2_ARRAY_INVALID");
    parts.push(encodeValue(descriptor.value, depth + 1, budget));
  }
  parts.push(appendAscii("]", budget));
  return parts.join("");
}

function encodeObject(value: CandidateJsonObject, depth: number, budget: EncodingBudget): string {
  const keys = Object.keys(value);
  candidateAssert(keys.length <= MAX_MAPPING_ENTRIES, "PUBLIC_V2_CANONICAL_OBJECT_TOO_LARGE");
  keys.sort(asciiCompare);
  const parts = [appendAscii("{", budget)];
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    candidateAssert(key !== undefined, "PUBLIC_V2_CANONICAL_KEY_INVALID");
    assertAsciiKey(key);
    if (index > 0) parts.push(appendAscii(",", budget));
    parts.push(encodeString(key, budget), appendAscii(":", budget));
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    candidateAssert(descriptor !== undefined && "value" in descriptor, "PUBLIC_V2_OBJECT_INVALID");
    parts.push(encodeValue(descriptor.value, depth + 1, budget));
  }
  parts.push(appendAscii("}", budget));
  return parts.join("");
}

/** Exact escaping: no solidus/non-ASCII/U+2028/U+2029 escaping. */
function encodeString(value: string, budget: EncodingBudget): string {
  let rawBytes = 0;
  const parts = [appendAscii('"', budget)];
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = value.charCodeAt(index + 1);
      candidateAssert(low >= 0xdc00 && low <= 0xdfff, "PUBLIC_V2_CANONICAL_SURROGATE_INVALID");
      rawBytes += 4;
      charge(4, budget);
      parts.push(`${value[index] ?? ""}${value[index + 1] ?? ""}`);
      index += 1;
    } else {
      candidateAssert(unit < 0xdc00 || unit > 0xdfff, "PUBLIC_V2_CANONICAL_SURROGATE_INVALID");
      const escaped = escapedCodeUnit(unit);
      const rawUnitBytes = utf8UnitBytes(unit);
      rawBytes += rawUnitBytes;
      if (escaped === null) {
        charge(rawUnitBytes, budget);
        parts.push(value[index] ?? "");
      } else {
        parts.push(appendAscii(escaped, budget));
      }
    }
    candidateAssert(rawBytes <= MAX_STRING_BYTES, "PUBLIC_V2_CANONICAL_STRING_TOO_LARGE");
  }
  parts.push(appendAscii('"', budget));
  return parts.join("");
}

function escapedCodeUnit(unit: number): string | null {
  if (unit === 0x22) return '\\"';
  if (unit === 0x5c) return "\\\\";
  if (unit === 0x08) return "\\b";
  if (unit === 0x09) return "\\t";
  if (unit === 0x0a) return "\\n";
  if (unit === 0x0c) return "\\f";
  if (unit === 0x0d) return "\\r";
  return unit <= 0x1f ? `\\u00${unit.toString(16).padStart(2, "0")}` : null;
}

function assertPlainObject(value: unknown, code: string): asserts value is CandidateJsonObject {
  candidateAssert(value !== null && typeof value === "object" && !Array.isArray(value), code);
  const prototype = Object.getPrototypeOf(value) as unknown;
  candidateAssert(prototype === Object.prototype || prototype === null, code);
  const keys = Reflect.ownKeys(value);
  candidateAssert(keys.length <= MAX_MAPPING_ENTRIES, "PUBLIC_V2_CANONICAL_OBJECT_TOO_LARGE");
  candidateAssert(
    keys.every((key) => typeof key === "string"),
    "PUBLIC_V2_OBJECT_SYMBOL_INVALID",
  );
  for (const key of keys) {
    candidateAssert(typeof key === "string", "PUBLIC_V2_OBJECT_SYMBOL_INVALID");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    candidateAssert(
      descriptor !== undefined && "value" in descriptor && descriptor.enumerable === true,
      "PUBLIC_V2_OBJECT_DESCRIPTOR_INVALID",
    );
  }
}

function assertDenseDataArray(value: unknown[]): void {
  candidateAssert(Object.getPrototypeOf(value) === Array.prototype, "PUBLIC_V2_ARRAY_INVALID");
  candidateAssert(value.length <= MAX_SEQUENCE_ITEMS, "PUBLIC_V2_CANONICAL_ARRAY_TOO_LARGE");
  const ownKeys = Reflect.ownKeys(value);
  candidateAssert(ownKeys.length === value.length + 1, "PUBLIC_V2_ARRAY_INVALID");
  const length = Object.getOwnPropertyDescriptor(value, "length");
  candidateAssert(
    length !== undefined &&
      "value" in length &&
      length.value === value.length &&
      length.enumerable === false &&
      length.configurable === false,
    "PUBLIC_V2_ARRAY_INVALID",
  );
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    candidateAssert(
      descriptor !== undefined && "value" in descriptor && descriptor.enumerable === true,
      "PUBLIC_V2_ARRAY_INVALID",
    );
  }
}

function assertAsciiKey(key: string): void {
  candidateAssert(key.length > 0 && key.length <= MAX_KEY_BYTES, "PUBLIC_V2_CANONICAL_KEY_INVALID");
  for (let index = 0; index < key.length; index += 1) {
    candidateAssert(key.charCodeAt(index) <= 0x7f, "PUBLIC_V2_CANONICAL_KEY_INVALID");
  }
}

function appendAscii(value: string, budget: EncodingBudget): string {
  charge(value.length, budget);
  return value;
}

function charge(bytes: number, budget: EncodingBudget): void {
  candidateAssert(bytes >= 0, "PUBLIC_V2_CANONICAL_SIZE_INVALID");
  budget.bytes += bytes;
  candidateAssert(budget.bytes <= PUBLIC_V2_MAX_BYTES, "PUBLIC_V2_CANONICAL_SIZE_INVALID");
}

function utf8UnitBytes(unit: number): number {
  return unit <= 0x7f ? 1 : unit <= 0x7ff ? 2 : 3;
}

function assertBoundedRaw(bytes: Uint8Array): void {
  candidateAssert(
    bytes.byteLength >= 1 && bytes.byteLength <= PUBLIC_V2_MAX_BYTES,
    "PUBLIC_V2_RAW_SIZE_INVALID",
  );
}

function asciiCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}
