import { BrokerError } from "./errors";
import type { JsonObject, JsonValue } from "./types";

const MAX_DEPTH = 32;
const MAX_NODES = 100_000;
const MAX_MAPPING_ENTRIES = 1_024;
const MAX_SEQUENCE_ITEMS = 4_096;
const MAX_KEY_BYTES = 128;
const MAX_STRING_BYTES = 1_048_576;
const MAX_CANONICAL_BYTES = 16_777_216;

/**
 * Canonical JSON for the exact bounded Python/TypeScript identity domain.
 *
 * The domain is stricter than RFC 8785: numbers must be JavaScript-safe
 * integers. This removes Python/JavaScript floating-point serialization
 * differences. Non-empty ASCII keys make Python and JavaScript sorting
 * byte-identical without relying on their different Unicode ordering rules.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("CANONICAL_JSON_ROOT_INVALID", 400, false);
  }
  const budget = { remaining: MAX_NODES };
  const encoded = encodeCanonical(value as JsonObject, 0, budget);
  if (new TextEncoder().encode(encoded).byteLength > MAX_CANONICAL_BYTES) {
    throw new BrokerError("CANONICAL_JSON_TOO_LARGE", 400, false);
  }
  return encoded;
}

export function canonicalBytes(value: JsonObject): Uint8Array {
  return new TextEncoder().encode(canonicalJson(value));
}

/** SHA-256 through the Workers WebCrypto implementation, never custom crypto. */
export async function sha256Hex(value: Uint8Array | string): Promise<string> {
  const input = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", Uint8Array.from(input).buffer);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function digestObject(value: JsonObject): Promise<string> {
  return `sha256:${await sha256Hex(canonicalBytes(value))}`;
}

export function timingSafeEqual(left: string, right: string): boolean {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  let difference = leftBytes.length ^ rightBytes.length;
  const length = Math.max(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }
  return difference === 0;
}

function encodeCanonical(value: JsonValue, depth: number, budget: { remaining: number }): string {
  if (depth > MAX_DEPTH) {
    throw new BrokerError("CANONICAL_JSON_TOO_DEEP", 400, false);
  }
  budget.remaining -= 1;
  if (budget.remaining < 0) {
    throw new BrokerError("CANONICAL_JSON_TOO_COMPLEX", 400, false);
  }
  if (value === null || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    if (
      new TextEncoder().encode(value).byteLength > MAX_STRING_BYTES ||
      !hasOnlyUnicodeScalars(value)
    ) {
      throw new BrokerError("CANONICAL_JSON_STRING_INVALID", 400, false);
    }
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new BrokerError("CANONICAL_JSON_NUMBER_INVALID", 400, false);
    }
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_SEQUENCE_ITEMS) {
      throw new BrokerError("CANONICAL_JSON_ARRAY_TOO_LARGE", 400, false);
    }
    return `[${value.map((item) => encodeCanonical(item, depth + 1, budget)).join(",")}]`;
  }
  if (typeof value !== "object") {
    throw new BrokerError("CANONICAL_JSON_TYPE_INVALID", 400, false);
  }
  const keys = Object.keys(value).sort();
  if (keys.length > MAX_MAPPING_ENTRIES) {
    throw new BrokerError("CANONICAL_JSON_OBJECT_TOO_LARGE", 400, false);
  }
  for (const key of keys) {
    if (!isBoundedAscii(key, MAX_KEY_BYTES)) {
      throw new BrokerError("CANONICAL_JSON_KEY_INVALID", 400, false);
    }
  }
  return `{${keys
    .map(
      (key) =>
        `${JSON.stringify(key)}:${encodeCanonical(value[key] as JsonValue, depth + 1, budget)}`,
    )
    .join(",")}}`;
}

export function isBoundedAscii(value: string, maximumLength: number): boolean {
  if (value.length === 0 || value.length > maximumLength) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (value.charCodeAt(index) > 0x7f) return false;
  }
  return true;
}

function hasOnlyUnicodeScalars(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const following = value.charCodeAt(index + 1);
      if (!(following >= 0xdc00 && following <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}
