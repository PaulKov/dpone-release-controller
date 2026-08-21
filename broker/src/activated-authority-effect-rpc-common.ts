import { canonicalJson } from "./canonical";
import { LIMITS } from "./config";
import { assert, BrokerError } from "./errors";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export function decodeEffectCanonical(text: string): JsonObject {
  const size = new TextEncoder().encode(text).byteLength;
  if (size === 0 || size > LIMITS.bodyBytes) {
    throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RPC_SIZE_INVALID", 413, false);
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RPC_INVALID", 409, false);
  }
  const object = exactObject(value, Object.keys(value as JsonObject).sort());
  assert(text === canonicalJson(object), "ACTIVATED_AUTHORITY_EFFECT_RPC_NONCANONICAL", 409);
  return object;
}

export function canonicalEffectTimestamp(value: string): string {
  assert(
    new Date(Date.parse(value)).toISOString() === value,
    "ACTIVATED_AUTHORITY_EFFECT_RPC_INVALID",
    409,
  );
  return value;
}

export function requireEffectLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, expected.length) === expected,
    "ACTIVATED_AUTHORITY_EFFECT_RPC_INVALID",
    409,
  );
}

export function requireEffectExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "ACTIVATED_AUTHORITY_EFFECT_RPC_INVALID",
    409,
  );
}

export function requireEffectObject(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RESULT_INVALID", 503, false);
  }
  return value as JsonObject;
}
