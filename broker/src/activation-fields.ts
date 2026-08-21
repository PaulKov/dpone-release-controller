import { TIMESTAMP } from "./activation-contract";
import { isSha256 } from "./config";
import { assert } from "./errors";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export function nested(parent: JsonObject, key: string, fields: readonly string[]): JsonObject {
  return exactObject(parent[key], fields);
}

export function requireDigest(object: JsonObject, key: string): string {
  const value = requireString(object, key, 71);
  assert(isSha256(value), "ACTIVATION_DIGEST_INVALID");
  return value;
}

export function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, Math.max(1, expected.length)) === expected,
    "ACTIVATION_LITERAL_MISMATCH",
  );
}

export function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "ACTIVATION_INTEGER_MISMATCH",
  );
}

export function requireTimestamp(object: JsonObject, key: string): string {
  const value = requireString(object, key, 32, TIMESTAMP);
  const milliseconds = Date.parse(value);
  assert(
    Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value,
    "ACTIVATION_TIMESTAMP_INVALID",
  );
  return value;
}

export function stringArray(object: JsonObject, key: string): string[] {
  const value = object[key];
  assert(
    Array.isArray(value) &&
      value.length >= 1 &&
      value.length <= 32 &&
      value.every((item) => typeof item === "string"),
    "ACTIVATION_STRING_ARRAY_INVALID",
  );
  return value;
}

export function requireExactStringArray(
  object: JsonObject,
  key: string,
  expected: readonly string[],
): void {
  const value = object[key];
  assert(Array.isArray(value), "ACTIVATION_STRING_ARRAY_INVALID");
  assert(
    value.length === expected.length && value.every((item, index) => item === expected[index]),
    "ACTIVATION_STRING_ARRAY_MISMATCH",
  );
}

export function validateActorIds(values: readonly string[]): void {
  assert(values.length >= 1 && values.length <= 8, "ACTIVATION_ACTOR_ALLOWLIST_INVALID");
  let previous = "";
  for (const value of values) {
    assert(/^[1-9][0-9]{0,31}$/u.test(value), "ACTIVATION_ACTOR_ALLOWLIST_INVALID");
    assert(value > previous, "ACTIVATION_ACTOR_ALLOWLIST_ORDER_INVALID");
    previous = value;
  }
}
