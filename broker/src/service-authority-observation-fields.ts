import { assert } from "./errors";
import type { JsonObject } from "./types";
import { requireInteger, requireString } from "./validation";

export const SERVICE_AUTHORITY_DIGEST = /^sha256:[0-9a-f]{64}$/u;
export const SERVICE_AUTHORITY_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;

export function tagged(object: JsonObject, key: string): string {
  return requireString(object, key, 71, SERVICE_AUTHORITY_DIGEST);
}

export function timestamp(object: JsonObject, key: string): string {
  const value = requireString(object, key, 32, SERVICE_AUTHORITY_TIMESTAMP);
  assert(
    new Date(Date.parse(value)).toISOString() === value,
    "SERVICE_AUTHORITY_TIMESTAMP_INVALID",
    503,
  );
  return value;
}

export function literal(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, Math.max(1, expected.length)) === expected,
    "SERVICE_AUTHORITY_OBSERVATION_LITERAL_MISMATCH",
    503,
  );
}

export function exactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "SERVICE_AUTHORITY_OBSERVATION_INTEGER_MISMATCH",
    503,
  );
}
