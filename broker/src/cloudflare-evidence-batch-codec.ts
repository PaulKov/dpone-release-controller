import { BrokerError } from "./errors";
import type { JsonObject, JsonValue } from "./types";
import { requireInteger, requireString } from "./validation";

export const BATCH_DIGEST = /^sha256:[0-9a-f]{64}$/u;
export const BATCH_UUID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;
export const BATCH_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
export const B2_OBSERVER_IDENTITY =
  /^cloudflare-worker:[0-9a-f]{32}\/dpone-release-worm-version-observer@[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;
export const WORM_IDENTITY =
  /^cloudflare-worker:[0-9a-f]{32}\/dpone-release-worm-mirror@[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;
export const BATCH_RETENTION_MILLISECONDS = 2557 * 86_400_000;

export function requireBatchObject(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    batchFail("BATCH_OBJECT_INVALID");
  }
  return value as JsonObject;
}

export function requireBatchObjectArray(
  value: JsonValue | undefined,
  length: number,
): JsonObject[] {
  if (!Array.isArray(value) || value.length !== length) batchFail("BATCH_ARRAY_INVALID");
  return value.map(requireBatchObject);
}

export function canonicalBatchTimestamp(value: string): string {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    batchFail("BATCH_TIME_INVALID");
  }
  return value;
}

export function requireBatchLiteral(value: JsonObject, key: string, expected: string): void {
  if (requireString(value, key, expected.length) !== expected) batchFail("BATCH_SCHEMA_INVALID");
}

export function requireBatchInteger(value: JsonObject, key: string, expected: number): void {
  if (requireInteger(value, key, expected, expected) !== expected) {
    batchFail("BATCH_SCHEMA_INVALID");
  }
}

export function batchFail(suffix: string): never {
  throw new BrokerError(`CLOUDFLARE_EVIDENCE_${suffix}`, 503, false);
}
