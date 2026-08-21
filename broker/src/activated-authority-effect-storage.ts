import { BrokerError } from "./errors";
import type { JsonObject } from "./types";

export const AUTHORITY_EFFECT_SELECT = `SELECT reservation_id, canonical_bytes, head_generation,
  head_record_id, head_record_sha256, operation, intent_sha256, request_id,
  created_at, expires_at, status, result_bytes, result_sha256
  FROM authority_effect_reservations`;

export function ensureAuthorityEffectSchema(sql: SqlStorage): void {
  sql.exec(`
    CREATE TABLE IF NOT EXISTS authority_effect_reservations (
      reservation_id TEXT PRIMARY KEY,
      canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 65536),
      head_generation INTEGER NOT NULL,
      head_record_id TEXT NOT NULL,
      head_record_sha256 TEXT NOT NULL,
      operation TEXT NOT NULL CHECK(operation = 'ACTIVATION_PROOF'),
      intent_sha256 TEXT NOT NULL UNIQUE,
      request_id TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN (
        'RESERVED','SEALED','DISPATCHED_HOLD','CONFIRMED','EXPIRED_UNDISPATCHED','CANCELLED_UNDISPATCHED'
      )),
      result_bytes BLOB CHECK(result_bytes IS NULL OR length(result_bytes) BETWEEN 1 AND 65536),
      result_sha256 TEXT,
      CHECK (
        ((status IN ('SEALED','DISPATCHED_HOLD','CONFIRMED')) AND result_bytes IS NOT NULL AND result_sha256 IS NOT NULL)
        OR
        ((status IN ('RESERVED','EXPIRED_UNDISPATCHED','CANCELLED_UNDISPATCHED')) AND result_bytes IS NULL AND result_sha256 IS NULL)
      )
    ) STRICT;
  `);
}

export function decodeEffectBytes(bytes: ArrayBuffer): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

export function decodeNullableEffectBytes(bytes: ArrayBuffer | null): string | undefined {
  return bytes === null ? undefined : decodeEffectBytes(bytes);
}

export function requiredEffectObject(value: JsonObject, key: string): JsonObject {
  const candidate = value[key];
  if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
    throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RESERVATION_INVALID", 409, false);
  }
  return candidate;
}

export function requiredEffectString(value: JsonObject, key: string): string {
  const candidate = value[key];
  if (typeof candidate !== "string") {
    throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RESERVATION_INVALID", 409, false);
  }
  return candidate;
}

export function requiredEffectNumber(value: JsonObject, key: string): number {
  const candidate = value[key];
  if (!Number.isSafeInteger(candidate)) {
    throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RESERVATION_INVALID", 409, false);
  }
  return candidate as number;
}
