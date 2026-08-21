import type { WormExactObjectEffectStatus } from "./worm-exact-object-effect-contract";

export interface WormExactObjectEffectRow extends Record<string, SqlStorageValue> {
  readonly absence_inventory_digest: string | null;
  readonly canonical_bytes: ArrayBuffer;
  readonly committed_at: string;
  readonly digest: string;
  readonly effect_id: string;
  readonly executor_service_identity: string;
  readonly executor_version_id: string;
  readonly hold_code: string | null;
  readonly object_key: string;
  readonly observer_service_identity: string;
  readonly observer_version_id: string;
  readonly singleton: number;
  readonly status: WormExactObjectEffectStatus;
  readonly worm_retention_until: string | null;
  readonly worm_version_id: string | null;
  readonly writer_version_id: string | null;
}

/** Install the singleton, exact-byte effect journal with database-level states. */
export function initializeWormExactObjectEffectSchema(sql: SqlStorage): void {
  sql.exec(`
    CREATE TABLE IF NOT EXISTS worm_exact_object_effect (
      singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
      effect_id TEXT NOT NULL UNIQUE CHECK(length(effect_id) = 71),
      canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 65536),
      committed_at TEXT NOT NULL CHECK(length(committed_at) = 24),
      digest TEXT NOT NULL CHECK(length(digest) = 71),
      object_key TEXT NOT NULL UNIQUE CHECK(length(object_key) BETWEEN 1 AND 512),
      executor_service_identity TEXT NOT NULL CHECK(length(executor_service_identity) BETWEEN 1 AND 512),
      executor_version_id TEXT NOT NULL CHECK(length(executor_version_id) = 36),
      observer_service_identity TEXT NOT NULL CHECK(length(observer_service_identity) BETWEEN 1 AND 512),
      observer_version_id TEXT NOT NULL CHECK(length(observer_version_id) = 36),
      status TEXT NOT NULL CHECK(status IN (
        'PREPARED','ABSENT','IN_FLIGHT','ACCEPTED','DISPATCHED_HOLD','CONFIRMED','HOLD'
      )),
      absence_inventory_digest TEXT CHECK(
        absence_inventory_digest IS NULL OR length(absence_inventory_digest) = 71
      ),
      writer_version_id TEXT CHECK(
        writer_version_id IS NULL OR length(writer_version_id) BETWEEN 1 AND 512
      ),
      worm_version_id TEXT CHECK(
        worm_version_id IS NULL OR length(worm_version_id) BETWEEN 1 AND 512
      ),
      worm_retention_until TEXT CHECK(
        worm_retention_until IS NULL OR length(worm_retention_until) = 24
      ),
      hold_code TEXT CHECK(hold_code IS NULL OR length(hold_code) BETWEEN 1 AND 128),
      CHECK(executor_service_identity != observer_service_identity),
      CHECK(
        (status = 'PREPARED'
          AND absence_inventory_digest IS NULL
          AND writer_version_id IS NULL
          AND worm_version_id IS NULL
          AND worm_retention_until IS NULL
          AND hold_code IS NULL)
        OR
        (status = 'ABSENT'
          AND absence_inventory_digest IS NOT NULL
          AND writer_version_id IS NULL
          AND worm_version_id IS NULL
          AND worm_retention_until IS NULL
          AND hold_code IS NULL)
        OR
        (status = 'IN_FLIGHT'
          AND absence_inventory_digest IS NOT NULL
          AND writer_version_id IS NULL
          AND worm_version_id IS NULL
          AND worm_retention_until IS NULL
          AND hold_code IS NULL)
        OR
        (status = 'ACCEPTED'
          AND absence_inventory_digest IS NOT NULL
          AND writer_version_id IS NOT NULL
          AND worm_version_id IS NULL
          AND worm_retention_until IS NULL
          AND hold_code IS NULL)
        OR
        (status = 'DISPATCHED_HOLD'
          AND absence_inventory_digest IS NOT NULL
          AND worm_version_id IS NULL
          AND worm_retention_until IS NULL
          AND hold_code IS NULL)
        OR
        (status = 'CONFIRMED'
          AND absence_inventory_digest IS NOT NULL
          AND worm_version_id IS NOT NULL
          AND worm_retention_until IS NOT NULL
          AND hold_code IS NULL)
        OR
        (status = 'HOLD'
          AND worm_version_id IS NULL
          AND worm_retention_until IS NULL
          AND hold_code IS NOT NULL)
      )
    ) STRICT;
  `);
}

export function copyStoredBytes(bytes: ArrayBuffer): Uint8Array {
  return Uint8Array.from(new Uint8Array(bytes));
}

export function equalStoredBytes(left: ArrayBuffer, right: Uint8Array): boolean {
  const stored = new Uint8Array(left);
  if (stored.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < stored.byteLength; index += 1) {
    difference |= (stored[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}
