/** Create the fixed sanitized-only journal schema for one 15-slot batch. */
export function initializeCloudflareEvidenceBatchSchema(sql: SqlStorage): void {
  sql.exec(`
    CREATE TABLE IF NOT EXISTS cloudflare_evidence_batch (
      singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
      batch_id TEXT NOT NULL UNIQUE,
      binding_schema_version INTEGER NOT NULL CHECK(binding_schema_version IN (1, 2)),
      activation_issuance_id TEXT,
      activation_issuance_ordinal INTEGER,
      activation_sequence INTEGER,
      b2_observer_service_identity TEXT NOT NULL,
      b2_observer_worker_version_id TEXT NOT NULL,
      cloudflare_observer_service_identity TEXT,
      delegation_sha256 TEXT,
      delegation_committed_at TEXT,
      delegation_issued_at TEXT,
      delegation_fresh_until TEXT,
      expectation_sha256 TEXT NOT NULL,
      observer_worker_version_id TEXT NOT NULL,
      phase TEXT NOT NULL CHECK(phase IN ('A0_PRE', 'A1_PRECOMMIT')),
      observed_at TEXT NOT NULL,
      committed_at TEXT NOT NULL,
      observation_canonical_bytes BLOB NOT NULL CHECK(length(observation_canonical_bytes) BETWEEN 1 AND 1048576),
      provider_observation_sha256 TEXT NOT NULL,
      seal_sha256 TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('SEALED', 'CONFIRMED', 'HOLD')),
      worm_service_identity TEXT NOT NULL,
      worm_worker_version_id TEXT NOT NULL,
      CHECK(
        (binding_schema_version = 1 AND activation_issuance_id IS NULL
          AND activation_issuance_ordinal IS NULL AND activation_sequence IS NULL
          AND cloudflare_observer_service_identity IS NULL AND delegation_sha256 IS NULL
          AND delegation_committed_at IS NULL AND delegation_issued_at IS NULL
          AND delegation_fresh_until IS NULL)
        OR
        (binding_schema_version = 2 AND activation_issuance_id IS NOT NULL
          AND activation_issuance_ordinal BETWEEN 1 AND 1000000
          AND activation_sequence IN (0, 1)
          AND cloudflare_observer_service_identity IS NOT NULL AND delegation_sha256 IS NOT NULL
          AND delegation_committed_at IS NOT NULL AND delegation_issued_at IS NOT NULL
          AND delegation_fresh_until IS NOT NULL)
      )
    ) STRICT;
    CREATE TABLE IF NOT EXISTS cloudflare_evidence_slots (
      slot_index INTEGER PRIMARY KEY CHECK(slot_index BETWEEN 0 AND 14),
      authority_role TEXT UNIQUE,
      kind TEXT NOT NULL CHECK(kind IN ('cloudflare_service_deployments', 'cloudflare_network_surface')),
      record_id TEXT NOT NULL UNIQUE,
      record_sha256 TEXT NOT NULL UNIQUE,
      expected_worm_key TEXT NOT NULL UNIQUE,
      canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 65536),
      committed_at TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('PREPARED', 'ABSENT', 'IN_FLIGHT', 'ACCEPTED', 'CONFIRMED', 'HOLD')),
      absence_inventory_sha256 TEXT,
      writer_version_id TEXT UNIQUE,
      worm_digest TEXT,
      worm_key TEXT UNIQUE,
      worm_version_id TEXT UNIQUE,
      worm_retention_until TEXT,
      CHECK(
        (worm_digest IS NULL AND worm_key IS NULL AND worm_version_id IS NULL AND worm_retention_until IS NULL)
        OR
        (worm_digest IS NOT NULL AND worm_key IS NOT NULL AND worm_version_id IS NOT NULL AND worm_retention_until IS NOT NULL)
      )
    ) STRICT;
  `);
}
