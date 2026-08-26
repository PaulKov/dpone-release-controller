import type { ActivationOperationIssuanceState } from "./activation-operation-contract";
import {
  ACTIVATION_OPERATION_SCHEMA_V2_TRIGGERS,
  initializeActivationOperationSchemaV2Guards,
} from "./activation-operation-schema-v2-guards";

export { ACTIVATION_OPERATION_SCHEMA_V2_TRIGGERS };

export const ACTIVATION_OPERATION_SCHEMA_TABLES = Object.freeze([
  "activation_operation_intents",
  "activation_operation_issuances",
  "activation_operation_slots",
  "activation_cloudflare_anchors",
]);
export const ACTIVATION_OPERATION_SCHEMA_INDEXES = Object.freeze([
  "activation_operation_one_live_issuance",
]);
type ActivationOperationSchemaProfile = "COMPACT_V2" | "LEGACY_V1";

export interface ActivationOperationIntentRow extends Record<string, SqlStorageValue> {
  readonly attempt_id: string;
  readonly created_at: string;
  readonly intent_sha256: string;
  readonly semantic_request_bytes: ArrayBuffer;
  readonly sequence: number;
  readonly state: string;
  readonly worker_version_id: string;
}

export interface ActivationOperationIssuanceRow extends Record<string, SqlStorageValue> {
  readonly attempt_id: string;
  readonly fresh_until: string;
  readonly internal_request_id: string;
  readonly issuance_id: string;
  readonly issued_at: string;
  readonly ordinal: number;
  readonly record_committed_at: string | null;
  readonly record_worm_result_bytes: ArrayBuffer | null;
  readonly record_worm_result_sha256: string | null;
  readonly state: ActivationOperationIssuanceState;
  readonly superseded_by_ordinal: number | null;
}

export interface ActivationOperationSlotRow extends Record<string, SqlStorageValue> {
  readonly batch_id: string | null;
  readonly b2_observer_service_identity: string | null;
  readonly b2_observer_worker_version_id: string | null;
  readonly cloudflare_observer_service_identity: string | null;
  readonly cloudflare_observer_worker_version_id: string | null;
  readonly committed_at: string | null;
  readonly effect_id: string | null;
  readonly executor_service_identity: string | null;
  readonly executor_worker_version_id: string | null;
  readonly expected_worm_key: string | null;
  readonly frozen_payload_bytes: ArrayBuffer | null;
  readonly frozen_payload_sha256: string | null;
  readonly issuance_id: string;
  readonly observed_at: string | null;
  readonly observer_service_identity: string | null;
  readonly observer_worker_version_id: string | null;
  readonly provider_request_bytes: ArrayBuffer | null;
  readonly provider_request_sha256: string | null;
  readonly result_bytes: ArrayBuffer | null;
  readonly result_sha256: string | null;
  readonly slot_id: string;
  readonly slot_index: number;
  readonly slot_kind: string;
  readonly state: string;
  readonly worm_digest: string | null;
  readonly worm_key: string | null;
  readonly worm_retention_until: string | null;
  readonly worm_version_id: string | null;
  readonly worm_service_identity: string | null;
  readonly worm_worker_version_id: string | null;
}

/** Initialize the version-local activation operation journal. */
export function initializeActivationOperationSchema(sql: SqlStorage): void {
  initializeActivationOperationSchemaProfile(sql, "LEGACY_V1");
}

/** Initialize compact-v2 operation storage without changing the legacy default. */
export function initializeActivationOperationSchemaV2(sql: SqlStorage): void {
  initializeActivationOperationSchemaProfile(sql, "COMPACT_V2");
}

function initializeActivationOperationSchemaProfile(
  sql: SqlStorage,
  profile: ActivationOperationSchemaProfile,
): void {
  const slotRosterConstraint =
    profile === "COMPACT_V2"
      ? `(slot_id = 'CONTROLLER_ACTION' AND slot_kind = 'DIRECT_WORM' AND slot_index = 0)
        OR (slot_id = 'CONTROLLER_OIDC' AND slot_kind = 'DIRECT_WORM' AND slot_index = 1)
        OR (slot_id = 'TARGET_OIDC' AND slot_kind = 'DIRECT_WORM' AND slot_index = 2)
        OR (slot_id = 'TARGET_RULESET' AND slot_kind = 'DIRECT_WORM' AND slot_index = 3)
        OR (slot_id = 'CLOUDFLARE_BATCH' AND slot_kind = 'CLOUDFLARE_BATCH'
            AND slot_index IN (0, 4))`
      : `(slot_id = 'CONTROLLER_ACTION' AND slot_kind = 'READ_ONLY' AND slot_index = 0)
        OR (slot_id = 'CONTROLLER_OIDC' AND slot_kind = 'DIRECT_WORM' AND slot_index = 1)
        OR (slot_id = 'TARGET_OIDC' AND slot_kind = 'DIRECT_WORM' AND slot_index = 2)
        OR (slot_id = 'TARGET_RULESET' AND slot_kind = 'DIRECT_WORM' AND slot_index = 3)
        OR (slot_id = 'CLOUDFLARE_BATCH' AND slot_kind = 'CLOUDFLARE_BATCH'
            AND slot_index IN (0, 4))`;
  sql.exec(`
    CREATE TABLE IF NOT EXISTS activation_operation_intents (
      sequence INTEGER PRIMARY KEY CHECK(sequence IN (0, 1)),
      attempt_id TEXT NOT NULL UNIQUE,
      intent_sha256 TEXT NOT NULL UNIQUE,
      semantic_request_bytes BLOB NOT NULL CHECK(length(semantic_request_bytes) BETWEEN 1 AND 65536),
      worker_version_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('OPEN', 'CONFIRMED', 'HOLD'))
    ) STRICT;

    CREATE TABLE IF NOT EXISTS activation_operation_issuances (
      attempt_id TEXT NOT NULL,
      ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 1 AND 1000000),
      issuance_id TEXT NOT NULL UNIQUE,
      internal_request_id TEXT NOT NULL UNIQUE,
      issued_at TEXT NOT NULL,
      fresh_until TEXT NOT NULL,
      record_committed_at TEXT,
      record_worm_result_bytes BLOB CHECK(length(record_worm_result_bytes) BETWEEN 1 AND 65536),
      record_worm_result_sha256 TEXT,
      state TEXT NOT NULL CHECK(state IN (
        'RESERVED', 'COLLECTING', 'FROZEN', 'EFFECTS_PENDING',
        'READY_TO_APPEND', 'RECORD_APPENDED', 'CONFIRMED',
        'EXPIRED_UNDISPATCHED', 'SUPERSEDED_STALE',
        'DISPATCHED_HOLD', 'HOLD'
      )),
      superseded_by_ordinal INTEGER,
      PRIMARY KEY(attempt_id, ordinal),
      FOREIGN KEY(attempt_id) REFERENCES activation_operation_intents(attempt_id),
      CHECK(
        (state = 'SUPERSEDED_STALE' AND superseded_by_ordinal IS NOT NULL)
        OR (state != 'SUPERSEDED_STALE' AND superseded_by_ordinal IS NULL)
      ),
      CHECK(
        (state IN ('READY_TO_APPEND', 'RECORD_APPENDED', 'CONFIRMED')
          AND record_committed_at IS NOT NULL)
        OR
        (state NOT IN ('READY_TO_APPEND', 'RECORD_APPENDED', 'CONFIRMED'))
      ),
      CHECK(
        (record_worm_result_bytes IS NULL AND record_worm_result_sha256 IS NULL)
        OR
        (record_worm_result_bytes IS NOT NULL AND record_worm_result_sha256 IS NOT NULL)
      ),
      CHECK(
        (state = 'CONFIRMED' AND record_worm_result_bytes IS NOT NULL)
        OR (state != 'CONFIRMED' AND record_worm_result_bytes IS NULL)
      )
    ) STRICT;
    CREATE UNIQUE INDEX IF NOT EXISTS activation_operation_one_live_issuance
      ON activation_operation_issuances(attempt_id)
      WHERE state NOT IN ('CONFIRMED', 'EXPIRED_UNDISPATCHED', 'SUPERSEDED_STALE');

    CREATE TABLE IF NOT EXISTS activation_operation_slots (
      issuance_id TEXT NOT NULL,
      slot_id TEXT NOT NULL CHECK(slot_id IN (
        'CONTROLLER_ACTION', 'CONTROLLER_OIDC', 'TARGET_OIDC',
        'TARGET_RULESET', 'CLOUDFLARE_BATCH'
      )),
      slot_kind TEXT NOT NULL CHECK(slot_kind IN ('READ_ONLY', 'DIRECT_WORM', 'CLOUDFLARE_BATCH')),
      slot_index INTEGER NOT NULL CHECK(slot_index BETWEEN 0 AND 4),
      state TEXT NOT NULL CHECK(state IN (
        'PREPARED', 'READ_IN_FLIGHT', 'FROZEN',
        'DELEGATED_IN_FLIGHT', 'CONFIRMED', 'DISPATCHED_HOLD', 'HOLD'
      )),
      provider_request_bytes BLOB CHECK(length(provider_request_bytes) BETWEEN 1 AND 65536),
      provider_request_sha256 TEXT,
      frozen_payload_bytes BLOB CHECK(length(frozen_payload_bytes) BETWEEN 1 AND 1048576),
      frozen_payload_sha256 TEXT,
      observed_at TEXT,
      committed_at TEXT,
      effect_id TEXT UNIQUE,
      batch_id TEXT UNIQUE,
      cloudflare_observer_service_identity TEXT,
      cloudflare_observer_worker_version_id TEXT,
      worm_service_identity TEXT,
      worm_worker_version_id TEXT,
      b2_observer_service_identity TEXT,
      b2_observer_worker_version_id TEXT,
      executor_service_identity TEXT,
      executor_worker_version_id TEXT,
      expected_worm_key TEXT UNIQUE,
      observer_service_identity TEXT,
      observer_worker_version_id TEXT,
      result_bytes BLOB CHECK(length(result_bytes) BETWEEN 1 AND 1048576),
      result_sha256 TEXT,
      worm_digest TEXT,
      worm_key TEXT UNIQUE,
      worm_version_id TEXT UNIQUE,
      worm_retention_until TEXT,
      PRIMARY KEY(issuance_id, slot_id),
      UNIQUE(issuance_id, slot_index),
      FOREIGN KEY(issuance_id) REFERENCES activation_operation_issuances(issuance_id),
      CHECK(
        ${slotRosterConstraint}
      ),
      CHECK(
        (provider_request_bytes IS NULL AND provider_request_sha256 IS NULL)
        OR (provider_request_bytes IS NOT NULL AND provider_request_sha256 IS NOT NULL)
      ),
      CHECK(
        (cloudflare_observer_service_identity IS NULL AND cloudflare_observer_worker_version_id IS NULL
         AND worm_service_identity IS NULL AND worm_worker_version_id IS NULL
         AND b2_observer_service_identity IS NULL AND b2_observer_worker_version_id IS NULL)
        OR
        (cloudflare_observer_service_identity IS NOT NULL AND cloudflare_observer_worker_version_id IS NOT NULL
         AND worm_service_identity IS NOT NULL AND worm_worker_version_id IS NOT NULL
         AND b2_observer_service_identity IS NOT NULL AND b2_observer_worker_version_id IS NOT NULL)
      ),
      CHECK(
        (frozen_payload_bytes IS NULL AND frozen_payload_sha256 IS NULL)
        OR (frozen_payload_bytes IS NOT NULL AND frozen_payload_sha256 IS NOT NULL)
      ),
      CHECK(slot_kind != 'DIRECT_WORM' OR length(frozen_payload_bytes) <= 65536),
      CHECK(
        (result_bytes IS NULL AND result_sha256 IS NULL)
        OR (result_bytes IS NOT NULL AND result_sha256 IS NOT NULL)
      ),
      CHECK(slot_kind != 'DIRECT_WORM' OR length(result_bytes) <= 65536),
      CHECK(
        (worm_digest IS NULL AND worm_key IS NULL AND worm_version_id IS NULL AND worm_retention_until IS NULL)
        OR
        (worm_digest IS NOT NULL AND worm_key IS NOT NULL AND worm_version_id IS NOT NULL AND worm_retention_until IS NOT NULL)
      ),
      CHECK(slot_kind != 'READ_ONLY' OR (
        effect_id IS NULL AND batch_id IS NULL AND worm_digest IS NULL
      )),
      CHECK(
        (executor_service_identity IS NULL AND executor_worker_version_id IS NULL
         AND observer_service_identity IS NULL AND observer_worker_version_id IS NULL)
        OR
        (executor_service_identity IS NOT NULL AND executor_worker_version_id IS NOT NULL
         AND observer_service_identity IS NOT NULL AND observer_worker_version_id IS NOT NULL)
      ),
      CHECK(slot_kind != 'DIRECT_WORM' OR batch_id IS NULL),
      CHECK(slot_kind != 'CLOUDFLARE_BATCH' OR (effect_id IS NULL AND expected_worm_key IS NULL)),
      CHECK(slot_kind != 'READ_ONLY' OR expected_worm_key IS NULL),
      CHECK(slot_kind != 'READ_ONLY' OR state IN ('PREPARED', 'READ_IN_FLIGHT', 'FROZEN')),
      CHECK(state != 'CONFIRMED' OR (
        result_bytes IS NOT NULL AND
        (slot_kind != 'DIRECT_WORM' OR worm_digest IS NOT NULL) AND
        (slot_kind != 'CLOUDFLARE_BATCH' OR batch_id IS NOT NULL)
      )),
      CHECK(
        (state = 'PREPARED' AND
          provider_request_bytes IS NULL AND frozen_payload_bytes IS NULL AND observed_at IS NULL AND
          committed_at IS NULL AND effect_id IS NULL AND batch_id IS NULL AND
          expected_worm_key IS NULL AND executor_service_identity IS NULL AND
          cloudflare_observer_service_identity IS NULL AND
          result_bytes IS NULL AND worm_digest IS NULL)
        OR
        (state = 'READ_IN_FLIGHT' AND
          provider_request_bytes IS NOT NULL AND frozen_payload_bytes IS NULL AND observed_at IS NULL AND
          committed_at IS NULL AND effect_id IS NULL AND batch_id IS NULL AND
          expected_worm_key IS NULL AND executor_service_identity IS NULL AND
          cloudflare_observer_service_identity IS NULL AND
          result_bytes IS NULL AND worm_digest IS NULL)
        OR
        (state = 'FROZEN' AND
          slot_kind != 'CLOUDFLARE_BATCH' AND
          provider_request_bytes IS NOT NULL AND frozen_payload_bytes IS NOT NULL AND observed_at IS NOT NULL AND
          committed_at IS NULL AND effect_id IS NULL AND batch_id IS NULL AND
          expected_worm_key IS NULL AND executor_service_identity IS NULL AND
          cloudflare_observer_service_identity IS NULL AND
          result_bytes IS NULL AND worm_digest IS NULL)
        OR
        (state IN ('DELEGATED_IN_FLIGHT', 'DISPATCHED_HOLD', 'HOLD') AND
          provider_request_bytes IS NOT NULL AND committed_at IS NOT NULL AND
          result_bytes IS NULL AND worm_digest IS NULL AND
          ((slot_kind = 'DIRECT_WORM' AND frozen_payload_bytes IS NOT NULL AND
            observed_at IS NOT NULL AND effect_id IS NOT NULL AND expected_worm_key IS NOT NULL AND
            batch_id IS NULL AND executor_service_identity IS NOT NULL AND
            cloudflare_observer_service_identity IS NULL)
           OR
           (slot_kind = 'CLOUDFLARE_BATCH' AND frozen_payload_bytes IS NULL AND
            observed_at IS NULL AND batch_id IS NOT NULL AND effect_id IS NULL AND
            expected_worm_key IS NULL AND executor_service_identity IS NULL AND
            cloudflare_observer_service_identity IS NOT NULL)))
        OR
        (state = 'CONFIRMED' AND
          provider_request_bytes IS NOT NULL AND committed_at IS NOT NULL AND
          result_bytes IS NOT NULL AND
          ((slot_kind = 'DIRECT_WORM' AND frozen_payload_bytes IS NOT NULL AND
            observed_at IS NOT NULL AND effect_id IS NOT NULL AND expected_worm_key IS NOT NULL AND
            batch_id IS NULL AND worm_digest IS NOT NULL AND executor_service_identity IS NOT NULL AND
            cloudflare_observer_service_identity IS NULL)
           OR
           (slot_kind = 'CLOUDFLARE_BATCH' AND frozen_payload_bytes IS NULL AND
            observed_at IS NULL AND batch_id IS NOT NULL AND effect_id IS NULL AND
            expected_worm_key IS NULL AND worm_digest IS NULL AND
            executor_service_identity IS NULL AND cloudflare_observer_service_identity IS NOT NULL)))
      )
    ) STRICT;

    CREATE TABLE IF NOT EXISTS activation_cloudflare_anchors (
      issuance_id TEXT NOT NULL,
      slot_index INTEGER NOT NULL CHECK(slot_index BETWEEN 0 AND 14),
      authority_role TEXT,
      record_id TEXT NOT NULL UNIQUE,
      record_sha256 TEXT NOT NULL UNIQUE,
      worm_key TEXT NOT NULL UNIQUE,
      worm_version_id TEXT NOT NULL UNIQUE,
      worm_retention_until TEXT NOT NULL,
      PRIMARY KEY(issuance_id, slot_index),
      FOREIGN KEY(issuance_id) REFERENCES activation_operation_issuances(issuance_id)
    ) STRICT;
  `);
  if (profile === "COMPACT_V2") initializeActivationOperationSchemaV2Guards(sql);
}
