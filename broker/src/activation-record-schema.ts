export const ACTIVATION_RECORD_SCHEMA_TABLES = Object.freeze(["activation_records"]);
export const ACTIVATION_RECORD_SCHEMA_V2_TRIGGERS = Object.freeze([
  "activation_record_core_immutable_v2",
  "activation_record_delete_forbidden_v2",
  "activation_record_operation_binding_insert_v2",
]);

/** Create the append-only activation record table for the current storage version. */
export function initializeActivationRecordSchema(sql: SqlStorage): void {
  initializeActivationRecordSchemaProfile(sql, false);
}

/** Create compact-v2 records that must be owned by a durable operation issuance. */
export function initializeActivationRecordSchemaV2(sql: SqlStorage): void {
  initializeActivationRecordSchemaProfile(sql, true);
}

function initializeActivationRecordSchemaProfile(
  sql: SqlStorage,
  operationIssuanceRequired: boolean,
): void {
  const issuanceNullability = operationIssuanceRequired ? "NOT NULL " : "";
  sql.exec(`
    CREATE TABLE IF NOT EXISTS activation_records (
      sequence INTEGER PRIMARY KEY CHECK(sequence IN (0, 1)),
      operation_issuance_id TEXT ${issuanceNullability}UNIQUE,
      request_digest TEXT NOT NULL UNIQUE,
      record_id TEXT NOT NULL UNIQUE,
      record_digest TEXT NOT NULL UNIQUE,
      canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 65536),
      committed_at TEXT NOT NULL,
      worm_key TEXT,
      worm_version_id TEXT,
      worm_retention_until TEXT,
      FOREIGN KEY(operation_issuance_id) REFERENCES activation_operation_issuances(issuance_id),
      CHECK (
        (worm_key IS NULL AND worm_version_id IS NULL AND worm_retention_until IS NULL)
        OR
        (worm_key IS NOT NULL AND worm_version_id IS NOT NULL AND worm_retention_until IS NOT NULL)
      )
    ) STRICT
  `);
  if (operationIssuanceRequired) initializeActivationRecordSchemaV2Guards(sql);
}

function initializeActivationRecordSchemaV2Guards(sql: SqlStorage): void {
  sql.exec(`
    CREATE TRIGGER activation_record_operation_binding_insert_v2
      BEFORE INSERT ON activation_records
      WHEN NOT EXISTS (
        SELECT 1 FROM activation_operation_issuances AS issuance
        JOIN activation_operation_intents AS intent ON intent.attempt_id = issuance.attempt_id
        WHERE issuance.issuance_id = NEW.operation_issuance_id
          AND intent.state = 'OPEN'
          AND issuance.state = 'READY_TO_APPEND'
          AND issuance.ordinal = (
            SELECT MAX(current.ordinal) FROM activation_operation_issuances AS current
            WHERE current.attempt_id = issuance.attempt_id
          )
          AND intent.sequence = NEW.sequence
          AND intent.intent_sha256 = NEW.request_digest
          AND issuance.record_committed_at IS NOT NULL
          AND issuance.record_committed_at = NEW.committed_at
      )
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_RECORD_OPERATION_BINDING_INVALID');
      END;
    CREATE TRIGGER activation_record_core_immutable_v2
      BEFORE UPDATE OF sequence, operation_issuance_id, request_digest,
        record_id, record_digest, canonical_bytes, committed_at
      ON activation_records
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_RECORD_CORE_IMMUTABLE');
      END;
    CREATE TRIGGER activation_record_delete_forbidden_v2
      BEFORE DELETE ON activation_records
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_RECORD_DELETE_FORBIDDEN');
      END;
  `);
}
