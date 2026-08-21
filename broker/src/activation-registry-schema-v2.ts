import { initializeActivationComponentJournalSchemaInTransaction } from "./activation-component-journal-schema";
import { initializeActivationOperationSchemaV2 } from "./activation-operation-schema";
import expectedSchemaSnapshot from "./activation-registry-schema-v2-fingerprint.json";
import { initializeActivationRecordSchemaV2 } from "./activation-record-schema";
import { BrokerError } from "./errors";

export const ACTIVATION_REGISTRY_STORAGE_SCHEMA_VERSION_V2 = 2;
export const ACTIVATION_REGISTRY_COMPONENT_OPERATION_BINDING_TABLE =
  "activation_component_operation_binding_v2";

const REGISTRY_SCHEMA_TABLE = "activation_registry_storage_schema";

export type ActivationRegistrySchemaV2Checkpoint =
  | "BINDING_CREATED"
  | "JOURNAL_SELECTION_CREATED"
  | "JOURNAL_TOPOLOGY_CREATED"
  | "OPERATION_CREATED"
  | "RECORD_CREATED"
  | "REGISTRY_STAMPED";

interface SchemaObjectRow extends Record<string, SqlStorageValue> {
  readonly name: string;
  readonly sql: string;
  readonly type: string;
}

interface RegistryStampRow extends Record<string, SqlStorageValue> {
  readonly singleton: number;
  readonly version: number;
  readonly worker_version_id: string;
}

const EXPECTED_SCHEMA_OBJECTS: readonly SchemaObjectRow[] = Object.freeze(
  expectedSchemaSnapshot.map((row) => Object.freeze({ ...row })),
);

/**
 * Atomically bootstrap the complete compact-v2 ActivationRegistry topology.
 *
 * Only a storage instance with no application-owned schema objects is eligible
 * for creation. Any legacy, partial, unknown, or conflicting layout is left
 * byte-for-byte untouched and rejected. A current exact layout is verified and
 * returned without rerunning DDL or callbacks.
 */
export function initializeActivationRegistrySchemaV2(
  storage: DurableObjectStorage,
  workerVersionId: string,
  checkpoint?: (checkpoint: ActivationRegistrySchemaV2Checkpoint) => void,
): void {
  storage.transactionSync(() => {
    const objects = schemaObjects(storage.sql);
    if (objects.length > 0) {
      assertExactTopology(objects);
      assertCurrentSchema(storage.sql, workerVersionId);
      return;
    }

    initializeActivationOperationSchemaV2(storage.sql);
    checkpoint?.("OPERATION_CREATED");
    initializeActivationRecordSchemaV2(storage.sql);
    checkpoint?.("RECORD_CREATED");
    initializeActivationComponentJournalSchemaInTransaction(
      storage.sql,
      workerVersionId,
      (journalCheckpoint) => {
        checkpoint?.(
          journalCheckpoint === "TOPOLOGY_CREATED"
            ? "JOURNAL_TOPOLOGY_CREATED"
            : "JOURNAL_SELECTION_CREATED",
        );
      },
    );
    initializeComponentOperationBinding(storage.sql);
    checkpoint?.("BINDING_CREATED");
    initializeRegistryStamp(storage.sql, workerVersionId);
    checkpoint?.("REGISTRY_STAMPED");
    assertExactTopology(schemaObjects(storage.sql));
    assertCurrentSchema(storage.sql, workerVersionId);
  });
}

function initializeRegistryStamp(sql: SqlStorage, workerVersionId: string): void {
  sql.exec(`
    CREATE TABLE ${REGISTRY_SCHEMA_TABLE} (
      singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
      version INTEGER NOT NULL CHECK(version = 2),
      worker_version_id TEXT NOT NULL UNIQUE CHECK(length(worker_version_id) = 36)
    ) STRICT
  `);
  sql.exec(
    `INSERT INTO ${REGISTRY_SCHEMA_TABLE}(singleton, version, worker_version_id)
     VALUES (1, ?, ?)`,
    ACTIVATION_REGISTRY_STORAGE_SCHEMA_VERSION_V2,
    workerVersionId,
  );
}

function initializeComponentOperationBinding(sql: SqlStorage): void {
  sql.exec(`
    CREATE TABLE ${ACTIVATION_REGISTRY_COMPONENT_OPERATION_BINDING_TABLE} (
      singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
      selected_session_id TEXT NOT NULL UNIQUE CHECK(length(selected_session_id) = 71),
      attempt_id TEXT NOT NULL UNIQUE CHECK(length(attempt_id) = 71),
      manifest_pointer_sha256 TEXT NOT NULL CHECK(length(manifest_pointer_sha256) = 71),
      resolved_projection_sha256 TEXT NOT NULL CHECK(length(resolved_projection_sha256) = 71),
      FOREIGN KEY(selected_session_id)
        REFERENCES activation_component_selection_v2(selected_session_id),
      FOREIGN KEY(selected_session_id)
        REFERENCES activation_component_manifest_authority_v2(session_id),
      FOREIGN KEY(attempt_id) REFERENCES activation_operation_intents(attempt_id)
    ) STRICT;

    CREATE TRIGGER activation_component_operation_binding_insert_v2
      BEFORE INSERT ON ${ACTIVATION_REGISTRY_COMPONENT_OPERATION_BINDING_TABLE}
      WHEN NOT EXISTS (
        SELECT 1 FROM activation_component_selection_v2 AS selection
        JOIN activation_component_sessions_v2 AS session
          ON session.session_id = selection.selected_session_id
        JOIN activation_component_manifest_authority_v2 AS manifest
          ON manifest.session_id = selection.selected_session_id
        WHERE selection.singleton = 1 AND selection.state = 'CONFIRMED'
          AND selection.selected_session_id = NEW.selected_session_id
          AND session.state = 'SELECTED'
          AND session.worker_version_id = (
            SELECT worker_version_id FROM activation_component_journal_schema WHERE singleton = 1
          )
          AND manifest.status = 'CONFIRMED'
          AND manifest.pointer_sha256 = NEW.manifest_pointer_sha256
      ) OR NOT EXISTS (
        SELECT 1 FROM activation_operation_issuances AS issuance
        JOIN activation_operation_intents AS intent ON intent.attempt_id = issuance.attempt_id
        WHERE intent.attempt_id = NEW.attempt_id
          AND intent.sequence = 0 AND intent.state = 'OPEN'
          AND intent.worker_version_id = (
            SELECT worker_version_id FROM activation_component_journal_schema WHERE singleton = 1
          )
          AND issuance.state IN (
            'RESERVED', 'COLLECTING', 'FROZEN', 'EFFECTS_PENDING', 'READY_TO_APPEND'
          )
          AND issuance.ordinal = (
            SELECT MAX(current.ordinal) FROM activation_operation_issuances AS current
            WHERE current.attempt_id = issuance.attempt_id
          )
          AND (
            SELECT COUNT(*) FROM activation_operation_slots AS slot
            WHERE slot.issuance_id = issuance.issuance_id
          ) = 5
      )
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_OPERATION_BINDING_INVALID');
      END;
    CREATE TRIGGER activation_component_operation_binding_update_v2
      BEFORE UPDATE ON ${ACTIVATION_REGISTRY_COMPONENT_OPERATION_BINDING_TABLE}
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_OPERATION_BINDING_IMMUTABLE');
      END;
    CREATE TRIGGER activation_component_operation_binding_delete_v2
      BEFORE DELETE ON ${ACTIVATION_REGISTRY_COMPONENT_OPERATION_BINDING_TABLE}
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_OPERATION_BINDING_IMMUTABLE');
      END;
  `);
}

function assertCurrentSchema(sql: SqlStorage, workerVersionId: string): void {
  let rows: readonly RegistryStampRow[];
  try {
    rows = sql
      .exec<RegistryStampRow>(
        `SELECT singleton, version, worker_version_id FROM ${REGISTRY_SCHEMA_TABLE}`,
      )
      .toArray();
  } catch {
    throw schemaError("ACTIVATION_REGISTRY_V2_STAMP_INVALID");
  }
  const stamp = rows[0];
  if (
    rows.length !== 1 ||
    stamp?.singleton !== 1 ||
    stamp.version !== ACTIVATION_REGISTRY_STORAGE_SCHEMA_VERSION_V2 ||
    stamp.worker_version_id !== workerVersionId
  ) {
    throw schemaError("ACTIVATION_REGISTRY_V2_STAMP_CONFLICT");
  }
  assertRecordIssuanceRequired(sql);
  initializeActivationComponentJournalSchemaInTransaction(sql, workerVersionId);
}

function assertRecordIssuanceRequired(sql: SqlStorage): void {
  const column = sql
    .exec<{
      readonly name: string;
      readonly notnull: number;
      readonly type: string;
    }>("PRAGMA table_info(activation_records)")
    .toArray()
    .find(({ name }) => name === "operation_issuance_id");
  if (column?.type !== "TEXT" || column.notnull !== 1) {
    throw schemaError("ACTIVATION_REGISTRY_V2_RECORD_OWNERSHIP_INVALID");
  }
}

function assertExactTopology(objects: readonly SchemaObjectRow[]): void {
  if (
    objects.length !== EXPECTED_SCHEMA_OBJECTS.length ||
    objects.some((actual, index) => {
      const expected = EXPECTED_SCHEMA_OBJECTS[index];
      return (
        actual.type !== expected?.type ||
        actual.name !== expected.name ||
        actual.sql !== expected.sql
      );
    })
  ) {
    throw schemaError("ACTIVATION_REGISTRY_V2_TOPOLOGY_CONFLICT");
  }
}

function schemaObjects(sql: SqlStorage): readonly SchemaObjectRow[] {
  return sql
    .exec<SchemaObjectRow>(
      `SELECT type, name, sql FROM sqlite_schema
       WHERE type IN ('index', 'table', 'trigger', 'view') AND name NOT LIKE 'sqlite_%'
       ORDER BY type, name`,
    )
    .toArray();
}

function schemaError(code: string): BrokerError {
  return new BrokerError(code, 500, false);
}
