import { ACTIVATION_COMPONENT_KINDS } from "./activation-component-contract";
import { ACTIVATION_COMPONENT_WORKER_VERSION } from "./activation-component-codec";
import {
  ACTIVATION_COMPONENT_CONTINUATION_TRIGGERS,
  ACTIVATION_COMPONENT_MANIFEST_AUTHORITY_TABLE,
  activationComponentManifestAuthoritySchemaSql,
} from "./activation-component-journal-manifest-schema";
import { BrokerError } from "./errors";

export const ACTIVATION_COMPONENT_JOURNAL_SCHEMA_VERSION = 2;
const JOURNAL_SCHEMA_TABLE = "activation_component_journal_schema";
export const ACTIVATION_COMPONENT_JOURNAL_SCHEMA_TABLES = Object.freeze([
  JOURNAL_SCHEMA_TABLE,
  "activation_component_sessions_v2",
  "activation_component_session_entries_v2",
  "activation_component_selection_v2",
  ACTIVATION_COMPONENT_MANIFEST_AUTHORITY_TABLE,
]);
export const ACTIVATION_COMPONENT_JOURNAL_SCHEMA_INDEXES = Object.freeze([
  "activation_component_live_sessions_v2",
  "activation_component_one_live_set_v2",
  "activation_component_one_selected_session_v2",
]);
export const ACTIVATION_COMPONENT_JOURNAL_SCHEMA_TRIGGERS = Object.freeze([
  "activation_component_live_capacity_insert_v2",
  "activation_component_live_capacity_update_v2",
  ...ACTIVATION_COMPONENT_CONTINUATION_TRIGGERS,
]);

export interface ActivationComponentJournalSessionRow extends Record<string, SqlStorageValue> {
  readonly component_set_committed_at: string;
  readonly descriptor_bytes: ArrayBuffer;
  readonly descriptor_id: string;
  readonly descriptor_sha256: string;
  readonly fresh_until: string;
  readonly generation: number;
  readonly journal_ordinal: number;
  readonly predecessor_session_id: string | null;
  readonly session_id: string;
  readonly set_id: string;
  readonly state: string;
  readonly terminal_code: string | null;
  readonly worker_version_id: string;
}

export interface ActivationComponentJournalEntryRow extends Record<string, SqlStorageValue> {
  readonly component_id: string | null;
  readonly component_kind: string;
  readonly effect_id: string | null;
  readonly envelope_bytes: ArrayBuffer | null;
  readonly envelope_sha256: string | null;
  readonly expected_payload_sha256: string;
  readonly object_key: string | null;
  readonly ordinal: number;
  readonly result_bytes: ArrayBuffer | null;
  readonly result_sha256: string | null;
  readonly session_id: string;
  readonly status: string;
}

export interface ActivationComponentJournalSelectionRow extends Record<string, SqlStorageValue> {
  readonly hold_code: string | null;
  readonly observer_service_identity: string | null;
  readonly observer_version_id: string | null;
  readonly selected_session_id: string | null;
  readonly state: string;
  readonly worm_service_identity: string | null;
  readonly worm_version_id: string | null;
}

export type ActivationComponentJournalSchemaCheckpoint = "TOPOLOGY_CREATED" | "SELECTION_CREATED";

/** Initialize the isolated, version-scoped candidate journal topology. */
export function initializeActivationComponentJournalSchema(
  storage: DurableObjectStorage,
  workerVersionId: string,
  checkpoint?: (checkpoint: ActivationComponentJournalSchemaCheckpoint) => void,
): void {
  storage.transactionSync(() => {
    initializeActivationComponentJournalSchemaInTransaction(
      storage.sql,
      workerVersionId,
      checkpoint,
    );
  });
}

/** Initialize journal DDL inside a transaction owned by a unified registry bootstrap. */
export function initializeActivationComponentJournalSchemaInTransaction(
  sql: SqlStorage,
  workerVersionId: string,
  checkpoint?: (checkpoint: ActivationComponentJournalSchemaCheckpoint) => void,
): void {
  if (!ACTIVATION_COMPONENT_WORKER_VERSION.test(workerVersionId)) {
    throw schemaError("ACTIVATION_COMPONENT_JOURNAL_WORKER_VERSION_INVALID");
  }
  if (tableExists(sql, JOURNAL_SCHEMA_TABLE)) {
    assertCurrentSchema(sql, workerVersionId);
    return;
  }
  if (ACTIVATION_COMPONENT_JOURNAL_SCHEMA_TABLES.slice(1).some((name) => tableExists(sql, name))) {
    throw schemaError("ACTIVATION_COMPONENT_JOURNAL_UNVERSIONED_STATE_PRESENT");
  }
  sql.exec(`
    CREATE TABLE IF NOT EXISTS activation_component_journal_schema (
      singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
      schema_version INTEGER NOT NULL CHECK(schema_version = 2),
      worker_version_id TEXT NOT NULL UNIQUE CHECK(length(worker_version_id) = 36)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS activation_component_sessions_v2 (
      session_id TEXT PRIMARY KEY CHECK(length(session_id) = 71),
      journal_ordinal INTEGER NOT NULL UNIQUE CHECK(journal_ordinal BETWEEN 1 AND 8),
      generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 8),
      predecessor_session_id TEXT UNIQUE,
      set_id TEXT NOT NULL CHECK(length(set_id) = 71),
      worker_version_id TEXT NOT NULL CHECK(length(worker_version_id) = 36),
      descriptor_id TEXT NOT NULL UNIQUE CHECK(length(descriptor_id) = 71),
      descriptor_sha256 TEXT NOT NULL UNIQUE CHECK(length(descriptor_sha256) = 71),
      descriptor_bytes BLOB NOT NULL CHECK(length(descriptor_bytes) BETWEEN 1 AND 65536),
      component_set_committed_at TEXT NOT NULL CHECK(length(component_set_committed_at) = 24),
      fresh_until TEXT NOT NULL CHECK(length(fresh_until) = 24),
      state TEXT NOT NULL CHECK(state IN (
        'PROVISIONAL', 'STAGED', 'SELECTED', 'REJECTED', 'ABANDONED', 'SUPERSEDED'
      )),
      terminal_code TEXT CHECK(length(terminal_code) BETWEEN 1 AND 128),
      UNIQUE(set_id, generation),
      FOREIGN KEY(predecessor_session_id) REFERENCES activation_component_sessions_v2(session_id),
      FOREIGN KEY(worker_version_id) REFERENCES activation_component_journal_schema(worker_version_id),
      CHECK(
        (generation = 1 AND predecessor_session_id IS NULL)
        OR (generation > 1 AND predecessor_session_id IS NOT NULL)
      ),
      CHECK(component_set_committed_at < fresh_until),
      CHECK(
        (state IN ('PROVISIONAL', 'STAGED', 'SELECTED') AND terminal_code IS NULL)
        OR (state = 'REJECTED' AND terminal_code IS NOT NULL
          AND terminal_code = 'ACTIVATION_COMPONENT_SET_SEMANTIC_INVALID')
        OR (state = 'ABANDONED' AND terminal_code IS NOT NULL
          AND terminal_code = 'ACTIVATION_COMPONENT_SESSION_EXPIRED')
        OR (state = 'SUPERSEDED' AND terminal_code IS NOT NULL
          AND terminal_code = 'ACTIVATION_COMPONENT_SESSION_SUPERSEDED')
      )
    ) STRICT;

    CREATE TABLE IF NOT EXISTS activation_component_session_entries_v2 (
      session_id TEXT NOT NULL,
      ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 14),
      component_kind TEXT NOT NULL,
      expected_payload_sha256 TEXT NOT NULL CHECK(length(expected_payload_sha256) = 71),
      component_id TEXT UNIQUE CHECK(length(component_id) = 71),
      envelope_sha256 TEXT UNIQUE CHECK(length(envelope_sha256) = 71),
      envelope_bytes BLOB CHECK(length(envelope_bytes) BETWEEN 1 AND 65536),
      object_key TEXT UNIQUE CHECK(length(object_key) BETWEEN 1 AND 512),
      effect_id TEXT UNIQUE CHECK(length(effect_id) = 71),
      result_bytes BLOB CHECK(length(result_bytes) BETWEEN 1 AND 65536),
      result_sha256 TEXT CHECK(length(result_sha256) = 71),
      status TEXT NOT NULL CHECK(status IN ('EXPECTED', 'STAGED', 'SEALED', 'CONFIRMED')),
      PRIMARY KEY(session_id, ordinal),
      UNIQUE(session_id, component_kind),
      FOREIGN KEY(session_id) REFERENCES activation_component_sessions_v2(session_id),
      CHECK(${rosterConstraint()}),
      CHECK(
        (status = 'EXPECTED' AND component_id IS NULL AND envelope_sha256 IS NULL
          AND envelope_bytes IS NULL AND object_key IS NULL AND effect_id IS NULL
          AND result_bytes IS NULL AND result_sha256 IS NULL)
        OR
        (status = 'STAGED' AND component_id IS NOT NULL AND envelope_sha256 IS NOT NULL
          AND envelope_bytes IS NOT NULL AND object_key IS NOT NULL AND effect_id IS NULL
          AND result_bytes IS NULL AND result_sha256 IS NULL)
        OR
        (status = 'SEALED' AND component_id IS NOT NULL AND envelope_sha256 IS NOT NULL
          AND envelope_bytes IS NOT NULL AND object_key IS NOT NULL AND effect_id IS NOT NULL
          AND result_bytes IS NULL AND result_sha256 IS NULL)
        OR
        (status = 'CONFIRMED' AND component_id IS NOT NULL AND envelope_sha256 IS NOT NULL
          AND envelope_bytes IS NOT NULL AND object_key IS NOT NULL AND effect_id IS NOT NULL
          AND result_bytes IS NOT NULL AND result_sha256 IS NOT NULL)
      )
    ) STRICT;

    CREATE TABLE IF NOT EXISTS activation_component_selection_v2 (
      singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
      selected_session_id TEXT UNIQUE,
      state TEXT NOT NULL CHECK(state IN (
        'OPEN', 'COMPONENT_EFFECTS_SEALED', 'COMPONENTS_CONFIRMED',
        'MANIFEST_EFFECT_SEALED', 'CONFIRMED', 'HOLD'
      )),
      worm_service_identity TEXT,
      worm_version_id TEXT,
      observer_service_identity TEXT,
      observer_version_id TEXT,
      hold_code TEXT CHECK(length(hold_code) BETWEEN 1 AND 128),
      FOREIGN KEY(selected_session_id) REFERENCES activation_component_sessions_v2(session_id),
      CHECK(
        (state = 'OPEN' AND selected_session_id IS NULL AND worm_service_identity IS NULL
          AND worm_version_id IS NULL AND observer_service_identity IS NULL
          AND observer_version_id IS NULL AND hold_code IS NULL)
        OR
        (state NOT IN ('OPEN', 'HOLD') AND selected_session_id IS NOT NULL
          AND worm_service_identity IS NOT NULL AND worm_version_id IS NOT NULL
          AND observer_service_identity IS NOT NULL AND observer_version_id IS NOT NULL
          AND hold_code IS NULL)
        OR
        (state = 'HOLD' AND selected_session_id IS NOT NULL
          AND worm_service_identity IS NOT NULL AND worm_version_id IS NOT NULL
          AND observer_service_identity IS NOT NULL AND observer_version_id IS NOT NULL
          AND hold_code IS NOT NULL)
      )
    ) STRICT;

    ${activationComponentManifestAuthoritySchemaSql()}

    CREATE INDEX IF NOT EXISTS activation_component_live_sessions_v2
      ON activation_component_sessions_v2(state)
      WHERE state IN ('PROVISIONAL', 'STAGED');
    CREATE UNIQUE INDEX IF NOT EXISTS activation_component_one_live_set_v2
      ON activation_component_sessions_v2(set_id)
      WHERE state IN ('PROVISIONAL', 'STAGED', 'SELECTED');
    CREATE UNIQUE INDEX IF NOT EXISTS activation_component_one_selected_session_v2
      ON activation_component_sessions_v2((1))
      WHERE state = 'SELECTED';
    CREATE TRIGGER IF NOT EXISTS activation_component_live_capacity_insert_v2
      BEFORE INSERT ON activation_component_sessions_v2
      WHEN NEW.state IN ('PROVISIONAL', 'STAGED')
        AND (SELECT COUNT(*) FROM activation_component_sessions_v2
             WHERE state IN ('PROVISIONAL', 'STAGED')) >= 4
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_JOURNAL_LIVE_CAPACITY_EXHAUSTED');
      END;
    CREATE TRIGGER IF NOT EXISTS activation_component_live_capacity_update_v2
      BEFORE UPDATE OF state ON activation_component_sessions_v2
      WHEN OLD.state NOT IN ('PROVISIONAL', 'STAGED')
        AND NEW.state IN ('PROVISIONAL', 'STAGED')
        AND (SELECT COUNT(*) FROM activation_component_sessions_v2
             WHERE state IN ('PROVISIONAL', 'STAGED')) >= 4
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_JOURNAL_LIVE_CAPACITY_EXHAUSTED');
      END;
  `);
  checkpoint?.("TOPOLOGY_CREATED");
  sql.exec(`INSERT INTO activation_component_selection_v2(singleton, state) VALUES (1, 'OPEN')`);
  checkpoint?.("SELECTION_CREATED");
  sql.exec(
    `INSERT INTO activation_component_journal_schema(singleton, schema_version, worker_version_id)
     VALUES (1, ?, ?)`,
    ACTIVATION_COMPONENT_JOURNAL_SCHEMA_VERSION,
    workerVersionId,
  );
}

function rosterConstraint(): string {
  return ACTIVATION_COMPONENT_KINDS.map(
    (kind, ordinal) => `(ordinal = ${ordinal} AND component_kind = '${kind}')`,
  ).join(" OR ");
}

function assertCurrentSchema(sql: SqlStorage, workerVersionId: string): void {
  if (
    ACTIVATION_COMPONENT_JOURNAL_SCHEMA_TABLES.some(
      (name) => !schemaObjectExists(sql, "table", name),
    ) ||
    ACTIVATION_COMPONENT_JOURNAL_SCHEMA_INDEXES.some(
      (name) => !schemaObjectExists(sql, "index", name),
    ) ||
    ACTIVATION_COMPONENT_JOURNAL_SCHEMA_TRIGGERS.some(
      (name) => !schemaObjectExists(sql, "trigger", name),
    )
  ) {
    throw schemaError("ACTIVATION_COMPONENT_JOURNAL_SCHEMA_TABLE_MISSING");
  }
  const schema = sql
    .exec<{
      readonly schema_version: number;
      readonly worker_version_id: string;
    }>(`SELECT schema_version, worker_version_id FROM activation_component_journal_schema`)
    .toArray();
  const current = schema[0];
  if (
    schema.length !== 1 ||
    current?.schema_version !== ACTIVATION_COMPONENT_JOURNAL_SCHEMA_VERSION ||
    current.worker_version_id !== workerVersionId
  ) {
    throw schemaError("ACTIVATION_COMPONENT_JOURNAL_SCHEMA_CONFLICT");
  }
  const selections = sql
    .exec<{
      readonly singleton: number;
    }>(`SELECT singleton FROM activation_component_selection_v2 WHERE singleton = 1`)
    .toArray();
  if (selections.length !== 1) {
    throw schemaError("ACTIVATION_COMPONENT_JOURNAL_SCHEMA_SELECTION_MISSING");
  }
}

function tableExists(sql: SqlStorage, name: string): boolean {
  return schemaObjectExists(sql, "table", name);
}

function schemaObjectExists(
  sql: SqlStorage,
  type: "index" | "table" | "trigger",
  name: string,
): boolean {
  return (
    sql
      .exec<{
        readonly name: string;
      }>(`SELECT name FROM sqlite_schema WHERE type = ? AND name = ?`, type, name)
      .toArray()[0]?.name === name
  );
}

function schemaError(code: string): BrokerError {
  return new BrokerError(code, 500, false);
}
