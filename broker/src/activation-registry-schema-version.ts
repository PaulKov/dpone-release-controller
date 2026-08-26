import { BrokerError } from "./errors";

export const ACTIVATION_REGISTRY_STORAGE_SCHEMA_VERSION = 1;
export const ACTIVATION_REGISTRY_STORAGE_TABLES = Object.freeze([
  "activation_operation_intents",
  "activation_operation_issuances",
  "activation_operation_slots",
  "activation_cloudflare_anchors",
  "activation_records",
]);

const VERSION_TABLE = "activation_registry_storage_schema";
const TABLE_NAME = /^[a-z][a-z0-9_]{0,63}$/u;

/**
 * Initialize one explicitly versioned ActivationRegistry storage layout.
 *
 * Unversioned state is eligible only while every reviewed legacy table is
 * empty. Empty tables are dropped in reverse dependency order, rebuilt by the
 * supplied initializer, verified present, and stamped last. A crash before the
 * final stamp therefore remains safely retryable; populated or unknown layouts
 * fail closed without mutation.
 */
export function initializeActivationRegistrySchemaVersion(
  sql: SqlStorage,
  initializeCurrentSchema: () => void,
  tableNames: readonly string[] = ACTIVATION_REGISTRY_STORAGE_TABLES,
): void {
  const names = validateTableNames(tableNames);
  initializeVersionTable(sql);
  const version = storedVersion(sql);
  if (version !== null) {
    if (version !== ACTIVATION_REGISTRY_STORAGE_SCHEMA_VERSION) {
      throw schemaError("ACTIVATION_REGISTRY_SCHEMA_VERSION_UNSUPPORTED");
    }
    assertTablesPresent(sql, names);
    return;
  }

  assertEmptyLegacyOrFail(sql, names);
  for (const name of [...names].reverse()) {
    if (tableExists(sql, name)) sql.exec(`DROP TABLE ${quoted(name)}`);
  }
  initializeCurrentSchema();
  assertTablesPresent(sql, names);
  sql.exec(
    `INSERT INTO ${VERSION_TABLE}(singleton, version) VALUES (1, ?)`,
    ACTIVATION_REGISTRY_STORAGE_SCHEMA_VERSION,
  );
}

/** Reject any populated unversioned table before a destructive schema rebuild. */
export function assertEmptyLegacyOrFail(sql: SqlStorage, tableNames: readonly string[]): void {
  for (const name of validateTableNames(tableNames)) {
    if (!tableExists(sql, name)) continue;
    const populated = sql.exec(`SELECT 1 AS present FROM ${quoted(name)} LIMIT 1`).toArray()[0];
    if (populated !== undefined) {
      throw schemaError("ACTIVATION_REGISTRY_LEGACY_STATE_PRESENT");
    }
  }
}

function initializeVersionTable(sql: SqlStorage): void {
  sql.exec(`
    CREATE TABLE IF NOT EXISTS ${VERSION_TABLE} (
      singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
      version INTEGER NOT NULL CHECK(version BETWEEN 1 AND 1000000)
    ) STRICT
  `);
}

function storedVersion(sql: SqlStorage): number | null {
  const rows = sql
    .exec<{
      readonly singleton: number;
      readonly version: number;
    }>(`SELECT singleton, version FROM ${VERSION_TABLE}`)
    .toArray();
  if (rows.length === 0) return null;
  const row = rows[0];
  if (
    rows.length !== 1 ||
    row?.singleton !== 1 ||
    !Number.isSafeInteger(row.version) ||
    row.version < 1
  ) {
    throw schemaError("ACTIVATION_REGISTRY_SCHEMA_VERSION_INVALID");
  }
  return row.version;
}

function assertTablesPresent(sql: SqlStorage, tableNames: readonly string[]): void {
  if (tableNames.some((name) => !tableExists(sql, name))) {
    throw schemaError("ACTIVATION_REGISTRY_SCHEMA_TABLE_MISSING");
  }
}

function tableExists(sql: SqlStorage, name: string): boolean {
  return (
    sql
      .exec<{
        readonly name: string;
      }>("SELECT name FROM sqlite_schema WHERE type = 'table' AND name = ?", name)
      .toArray()[0]?.name === name
  );
}

function validateTableNames(tableNames: readonly string[]): readonly string[] {
  if (
    tableNames.length === 0 ||
    new Set(tableNames).size !== tableNames.length ||
    tableNames.some((name) => !TABLE_NAME.test(name) || name === VERSION_TABLE)
  ) {
    throw schemaError("ACTIVATION_REGISTRY_SCHEMA_TABLE_INVALID");
  }
  return [...tableNames];
}

function quoted(name: string): string {
  return `"${name}"`;
}

function schemaError(code: string): BrokerError {
  return new BrokerError(code, 500, false);
}
