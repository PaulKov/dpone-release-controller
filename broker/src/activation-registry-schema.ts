import { initializeActivationOperationSchema } from "./activation-operation-schema";
import { initializeActivationRecordSchema } from "./activation-record-schema";
import { initializeActivationRegistrySchemaVersion } from "./activation-registry-schema-version";

/** Initialize the complete versioned SQLite topology exactly once per registry. */
export function initializeActivationRegistrySchema(sql: SqlStorage): void {
  initializeActivationRegistrySchemaVersion(sql, () => {
    initializeActivationOperationSchema(sql);
    initializeActivationRecordSchema(sql);
  });
}
