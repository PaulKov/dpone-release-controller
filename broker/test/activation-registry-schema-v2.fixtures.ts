import { ACTIVATION_COMPONENT_KINDS } from "../src/activation-component-contract";
import { ACTIVATION_REGISTRY_COMPONENT_OPERATION_BINDING_TABLE } from "../src/activation-registry-schema-v2";

export const REGISTRY_V2_WORKER_VERSION = "11111111-1111-4111-8111-111111111111";
export const REGISTRY_V2_RECORD_TIME = "2026-08-19T00:00:30.000Z";

export interface ConfirmedComponentAuthorityFixture {
  readonly manifestPointerSha256: string;
  readonly resolvedProjectionSha256: string;
  readonly sessionId: string;
}

export function clearLegacyRegistry(sql: SqlStorage): void {
  sql.exec(`
    DROP TABLE activation_records;
    DROP TABLE activation_operation_slots;
    DROP TABLE activation_cloudflare_anchors;
    DROP TABLE activation_operation_issuances;
    DROP TABLE activation_operation_intents;
    DROP TABLE activation_registry_storage_schema;
  `);
}

export function schemaObjectCount(sql: SqlStorage): number {
  return sql
    .exec<{ readonly count: number }>(
      `SELECT COUNT(*) AS count FROM sqlite_schema
       WHERE type IN ('index', 'table', 'trigger', 'view') AND name NOT LIKE 'sqlite_%'`,
    )
    .one().count;
}

export function registryStamp(sql: SqlStorage): {
  readonly singleton: number;
  readonly version: number;
  readonly worker_version_id: string;
} {
  return sql
    .exec<{
      readonly singleton: number;
      readonly version: number;
      readonly worker_version_id: string;
    }>("SELECT singleton, version, worker_version_id FROM activation_registry_storage_schema")
    .one();
}

export function journalStamp(sql: SqlStorage): {
  readonly schema_version: number;
  readonly worker_version_id: string;
} {
  return sql
    .exec<{
      readonly schema_version: number;
      readonly worker_version_id: string;
    }>("SELECT schema_version, worker_version_id FROM activation_component_journal_schema")
    .one();
}

export function schemaColumn(
  sql: SqlStorage,
  table: string,
  name: string,
): { readonly name: string; readonly notnull: number; readonly type: string } | undefined {
  return sql
    .exec<{ readonly name: string; readonly notnull: number; readonly type: string }>(
      `PRAGMA table_info(${table})`,
    )
    .toArray()
    .find((candidate) => candidate.name === name);
}

export function insertIntent(
  sql: SqlStorage,
  sequence: 0 | 1,
  attemptId: string,
  state: "CONFIRMED" | "HOLD" | "OPEN" = "OPEN",
): void {
  sql.exec(
    `INSERT INTO activation_operation_intents(
       sequence, attempt_id, intent_sha256, semantic_request_bytes,
       worker_version_id, created_at, state
     ) VALUES (?, ?, ?, ?, ?, '2026-08-19T00:00:00.000Z', ?)`,
    sequence,
    attemptId,
    digest(700 + sequence),
    new Uint8Array([sequence + 1]),
    REGISTRY_V2_WORKER_VERSION,
    state,
  );
}

export function insertRecord(
  sql: SqlStorage,
  sequence: 0 | 1,
  issuanceId: string,
  requestDigest: string,
  committedAt: string,
  suffix: string,
): void {
  sql.exec(
    `INSERT INTO activation_records(
       sequence, operation_issuance_id, request_digest, record_id, record_digest,
       canonical_bytes, committed_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    sequence,
    issuanceId,
    requestDigest,
    `record-${suffix}`,
    `digest-${suffix}`,
    new Uint8Array([sequence + 1]),
    committedAt,
  );
}

export function insertIssuance(
  sql: SqlStorage,
  attemptId: string,
  ordinal: number,
  issuanceId: string,
  state = "RESERVED",
  supersededByOrdinal: number | null = null,
): void {
  sql.exec(
    `INSERT INTO activation_operation_issuances(
       attempt_id, ordinal, issuance_id, internal_request_id, issued_at,
       fresh_until, state, superseded_by_ordinal
     ) VALUES (?, ?, ?, ?, '2026-08-19T00:00:00.000Z',
       '2026-08-19T00:01:00.000Z', ?, ?)`,
    attemptId,
    ordinal,
    issuanceId,
    `request-${issuanceId}`,
    state,
    supersededByOrdinal,
  );
}

export function insertSlot(
  sql: SqlStorage,
  issuanceId: string,
  slotId: string,
  slotKind: string,
  slotIndex: number,
): void {
  sql.exec(
    `INSERT INTO activation_operation_slots(
       issuance_id, slot_id, slot_kind, slot_index, state
     ) VALUES (?, ?, ?, ?, 'PREPARED')`,
    issuanceId,
    slotId,
    slotKind,
    slotIndex,
  );
}

export function insertCompactA0Roster(sql: SqlStorage, issuanceId: string): void {
  for (const [slotId, slotKind, slotIndex] of [
    ["CONTROLLER_ACTION", "DIRECT_WORM", 0],
    ["CONTROLLER_OIDC", "DIRECT_WORM", 1],
    ["TARGET_OIDC", "DIRECT_WORM", 2],
    ["TARGET_RULESET", "DIRECT_WORM", 3],
    ["CLOUDFLARE_BATCH", "CLOUDFLARE_BATCH", 4],
  ] as const) {
    insertSlot(sql, issuanceId, slotId, slotKind, slotIndex);
  }
}

export function confirmComponentAuthority(sql: SqlStorage): ConfirmedComponentAuthorityFixture {
  const sessionId = digest(100);
  sql.exec(
    `INSERT INTO activation_component_sessions_v2(
       session_id, journal_ordinal, generation, predecessor_session_id, set_id,
       worker_version_id, descriptor_id, descriptor_sha256, descriptor_bytes,
       component_set_committed_at, fresh_until, state, terminal_code
     ) VALUES (?, 1, 1, NULL, ?, ?, ?, ?, ?,
       '2026-08-19T00:00:00.000Z', '2026-08-19T00:10:00.000Z', 'SELECTED', NULL)`,
    sessionId,
    digest(101),
    REGISTRY_V2_WORKER_VERSION,
    digest(102),
    digest(103),
    new Uint8Array([1]),
  );
  for (const [ordinal, componentKind] of ACTIVATION_COMPONENT_KINDS.entries()) {
    sql.exec(
      `INSERT INTO activation_component_session_entries_v2(
         session_id, ordinal, component_kind, expected_payload_sha256, component_id,
         envelope_sha256, envelope_bytes, object_key, effect_id, result_bytes,
         result_sha256, status
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'CONFIRMED')`,
      sessionId,
      ordinal,
      componentKind,
      digest(200 + ordinal),
      digest(220 + ordinal),
      digest(240 + ordinal),
      new Uint8Array([ordinal + 1]),
      `receipts/v2/components/${ordinal}.json`,
      digest(260 + ordinal),
      new Uint8Array([ordinal + 2]),
      digest(280 + ordinal),
    );
  }
  sql.exec(
    `UPDATE activation_component_selection_v2
     SET selected_session_id = ?, state = 'COMPONENT_EFFECTS_SEALED',
         worm_service_identity = 'worm-service', worm_version_id = ?,
         observer_service_identity = 'observer-service', observer_version_id = ?
     WHERE singleton = 1`,
    sessionId,
    REGISTRY_V2_WORKER_VERSION,
    "22222222-2222-4222-8222-222222222222",
  );
  sql.exec(
    `UPDATE activation_component_selection_v2 SET state = 'COMPONENTS_CONFIRMED'
     WHERE singleton = 1`,
  );
  const pointerSha256 = digest(402);
  sql.exec(
    `INSERT INTO activation_component_manifest_authority_v2(
       session_id, manifest_id, manifest_sha256, manifest_bytes, object_key,
       effect_id, status
     ) VALUES (?, ?, ?, ?, 'receipts/v2/manifests/manifest.json', ?, 'SEALED')`,
    sessionId,
    digest(400),
    digest(401),
    new Uint8Array([1]),
    digest(403),
  );
  sql.exec(
    `UPDATE activation_component_selection_v2 SET state = 'MANIFEST_EFFECT_SEALED'
     WHERE singleton = 1`,
  );
  sql.exec(
    `UPDATE activation_component_manifest_authority_v2
     SET result_bytes = ?, result_sha256 = ?, pointer_bytes = ?, pointer_sha256 = ?,
         status = 'CONFIRMED' WHERE session_id = ?`,
    new Uint8Array([2]),
    digest(404),
    new Uint8Array([3]),
    pointerSha256,
    sessionId,
  );
  sql.exec("UPDATE activation_component_selection_v2 SET state = 'CONFIRMED' WHERE singleton = 1");
  return {
    manifestPointerSha256: pointerSha256,
    resolvedProjectionSha256: digest(405),
    sessionId,
  };
}

export function insertBinding(
  sql: SqlStorage,
  component: ConfirmedComponentAuthorityFixture,
  attemptId: string,
): void {
  sql.exec(
    `INSERT INTO ${ACTIVATION_REGISTRY_COMPONENT_OPERATION_BINDING_TABLE}(
       singleton, selected_session_id, attempt_id,
       manifest_pointer_sha256, resolved_projection_sha256
     ) VALUES (1, ?, ?, ?, ?)`,
    component.sessionId,
    attemptId,
    component.manifestPointerSha256,
    component.resolvedProjectionSha256,
  );
}

export function digest(value: number): string {
  return `sha256:${value.toString(16).padStart(64, "0")}`;
}
