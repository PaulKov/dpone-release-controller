import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import {
  ACTIVATION_REGISTRY_COMPONENT_OPERATION_BINDING_TABLE,
  ACTIVATION_REGISTRY_STORAGE_SCHEMA_VERSION_V2,
  type ActivationRegistrySchemaV2Checkpoint,
  initializeActivationRegistrySchemaV2,
} from "../src/activation-registry-schema-v2";
import {
  clearLegacyRegistry,
  confirmComponentAuthority,
  digest,
  insertBinding,
  insertCompactA0Roster,
  insertIntent,
  insertIssuance,
  insertRecord,
  insertSlot,
  journalStamp,
  registryStamp,
  REGISTRY_V2_RECORD_TIME,
  REGISTRY_V2_WORKER_VERSION,
  schemaColumn,
  schemaObjectCount,
} from "./activation-registry-schema-v2.fixtures";

const CHECKPOINTS: readonly ActivationRegistrySchemaV2Checkpoint[] = [
  "OPERATION_CREATED",
  "RECORD_CREATED",
  "JOURNAL_TOPOLOGY_CREATED",
  "JOURNAL_SELECTION_CREATED",
  "BINDING_CREATED",
  "REGISTRY_STAMPED",
];

afterEach(async () => {
  await reset();
});

describe("ActivationRegistry compact-v2 unified schema", () => {
  it("atomically creates the exact topology and is idempotent", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("registry-schema-v2-current-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      clearLegacyRegistry(state.storage.sql);
      const visited: ActivationRegistrySchemaV2Checkpoint[] = [];
      initializeActivationRegistrySchemaV2(
        state.storage,
        REGISTRY_V2_WORKER_VERSION,
        (checkpoint) => {
          visited.push(checkpoint);
        },
      );
      expect(visited).toEqual(CHECKPOINTS);
      expect(registryStamp(state.storage.sql)).toEqual({
        singleton: 1,
        version: ACTIVATION_REGISTRY_STORAGE_SCHEMA_VERSION_V2,
        worker_version_id: REGISTRY_V2_WORKER_VERSION,
      });
      expect(journalStamp(state.storage.sql)).toEqual({
        schema_version: 2,
        worker_version_id: REGISTRY_V2_WORKER_VERSION,
      });
      expect(
        schemaColumn(state.storage.sql, "activation_records", "operation_issuance_id"),
      ).toMatchObject({ name: "operation_issuance_id", notnull: 1, type: "TEXT" });
      expect(
        state.storage.sql
          .exec<{ readonly type: string }>(
            `PRAGMA table_info(${ACTIVATION_REGISTRY_COMPONENT_OPERATION_BINDING_TABLE})`,
          )
          .toArray()
          .some(({ type }) => type === "BLOB"),
      ).toBe(false);
      expect(schemaObjectCount(state.storage.sql)).toBeGreaterThan(30);

      initializeActivationRegistrySchemaV2(state.storage, REGISTRY_V2_WORKER_VERSION, () => {
        throw new Error("idempotent bootstrap reran a checkpoint");
      });
      expect(() =>
        initializeActivationRegistrySchemaV2(state.storage, "22222222-2222-4222-8222-222222222222"),
      ).toThrow("ACTIVATION_REGISTRY_V2_STAMP_CONFLICT");
    });
  });

  it.each(CHECKPOINTS)(
    "rolls back every object after injected %s failure",
    async (failurePoint) => {
      const stub = env.ACTIVATION_REGISTRY.getByName(
        `registry-schema-v2-fail-${failurePoint.toLowerCase()}`,
      );
      await runInDurableObject(stub, async (_instance, state) => {
        clearLegacyRegistry(state.storage.sql);
        expect(() =>
          initializeActivationRegistrySchemaV2(
            state.storage,
            REGISTRY_V2_WORKER_VERSION,
            (checkpoint) => {
              if (checkpoint === failurePoint) throw new Error(`ABORT_${failurePoint}`);
            },
          ),
        ).toThrow(`ABORT_${failurePoint}`);
        expect(schemaObjectCount(state.storage.sql)).toBe(0);

        initializeActivationRegistrySchemaV2(state.storage, REGISTRY_V2_WORKER_VERSION);
        expect(registryStamp(state.storage.sql).version).toBe(2);
      });
    },
  );

  it("leaves populated v1, unversioned, partial, and unknown layouts untouched", async () => {
    const populated = env.ACTIVATION_REGISTRY.getByName("registry-schema-v2-populated-v1-0001");
    await runInDurableObject(populated, async (_instance, state) => {
      state.storage.sql.exec(
        `INSERT INTO activation_records(
           sequence, operation_issuance_id, request_digest, record_id, record_digest,
           canonical_bytes, committed_at
         ) VALUES (0, NULL, 'request-v1', 'record-v1', 'digest-v1', ?, '2026-08-19T00:00:00.000Z')`,
        new Uint8Array([1]),
      );
      expect(() =>
        initializeActivationRegistrySchemaV2(state.storage, REGISTRY_V2_WORKER_VERSION),
      ).toThrow("ACTIVATION_REGISTRY_V2_TOPOLOGY_CONFLICT");
      expect(
        state.storage.sql
          .exec<{ readonly record_id: string }>("SELECT record_id FROM activation_records")
          .one().record_id,
      ).toBe("record-v1");
    });

    const unversioned = env.ACTIVATION_REGISTRY.getByName("registry-schema-v2-unversioned-0001");
    await runInDurableObject(unversioned, async (_instance, state) => {
      clearLegacyRegistry(state.storage.sql);
      state.storage.sql.exec("CREATE TABLE legacy_unversioned(value TEXT NOT NULL) STRICT");
      state.storage.sql.exec("INSERT INTO legacy_unversioned VALUES ('preserve-me')");
      expect(() =>
        initializeActivationRegistrySchemaV2(state.storage, REGISTRY_V2_WORKER_VERSION),
      ).toThrow("ACTIVATION_REGISTRY_V2_TOPOLOGY_CONFLICT");
      expect(
        state.storage.sql
          .exec<{ readonly value: string }>("SELECT value FROM legacy_unversioned")
          .one().value,
      ).toBe("preserve-me");
    });

    const partial = env.ACTIVATION_REGISTRY.getByName("registry-schema-v2-partial-0001");
    await runInDurableObject(partial, async (_instance, state) => {
      clearLegacyRegistry(state.storage.sql);
      state.storage.sql.exec(
        "CREATE TABLE activation_records(sequence INTEGER PRIMARY KEY) STRICT",
      );
      expect(() =>
        initializeActivationRegistrySchemaV2(state.storage, REGISTRY_V2_WORKER_VERSION),
      ).toThrow("ACTIVATION_REGISTRY_V2_TOPOLOGY_CONFLICT");
      expect(schemaObjectCount(state.storage.sql)).toBe(1);
    });

    const viewOnly = env.ACTIVATION_REGISTRY.getByName("registry-schema-v2-view-0001");
    await runInDurableObject(viewOnly, async (_instance, state) => {
      clearLegacyRegistry(state.storage.sql);
      state.storage.sql.exec("CREATE VIEW attacker_view AS SELECT 'preserve-me' AS value");
      expect(() =>
        initializeActivationRegistrySchemaV2(state.storage, REGISTRY_V2_WORKER_VERSION),
      ).toThrow("ACTIVATION_REGISTRY_V2_TOPOLOGY_CONFLICT");
      expect(
        state.storage.sql.exec<{ readonly value: string }>("SELECT value FROM attacker_view").one()
          .value,
      ).toBe("preserve-me");
    });

    const unknown = env.ACTIVATION_REGISTRY.getByName("registry-schema-v2-unknown-0001");
    await runInDurableObject(unknown, async (_instance, state) => {
      clearLegacyRegistry(state.storage.sql);
      initializeActivationRegistrySchemaV2(state.storage, REGISTRY_V2_WORKER_VERSION);
      state.storage.sql.exec("CREATE TABLE attacker_sidecar(value TEXT NOT NULL) STRICT");
      expect(() =>
        initializeActivationRegistrySchemaV2(state.storage, REGISTRY_V2_WORKER_VERSION),
      ).toThrow("ACTIVATION_REGISTRY_V2_TOPOLOGY_CONFLICT");
      expect(
        state.storage.sql
          .exec<{
            readonly version: number;
          }>("SELECT version FROM activation_registry_storage_schema WHERE singleton = 1")
          .one().version,
      ).toBe(2);
    });
  });

  it("enforces sequence-aware compact-v2 operation slot profiles", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("registry-schema-v2-operation-profile-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      clearLegacyRegistry(state.storage.sql);
      initializeActivationRegistrySchemaV2(state.storage, REGISTRY_V2_WORKER_VERSION);
      const sql = state.storage.sql;
      expect(() => insertIntent(sql, 0, "attempt-a0", "HOLD")).toThrow(
        "ACTIVATION_OPERATION_INTENT_INITIAL_STATE_INVALID",
      );
      insertIntent(sql, 0, "attempt-a0");
      expect(() => insertIssuance(sql, "attempt-a0", 1, "issuance-a0", "COLLECTING")).toThrow(
        "ACTIVATION_OPERATION_ISSUANCE_INITIAL_STATE_INVALID",
      );
      insertIssuance(sql, "attempt-a0", 1, "issuance-a0");
      for (const state of ["READ_IN_FLIGHT", "CONFIRMED"]) {
        expect(() =>
          sql.exec(
            `INSERT INTO activation_operation_slots(
               issuance_id, slot_id, slot_kind, slot_index, state
             ) VALUES ('issuance-a0', 'CONTROLLER_ACTION', 'DIRECT_WORM', 0, ?)`,
            state,
          ),
        ).toThrow("ACTIVATION_OPERATION_SLOT_PROFILE_INVALID");
      }
      insertSlot(sql, "issuance-a0", "CONTROLLER_ACTION", "DIRECT_WORM", 0);
      expect(() =>
        sql.exec(
          `UPDATE activation_operation_slots
           SET state = 'READ_IN_FLIGHT', provider_request_bytes = ?,
               provider_request_sha256 = ?
           WHERE issuance_id = 'issuance-a0' AND slot_id = 'CONTROLLER_ACTION'`,
          new Uint8Array([1]),
          digest(699),
        ),
      ).toThrow("ACTIVATION_OPERATION_ROSTER_INCOMPLETE");
      insertSlot(sql, "issuance-a0", "CONTROLLER_OIDC", "DIRECT_WORM", 1);
      insertSlot(sql, "issuance-a0", "TARGET_OIDC", "DIRECT_WORM", 2);
      insertSlot(sql, "issuance-a0", "TARGET_RULESET", "DIRECT_WORM", 3);
      insertSlot(sql, "issuance-a0", "CLOUDFLARE_BATCH", "CLOUDFLARE_BATCH", 4);
      expect(() =>
        sql.exec(
          `UPDATE activation_operation_slots
           SET state = 'READ_IN_FLIGHT', provider_request_bytes = ?,
               provider_request_sha256 = ?
           WHERE issuance_id = 'issuance-a0' AND slot_id = 'CONTROLLER_ACTION'`,
          new Uint8Array([1]),
          digest(698),
        ),
      ).not.toThrow();
      expect(() =>
        insertSlot(sql, "issuance-a0", "CLOUDFLARE_BATCH", "CLOUDFLARE_BATCH", 0),
      ).toThrow("ACTIVATION_OPERATION_SLOT_PROFILE_INVALID");

      insertIntent(sql, 1, "attempt-a1");
      insertIssuance(sql, "attempt-a1", 1, "issuance-a1");
      expect(() =>
        sql.exec(
          "UPDATE activation_operation_issuances SET state = 'COLLECTING' WHERE issuance_id = 'issuance-a1'",
        ),
      ).toThrow("ACTIVATION_OPERATION_ROSTER_INCOMPLETE");
      insertSlot(sql, "issuance-a1", "CLOUDFLARE_BATCH", "CLOUDFLARE_BATCH", 0);
      expect(() =>
        insertSlot(sql, "issuance-a1", "CLOUDFLARE_BATCH", "CLOUDFLARE_BATCH", 4),
      ).toThrow("ACTIVATION_OPERATION_SLOT_PROFILE_INVALID");
      expect(() => insertSlot(sql, "issuance-a1", "CONTROLLER_ACTION", "DIRECT_WORM", 0)).toThrow(
        "ACTIVATION_OPERATION_SLOT_PROFILE_INVALID",
      );
      expect(() =>
        sql.exec(
          "UPDATE activation_operation_intents SET sequence = 1 WHERE attempt_id = 'attempt-a0'",
        ),
      ).toThrow("ACTIVATION_OPERATION_INTENT_IDENTITY_IMMUTABLE");
      expect(() =>
        sql.exec(
          "UPDATE activation_operation_issuances SET attempt_id = 'attempt-a1' WHERE issuance_id = 'issuance-a0'",
        ),
      ).toThrow("ACTIVATION_OPERATION_ISSUANCE_IDENTITY_IMMUTABLE");
      expect(() =>
        sql.exec(
          `UPDATE activation_operation_slots SET slot_index = 4
           WHERE issuance_id = 'issuance-a0' AND slot_id = 'CONTROLLER_ACTION'`,
        ),
      ).toThrow("ACTIVATION_OPERATION_SLOT_IDENTITY_IMMUTABLE");
      expect(() =>
        sql.exec(
          `DELETE FROM activation_operation_slots
           WHERE issuance_id = 'issuance-a0' AND slot_id = 'CONTROLLER_ACTION'`,
        ),
      ).toThrow("ACTIVATION_OPERATION_SLOT_DELETE_FORBIDDEN");
      sql.exec(
        "UPDATE activation_operation_issuances SET state = 'COLLECTING' WHERE issuance_id = 'issuance-a1'",
      );
      expect(() =>
        insertSlot(sql, "issuance-a1", "CLOUDFLARE_BATCH", "CLOUDFLARE_BATCH", 0),
      ).toThrow("ACTIVATION_OPERATION_SLOT_PROFILE_INVALID");
      sql.exec(
        `UPDATE activation_operation_issuances
         SET state = 'READY_TO_APPEND', record_committed_at = ?
         WHERE issuance_id = 'issuance-a1'`,
        REGISTRY_V2_RECORD_TIME,
      );
      expect(() =>
        insertRecord(sql, 0, "issuance-a1", digest(701), REGISTRY_V2_RECORD_TIME, "mismatch"),
      ).toThrow("ACTIVATION_RECORD_OPERATION_BINDING_INVALID");
      insertRecord(sql, 1, "issuance-a1", digest(701), REGISTRY_V2_RECORD_TIME, "valid-a1");
      expect(() =>
        sql.exec("UPDATE activation_records SET sequence = 0 WHERE sequence = 1"),
      ).toThrow("ACTIVATION_RECORD_CORE_IMMUTABLE");
      expect(() => sql.exec("DELETE FROM activation_records WHERE sequence = 1")).toThrow(
        "ACTIVATION_RECORD_DELETE_FORBIDDEN",
      );
    });
  });

  it("keeps one attempt binding live across an eligible A0 issuance reissue", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("registry-schema-v2-binding-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      clearLegacyRegistry(state.storage.sql);
      initializeActivationRegistrySchemaV2(state.storage, REGISTRY_V2_WORKER_VERSION);
      const sql = state.storage.sql;
      const component = confirmComponentAuthority(sql);
      const attemptId = digest(600);
      const firstIssuance = digest(601);
      const secondIssuance = digest(602);
      insertIntent(sql, 0, attemptId);
      insertIssuance(sql, attemptId, 1, firstIssuance);
      expect(() => insertBinding(sql, component, attemptId)).toThrow(
        "ACTIVATION_COMPONENT_OPERATION_BINDING_INVALID",
      );
      insertCompactA0Roster(sql, firstIssuance);

      expect(() =>
        insertBinding(sql, { ...component, manifestPointerSha256: digest(999) }, attemptId),
      ).toThrow("ACTIVATION_COMPONENT_OPERATION_BINDING_INVALID");
      insertBinding(sql, component, attemptId);
      sql.exec(
        `UPDATE activation_operation_issuances SET state = 'EXPIRED_UNDISPATCHED'
         WHERE issuance_id = ?`,
        firstIssuance,
      );
      insertIssuance(sql, attemptId, 2, secondIssuance);
      insertCompactA0Roster(sql, secondIssuance);
      expect(
        sql
          .exec<{ readonly attempt_id: string }>(
            `SELECT attempt_id FROM ${ACTIVATION_REGISTRY_COMPONENT_OPERATION_BINDING_TABLE}
             WHERE singleton = 1`,
          )
          .one().attempt_id,
      ).toBe(attemptId);
      expect(() =>
        sql.exec(
          `UPDATE ${ACTIVATION_REGISTRY_COMPONENT_OPERATION_BINDING_TABLE}
           SET attempt_id = ? WHERE singleton = 1`,
          digest(998),
        ),
      ).toThrow("ACTIVATION_COMPONENT_OPERATION_BINDING_IMMUTABLE");
      expect(() =>
        sql.exec(`DELETE FROM ${ACTIVATION_REGISTRY_COMPONENT_OPERATION_BINDING_TABLE}`),
      ).toThrow("ACTIVATION_COMPONENT_OPERATION_BINDING_IMMUTABLE");
    });
  });
});
