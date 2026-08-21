import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { initializeActivationRegistrySchemaV2 } from "../src/activation-registry-schema-v2";
import {
  clearLegacyRegistry,
  confirmComponentAuthority,
  digest,
  insertBinding,
  insertCompactA0Roster,
  insertIntent,
  insertIssuance,
  insertRecord,
  REGISTRY_V2_RECORD_TIME,
  REGISTRY_V2_WORKER_VERSION,
} from "./activation-registry-schema-v2.fixtures";

afterEach(async () => {
  await reset();
});

describe("ActivationRegistry compact-v2 schema security", () => {
  it("rejects same-name weak DDL and no-op trigger forgeries without mutation", async () => {
    const triggerForgery = env.ACTIVATION_REGISTRY.getByName(
      "registry-schema-v2-trigger-forgery-0001",
    );
    await runInDurableObject(triggerForgery, async (_instance, state) => {
      clearLegacyRegistry(state.storage.sql);
      initializeActivationRegistrySchemaV2(state.storage, REGISTRY_V2_WORKER_VERSION);
      state.storage.sql.exec(`
        DROP TRIGGER activation_operation_slot_delete_forbidden_v2;
        CREATE TRIGGER activation_operation_slot_delete_forbidden_v2
          BEFORE DELETE ON activation_operation_slots BEGIN SELECT 1; END;
      `);
      expect(() =>
        initializeActivationRegistrySchemaV2(state.storage, REGISTRY_V2_WORKER_VERSION),
      ).toThrow("ACTIVATION_REGISTRY_V2_TOPOLOGY_CONFLICT");
      expect(
        state.storage.sql
          .exec<{ readonly sql: string }>(
            `SELECT sql FROM sqlite_schema
             WHERE type = 'trigger' AND name = 'activation_operation_slot_delete_forbidden_v2'`,
          )
          .one().sql,
      ).toContain("SELECT 1");
    });

    const tableForgery = env.ACTIVATION_REGISTRY.getByName("registry-schema-v2-table-forgery-0001");
    await runInDurableObject(tableForgery, async (_instance, state) => {
      clearLegacyRegistry(state.storage.sql);
      initializeActivationRegistrySchemaV2(state.storage, REGISTRY_V2_WORKER_VERSION);
      state.storage.sql.exec(`
        DROP TRIGGER activation_record_core_immutable_v2;
        DROP TRIGGER activation_record_delete_forbidden_v2;
        DROP TRIGGER activation_record_operation_binding_insert_v2;
        DROP TABLE activation_records;
        CREATE TABLE activation_records(sequence INTEGER PRIMARY KEY, sentinel TEXT) STRICT;
        CREATE TRIGGER activation_record_core_immutable_v2
          BEFORE UPDATE ON activation_records BEGIN SELECT 1; END;
        CREATE TRIGGER activation_record_delete_forbidden_v2
          BEFORE DELETE ON activation_records BEGIN SELECT 1; END;
        CREATE TRIGGER activation_record_operation_binding_insert_v2
          BEFORE INSERT ON activation_records BEGIN SELECT 1; END;
        INSERT INTO activation_records(sequence, sentinel) VALUES (0, 'preserve-me');
      `);
      expect(() =>
        initializeActivationRegistrySchemaV2(state.storage, REGISTRY_V2_WORKER_VERSION),
      ).toThrow("ACTIVATION_REGISTRY_V2_TOPOLOGY_CONFLICT");
      expect(
        state.storage.sql
          .exec<{ readonly sentinel: string }>("SELECT sentinel FROM activation_records")
          .one().sentinel,
      ).toBe("preserve-me");
    });
  });

  it("rejects a component binding across worker versions", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("registry-schema-v2-binding-worker-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      clearLegacyRegistry(state.storage.sql);
      initializeActivationRegistrySchemaV2(state.storage, REGISTRY_V2_WORKER_VERSION);
      const sql = state.storage.sql;
      const component = confirmComponentAuthority(sql);
      const attemptId = digest(650);
      const issuanceId = digest(651);
      sql.exec(
        `INSERT INTO activation_operation_intents(
           sequence, attempt_id, intent_sha256, semantic_request_bytes,
           worker_version_id, created_at, state
         ) VALUES (0, ?, ?, ?, ?, '2026-08-19T00:00:00.000Z', 'OPEN')`,
        attemptId,
        digest(652),
        new Uint8Array([1]),
        "33333333-3333-4333-8333-333333333333",
      );
      insertIssuance(sql, attemptId, 1, issuanceId);
      insertCompactA0Roster(sql, issuanceId);
      expect(() => insertBinding(sql, component, attemptId)).toThrow(
        "ACTIVATION_COMPONENT_OPERATION_BINDING_INVALID",
      );
    });
  });

  it("fences a record to the latest ready issuance and exact intent commitments", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("registry-schema-v2-record-binding-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      clearLegacyRegistry(state.storage.sql);
      initializeActivationRegistrySchemaV2(state.storage, REGISTRY_V2_WORKER_VERSION);
      const sql = state.storage.sql;
      const attemptId = digest(660);
      const firstIssuance = digest(661);
      const secondIssuance = digest(662);
      const intentDigest = digest(700);
      insertIntent(sql, 0, attemptId);
      insertIssuance(sql, attemptId, 1, firstIssuance);
      insertCompactA0Roster(sql, firstIssuance);
      sql.exec(
        `UPDATE activation_operation_issuances SET record_committed_at = ?
         WHERE issuance_id = ?`,
        REGISTRY_V2_RECORD_TIME,
        firstIssuance,
      );
      expect(() =>
        insertRecord(sql, 0, firstIssuance, intentDigest, REGISTRY_V2_RECORD_TIME, "reserved"),
      ).toThrow("ACTIVATION_RECORD_OPERATION_BINDING_INVALID");
      sql.exec(
        `UPDATE activation_operation_issuances SET state = 'EFFECTS_PENDING'
         WHERE issuance_id = ?`,
        firstIssuance,
      );
      expect(() =>
        insertRecord(
          sql,
          0,
          firstIssuance,
          intentDigest,
          REGISTRY_V2_RECORD_TIME,
          "effects-pending",
        ),
      ).toThrow("ACTIVATION_RECORD_OPERATION_BINDING_INVALID");

      sql.exec(
        `UPDATE activation_operation_issuances SET state = 'EXPIRED_UNDISPATCHED'
         WHERE issuance_id = ?`,
        firstIssuance,
      );
      insertIssuance(sql, attemptId, 2, secondIssuance);
      insertCompactA0Roster(sql, secondIssuance);
      sql.exec(
        `UPDATE activation_operation_issuances
         SET state = 'EXPIRED_UNDISPATCHED', record_committed_at = ?
         WHERE issuance_id = ?`,
        REGISTRY_V2_RECORD_TIME,
        secondIssuance,
      );
      sql.exec(
        `UPDATE activation_operation_issuances SET state = 'READY_TO_APPEND'
         WHERE issuance_id = ?`,
        firstIssuance,
      );
      expect(() =>
        insertRecord(sql, 0, firstIssuance, intentDigest, REGISTRY_V2_RECORD_TIME, "stale"),
      ).toThrow("ACTIVATION_RECORD_OPERATION_BINDING_INVALID");

      sql.exec(
        `UPDATE activation_operation_issuances SET state = 'EXPIRED_UNDISPATCHED'
         WHERE issuance_id = ?`,
        firstIssuance,
      );
      sql.exec(
        `UPDATE activation_operation_issuances SET state = 'READY_TO_APPEND'
         WHERE issuance_id = ?`,
        secondIssuance,
      );
      sql.exec(
        "UPDATE activation_operation_intents SET state = 'HOLD' WHERE attempt_id = ?",
        attemptId,
      );
      expect(() =>
        insertRecord(sql, 0, secondIssuance, intentDigest, REGISTRY_V2_RECORD_TIME, "intent-hold"),
      ).toThrow("ACTIVATION_RECORD_OPERATION_BINDING_INVALID");
      sql.exec(
        "UPDATE activation_operation_intents SET state = 'OPEN' WHERE attempt_id = ?",
        attemptId,
      );
      expect(() =>
        insertRecord(sql, 0, secondIssuance, digest(999), REGISTRY_V2_RECORD_TIME, "digest"),
      ).toThrow("ACTIVATION_RECORD_OPERATION_BINDING_INVALID");
      expect(() =>
        insertRecord(sql, 0, secondIssuance, intentDigest, "2026-08-19T00:00:31.000Z", "time"),
      ).toThrow("ACTIVATION_RECORD_OPERATION_BINDING_INVALID");
      insertRecord(sql, 0, secondIssuance, intentDigest, REGISTRY_V2_RECORD_TIME, "valid");
    });
  });
});
