import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import {
  journalClock,
  journalStore,
  prepareJournalSession,
  stagePreparedJournalSession,
} from "./activation-component-journal.fixtures";

afterEach(async () => {
  await reset();
});

describe("activation component journal continuation SQL invariants", () => {
  it("enforces the component, manifest, pointer, and terminal transition algebra", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-continuation-schema-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const store = journalStore(state.storage, journalClock());
      const prepared = await prepareJournalSession(store);
      await stagePreparedJournalSession(store, prepared);
      await store.selectAndSeal(prepared.session.sessionId);
      const sql = state.storage.sql;

      expect(() =>
        sql.exec(
          `UPDATE activation_component_selection_v2 SET state = 'COMPONENTS_CONFIRMED'
           WHERE singleton = 1`,
        ),
      ).toThrow("ACTIVATION_COMPONENTS_CONFIRMED_TRANSITION_INVALID");
      expect(() => insertManifest(sql, prepared.session.sessionId)).toThrow(
        "ACTIVATION_COMPONENT_MANIFEST_INSERT_INVALID",
      );

      for (let ordinal = 0; ordinal < 15; ordinal += 1) {
        sql.exec(
          `UPDATE activation_component_session_entries_v2
           SET result_bytes = ?, result_sha256 = ?, status = 'CONFIRMED'
           WHERE session_id = ? AND ordinal = ?`,
          new Uint8Array([ordinal + 1]),
          digest(100 + ordinal),
          prepared.session.sessionId,
          ordinal,
        );
      }
      sql.exec(
        `UPDATE activation_component_selection_v2 SET state = 'COMPONENTS_CONFIRMED'
         WHERE singleton = 1`,
      );
      insertManifest(sql, prepared.session.sessionId);
      expect(() =>
        sql.exec(
          `UPDATE activation_component_selection_v2 SET state = 'CONFIRMED'
           WHERE singleton = 1`,
        ),
      ).toThrow("ACTIVATION_COMPONENT_CONFIRMED_TRANSITION_INVALID");

      sql.exec(
        `UPDATE activation_component_selection_v2 SET state = 'MANIFEST_EFFECT_SEALED'
         WHERE singleton = 1`,
      );
      sql.exec(
        `UPDATE activation_component_manifest_authority_v2
         SET result_bytes = ?, result_sha256 = ?, pointer_bytes = ?, pointer_sha256 = ?,
             status = 'CONFIRMED'
         WHERE session_id = ?`,
        new Uint8Array([1]),
        digest(201),
        new Uint8Array([2]),
        digest(202),
        prepared.session.sessionId,
      );
      sql.exec(
        `UPDATE activation_component_selection_v2 SET state = 'CONFIRMED'
         WHERE singleton = 1`,
      );

      expect(() =>
        sql.exec(
          `UPDATE activation_component_manifest_authority_v2 SET pointer_sha256 = ?
           WHERE session_id = ?`,
          digest(203),
          prepared.session.sessionId,
        ),
      ).toThrow("ACTIVATION_COMPONENT_MANIFEST_IMMUTABLE");
      expect(() =>
        sql.exec(
          `UPDATE activation_component_selection_v2 SET state = 'HOLD', hold_code = ?
           WHERE singleton = 1`,
          "ACTIVATION_COMPONENT_MANIFEST_VERSION_CONFLICT",
        ),
      ).toThrow("ACTIVATION_COMPONENT_SELECTION_TERMINAL_IMMUTABLE");
    });
  });

  it("fails closed on an old or partial candidate schema", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-schema-v1-conflict-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      state.storage.sql.exec(`
        CREATE TABLE activation_component_journal_schema (
          singleton INTEGER PRIMARY KEY,
          schema_version INTEGER NOT NULL,
          worker_version_id TEXT NOT NULL
        ) STRICT;
        INSERT INTO activation_component_journal_schema VALUES (
          1, 1, '11111111-1111-4111-8111-111111111111'
        );
      `);
      expect(() => journalStore(state.storage, journalClock())).toThrow(
        "ACTIVATION_COMPONENT_JOURNAL_SCHEMA_TABLE_MISSING",
      );
    });
  });
});

function insertManifest(sql: SqlStorage, sessionId: string): void {
  sql.exec(
    `INSERT INTO activation_component_manifest_authority_v2(
       session_id, manifest_id, manifest_sha256, manifest_bytes, object_key, effect_id, status
     ) VALUES (?, ?, ?, ?, ?, ?, 'SEALED')`,
    sessionId,
    digest(191),
    digest(192),
    new Uint8Array([123]),
    "receipts/v2/activation-component-manifests/schema-fixture.json",
    digest(193),
  );
}

function digest(value: number): string {
  return `sha256:${value.toString(16).padStart(64, "0")}`;
}
