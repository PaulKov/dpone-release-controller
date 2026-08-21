import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { ActivationComponentJournalStore } from "../src/activation-component-journal-store";
import {
  type ActivationComponentJournalSchemaCheckpoint,
  initializeActivationComponentJournalSchema,
} from "../src/activation-component-journal-schema";
import {
  JOURNAL_WORKER_VERSION,
  acceptingJournalValidator,
  journalClock,
  journalStore,
  syntheticJournalInput,
} from "./activation-component-journal.fixtures";

afterEach(async () => {
  await reset();
});

describe("activation component journal SQL invariants", () => {
  it("pins one worker version and rejects a conflicting store facade", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-schema-worker-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const clock = journalClock();
      journalStore(state.storage, clock);
      expect(
        () =>
          new ActivationComponentJournalStore(
            state.storage,
            "99999999-9999-4999-8999-999999999999",
            acceptingJournalValidator(),
            clock.now,
          ),
      ).toThrow("ACTIVATION_COMPONENT_JOURNAL_SCHEMA_CONFLICT");
      expect(
        state.storage.sql
          .exec<{ schema_version: number; worker_version_id: string }>(
            `SELECT schema_version, worker_version_id
             FROM activation_component_journal_schema WHERE singleton = 1`,
          )
          .one(),
      ).toEqual({ schema_version: 2, worker_version_id: JOURNAL_WORKER_VERSION });
    });
  });

  it("rejects impossible worker, live-set, roster, status, and selection rows", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-schema-checks-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const store = journalStore(state.storage, journalClock());
      const first = await store.beginInitial(syntheticJournalInput(1));
      const second = await store.beginInitial(syntheticJournalInput(2));
      const sql = state.storage.sql;

      expect(() =>
        sql.exec(
          `UPDATE activation_component_sessions_v2 SET worker_version_id = ?
           WHERE session_id = ?`,
          "99999999-9999-4999-8999-999999999999",
          second.sessionId,
        ),
      ).toThrow();
      expect(() =>
        sql.exec(
          `UPDATE activation_component_sessions_v2 SET set_id = ? WHERE session_id = ?`,
          first.descriptor.setId,
          second.sessionId,
        ),
      ).toThrow();
      expect(() =>
        sql.exec(
          `UPDATE activation_component_sessions_v2 SET generation = 2 WHERE session_id = ?`,
          second.sessionId,
        ),
      ).toThrow();
      expect(() =>
        sql.exec(
          `UPDATE activation_component_sessions_v2 SET state = 'REJECTED'
           WHERE session_id = ?`,
          second.sessionId,
        ),
      ).toThrow();
      expect(() =>
        sql.exec(
          `UPDATE activation_component_session_entries_v2 SET status = 'STAGED'
           WHERE session_id = ? AND ordinal = 0`,
          first.sessionId,
        ),
      ).toThrow();
      expect(() =>
        sql.exec(
          `UPDATE activation_component_session_entries_v2 SET component_kind = 'attacker'
           WHERE session_id = ? AND ordinal = 0`,
          first.sessionId,
        ),
      ).toThrow();
      expect(() =>
        sql.exec(
          `UPDATE activation_component_selection_v2 SET state = 'COMPONENT_EFFECTS_SEALED'
           WHERE singleton = 1`,
        ),
      ).toThrow();

      expect(await store.session(first.sessionId)).toMatchObject({ state: "PROVISIONAL" });
      expect(await store.session(second.sessionId)).toMatchObject({ state: "PROVISIONAL" });
      expect(
        sql
          .exec<{ count: number }>(
            `SELECT COUNT(*) AS count FROM activation_component_session_entries_v2
             WHERE status = 'EXPECTED'`,
          )
          .one().count,
      ).toBe(30);
    });
  });

  it("fails closed when a stamped current-schema table is missing", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-schema-missing-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const clock = journalClock();
      journalStore(state.storage, clock);
      state.storage.sql.exec("DROP TABLE activation_component_session_entries_v2");

      expect(() => journalStore(state.storage, clock)).toThrow(
        "ACTIVATION_COMPONENT_JOURNAL_SCHEMA_TABLE_MISSING",
      );
      expect(
        state.storage.sql
          .exec<{
            worker_version_id: string;
          }>(`SELECT worker_version_id FROM activation_component_journal_schema`)
          .one().worker_version_id,
      ).toBe(JOURNAL_WORKER_VERSION);
    });
  });

  it.each<ActivationComponentJournalSchemaCheckpoint>(["TOPOLOGY_CREATED", "SELECTION_CREATED"])(
    "atomically rolls back and retries initialization after %s",
    async (failurePoint) => {
      const stub = env.AUTH_REPLAY_LEDGER.getByName(
        `component-journal-schema-rollback-${failurePoint.toLowerCase()}`,
      );
      await runInDurableObject(stub, async (_instance, state) => {
        expect(() =>
          initializeActivationComponentJournalSchema(
            state.storage,
            JOURNAL_WORKER_VERSION,
            (checkpoint) => {
              if (checkpoint === failurePoint) throw new Error(`ABORT_${failurePoint}`);
            },
          ),
        ).toThrow(`ABORT_${failurePoint}`);
        expect(
          state.storage.sql
            .exec<{ readonly count: number }>(
              `SELECT COUNT(*) AS count FROM sqlite_schema
             WHERE name LIKE 'activation_component_%'`,
            )
            .one().count,
        ).toBe(0);

        initializeActivationComponentJournalSchema(state.storage, JOURNAL_WORKER_VERSION);
        const store = journalStore(state.storage, journalClock());
        expect(await store.beginInitial(syntheticJournalInput(1))).toMatchObject({
          generation: 1,
          journalOrdinal: 1,
          state: "PROVISIONAL",
        });
      });
    },
  );
});
