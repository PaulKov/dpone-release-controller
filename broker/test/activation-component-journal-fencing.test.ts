import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { ACTIVATION_COMPONENT_JOURNAL_TTL_MS } from "../src/activation-component-journal-contract";
import type { ActivationComponentSetSemanticValidator } from "../src/activation-component-journal-contract";
import {
  acceptingJournalValidator,
  journalClock,
  journalCount,
  journalInitialInput,
  journalStore,
  prepareJournalSession,
  journalRejectDecision,
  stagePreparedJournalSession,
  syntheticJournalInput,
} from "./activation-component-journal.fixtures";

afterEach(async () => {
  await reset();
});

describe("activation component journal validation and fencing", () => {
  it("rejects semantic invalidity locally and leaves another set able to win", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-reject-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      let rejectedSetId = "";
      const closedValidator = acceptingJournalValidator();
      const validator: ActivationComponentSetSemanticValidator = {
        validate: (input) =>
          input.descriptor.setId === rejectedSetId
            ? journalRejectDecision()
            : closedValidator.validate(input),
      };
      const clock = journalClock();
      const store = journalStore(state.storage, clock, validator);
      const rejected = await prepareJournalSession(store, 1);
      const accepted = await prepareJournalSession(store, 2);
      rejectedSetId = rejected.session.descriptor.setId;
      await stagePreparedJournalSession(store, rejected);
      await stagePreparedJournalSession(store, accepted);

      const rejection = await store.selectAndSeal(rejected.session.sessionId);
      if (rejection.outcome !== "REJECTED") throw new Error("expected semantic rejection");
      expect(rejection).toMatchObject({
        outcome: "REJECTED",
        session: {
          stagedCount: 0,
          state: "REJECTED",
          terminalCode: "ACTIVATION_COMPONENT_SET_SEMANTIC_INVALID",
        },
      });
      expect(
        state.storage.sql
          .exec<{ count: number }>(
            `SELECT COUNT(*) AS count FROM activation_component_session_entries_v2
             WHERE session_id = ?`,
            rejected.session.sessionId,
          )
          .one().count,
      ).toBe(0);
      await expect(
        store.reissueExpired({
          predecessorDescriptorId: rejected.session.descriptor.descriptorId,
          predecessorDescriptorSha256: rejected.session.descriptor.descriptorSha256,
          predecessorSessionId: rejected.session.sessionId,
        }),
      ).rejects.toThrow("ACTIVATION_COMPONENT_JOURNAL_REISSUE_INVALID");

      const selection = await store.selectAndSeal(accepted.session.sessionId);
      expect(selection).toMatchObject({ outcome: "SEALED" });
      expect((await store.session(accepted.session.sessionId)).state).toBe("SELECTED");
      clock.milliseconds += ACTIVATION_COMPONENT_JOURNAL_TTL_MS + 1;
      expect(await store.beginInitial(await journalInitialInput(rejected.payloads))).toEqual(
        rejection.session,
      );
      expect(await store.selectAndSeal(rejected.session.sessionId)).toEqual(rejection);
    });
  });

  it("does not turn a validator exception into a terminal rejection", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-validator-throw-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const validator: ActivationComponentSetSemanticValidator = {
        validate() {
          throw new Error("TEST_SEMANTIC_VALIDATOR_UNAVAILABLE");
        },
      };
      const store = journalStore(state.storage, journalClock(), validator);
      const prepared = await prepareJournalSession(store);
      await stagePreparedJournalSession(store, prepared);

      await expect(store.selectAndSeal(prepared.session.sessionId)).rejects.toThrow(
        "TEST_SEMANTIC_VALIDATOR_UNAVAILABLE",
      );
      expect(await store.session(prepared.session.sessionId)).toMatchObject({
        stagedCount: 15,
        state: "STAGED",
        terminalCode: null,
      });
      expect(
        state.storage.sql
          .exec<{
            state: string;
          }>(`SELECT state FROM activation_component_selection_v2 WHERE singleton = 1`)
          .one().state,
      ).toBe("OPEN");
    });
  });

  it("atomically selects one winner, supersedes losers, and reparses sealed bytes", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-winner-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const clock = journalClock();
      const store = journalStore(state.storage, clock);
      const winner = await prepareJournalSession(store, 1);
      const loser = await prepareJournalSession(store, 2);
      await stagePreparedJournalSession(store, winner);
      await stagePreparedJournalSession(store, loser);

      const selected = await store.selectAndSeal(winner.session.sessionId);
      expect(selected).toMatchObject({ outcome: "SEALED" });
      expect(await store.session(loser.session.sessionId)).toMatchObject({
        stagedCount: 0,
        state: "SUPERSEDED",
        terminalCode: "ACTIVATION_COMPONENT_SESSION_SUPERSEDED",
      });
      expect(journalCount(state.storage, "activation_component_session_entries_v2")).toBe(15);
      const sessionStates = state.storage.sql
        .exec<{ state: string }>(
          `SELECT state FROM activation_component_sessions_v2 ORDER BY journal_ordinal`,
        )
        .toArray()
        .map(({ state }) => state);
      expect(sessionStates).toEqual(["SELECTED", "SUPERSEDED"]);

      clock.milliseconds += ACTIVATION_COMPONENT_JOURNAL_TTL_MS + 1;
      expect(await store.beginInitial(await journalInitialInput(loser.payloads))).toMatchObject({
        sessionId: loser.session.sessionId,
        state: "SUPERSEDED",
      });

      const beforeCorruption = await store.sealedPlans(winner.session.sessionId);
      expect(beforeCorruption.effects).toHaveLength(15);
      state.storage.sql.exec(
        `UPDATE activation_component_session_entries_v2 SET envelope_bytes = ?
         WHERE session_id = ? AND ordinal = 0`,
        new Uint8Array([0x7b]).buffer,
        winner.session.sessionId,
      );
      await expect(store.sealedPlans(winner.session.sessionId)).rejects.toThrow(
        "ACTIVATION_COMPONENT_ENVELOPE_INVALID",
      );
    });
  });

  it("rolls back selection, all effects, and loser cleanup when the last seal write aborts", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-rollback-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const store = journalStore(state.storage, journalClock());
      const winner = await prepareJournalSession(store, 1);
      const loser = await prepareJournalSession(store, 2);
      await stagePreparedJournalSession(store, winner);
      await stagePreparedJournalSession(store, loser);
      state.storage.sql.exec(`
        CREATE TRIGGER activation_component_test_abort_last_seal
        BEFORE UPDATE OF status ON activation_component_session_entries_v2
        WHEN NEW.status = 'SEALED' AND NEW.ordinal = 14
        BEGIN
          SELECT RAISE(ABORT, 'TEST_ABORT_LAST_SEAL');
        END;
      `);

      await expect(store.selectAndSeal(winner.session.sessionId)).rejects.toThrow(
        "TEST_ABORT_LAST_SEAL",
      );
      const selection = state.storage.sql
        .exec<{
          selected_session_id: string | null;
          state: string;
        }>(`SELECT selected_session_id, state FROM activation_component_selection_v2`)
        .one();
      expect(selection).toEqual({ selected_session_id: null, state: "OPEN" });
      expect(
        state.storage.sql
          .exec<{
            state: string;
          }>(`SELECT state FROM activation_component_sessions_v2 ORDER BY journal_ordinal`)
          .toArray(),
      ).toEqual([{ state: "STAGED" }, { state: "STAGED" }]);
      const entryState = state.storage.sql
        .exec<{ count: number; effects: number }>(
          `SELECT COUNT(*) AS count, COUNT(effect_id) AS effects
           FROM activation_component_session_entries_v2 WHERE status = 'STAGED'`,
        )
        .one();
      expect(entryState).toEqual({ count: 30, effects: 0 });
    });
  });

  it("allows exactly one winner under concurrent selection attempts", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-cas-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const store = journalStore(state.storage, journalClock());
      const left = await prepareJournalSession(store, 1);
      const right = await prepareJournalSession(store, 2);
      await stagePreparedJournalSession(store, left);
      await stagePreparedJournalSession(store, right);

      const outcomes = await Promise.allSettled([
        store.selectAndSeal(left.session.sessionId),
        store.selectAndSeal(right.session.sessionId),
      ]);
      expect(outcomes.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
      expect(outcomes.filter(({ status }) => status === "rejected")).toHaveLength(1);
      const states = state.storage.sql
        .exec<{
          count: number;
          state: string;
        }>(`SELECT state, COUNT(*) AS count FROM activation_component_sessions_v2 GROUP BY state`)
        .toArray();
      expect(states).toEqual([
        { count: 1, state: "SELECTED" },
        { count: 1, state: "SUPERSEDED" },
      ]);
      expect(journalCount(state.storage, "activation_component_session_entries_v2")).toBe(15);
      await expect(store.beginInitial(syntheticJournalInput(99))).rejects.toThrow(
        "ACTIVATION_COMPONENT_JOURNAL_SELECTION_CLOSED",
      );
    });
  });
});
