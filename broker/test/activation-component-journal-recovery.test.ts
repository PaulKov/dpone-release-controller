import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import {
  ACTIVATION_COMPONENT_JOURNAL_TTL_MS,
  type ActivationComponentSetSemanticValidator,
} from "../src/activation-component-journal-contract";
import { ActivationComponentJournalStore } from "../src/activation-component-journal-store";
import {
  JOURNAL_EFFECT_PINS,
  JOURNAL_WORKER_VERSION,
  acceptingJournalValidator,
  journalClock,
  journalCount,
  journalInitialInput,
  journalStore,
  journalRejectDecision,
  prepareJournalSession,
  stagePreparedJournalSession,
  syntheticJournalInput,
} from "./activation-component-journal.fixtures";

afterEach(async () => {
  await reset();
});

describe("activation component journal recovery", () => {
  it("returns the exact selected generation after TTL and rejects pin drift", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-selected-retry-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const clock = journalClock();
      const store = journalStore(state.storage, clock);
      const prepared = await prepareJournalSession(store);
      await stagePreparedJournalSession(store, prepared);
      const sealed = await store.selectAndSeal(prepared.session.sessionId);
      if (sealed.outcome !== "SEALED") throw new Error("expected selected fixture");
      clock.milliseconds += ACTIVATION_COMPONENT_JOURNAL_TTL_MS + 1;

      const retry = await store.beginInitial(await journalInitialInput(prepared.payloads));
      expect(retry).toEqual(sealed.sealed.session);
      expect(retry.state).toBe("SELECTED");
      await expect(store.selectAndSeal(prepared.session.sessionId)).resolves.toEqual(sealed);
      const driftedVersion = "99999999-9999-4999-8999-999999999999";
      const driftedPins = {
        ...JOURNAL_EFFECT_PINS,
        observerServiceIdentity: JOURNAL_EFFECT_PINS.observerServiceIdentity.replace(
          JOURNAL_EFFECT_PINS.observerVersionId,
          driftedVersion,
        ),
        observerVersionId: driftedVersion,
      };
      const forgedStore = journalStore(state.storage, clock, {
        validate: () => ({ outcome: "ACCEPT", pins: driftedPins }),
      });
      await expect(forgedStore.selectAndSeal(prepared.session.sessionId)).rejects.toThrow(
        "ACTIVATION_COMPONENT_JOURNAL_VALIDATOR_INVALID",
      );
      const rejectingStore = journalStore(state.storage, clock, {
        validate: () => journalRejectDecision(),
      });
      await expect(rejectingStore.selectAndSeal(prepared.session.sessionId)).rejects.toThrow(
        "ACTIVATION_COMPONENT_JOURNAL_SEMANTIC_CONFLICT",
      );
      await expect(store.sealedPlans(prepared.session.sessionId, driftedPins)).rejects.toThrow(
        "ACTIVATION_COMPONENT_JOURNAL_PIN_CONFLICT",
      );
      expect(journalCount(state.storage, "activation_component_sessions_v2")).toBe(1);
    });
  });

  it("keeps generation one addressable and collapses concurrent reissue to one successor", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-reissue-race-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const clock = journalClock();
      const store = journalStore(state.storage, clock);
      const input = syntheticJournalInput(1);
      const initial = await store.beginInitial(input);
      clock.milliseconds += ACTIVATION_COMPONENT_JOURNAL_TTL_MS + 1;
      const abandoned = await store.abandonExpired(initial.sessionId);
      const predecessor = {
        predecessorDescriptorId: initial.descriptor.descriptorId,
        predecessorDescriptorSha256: initial.descriptor.descriptorSha256,
        predecessorSessionId: initial.sessionId,
      };
      const [left, right] = await Promise.all([
        store.reissueExpired(predecessor),
        store.reissueExpired(predecessor),
      ]);
      expect(left).toEqual(right);
      expect(await store.beginInitial(input)).toEqual(abandoned);
      expect(journalCount(state.storage, "activation_component_sessions_v2")).toBe(2);
      expect(journalCount(state.storage, "activation_component_session_entries_v2")).toBe(15);

      clock.milliseconds = Date.parse(left.freshUntil) + 1;
      const lostResponseRetry = await store.reissueExpired(predecessor);
      expect(lostResponseRetry).toMatchObject({
        sessionId: left.sessionId,
        state: "ABANDONED",
        terminalCode: "ACTIVATION_COMPONENT_SESSION_EXPIRED",
      });
      expect(journalCount(state.storage, "activation_component_sessions_v2")).toBe(2);
      expect(journalCount(state.storage, "activation_component_session_entries_v2")).toBe(0);
    });
  });

  it("leaves STAGED unchanged for an invalid validator outcome", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-invalid-boundary-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const malformedValidator = {
        validate: () => "MALFORMED",
      } as unknown as ActivationComponentSetSemanticValidator;
      const clock = journalClock();
      const store = journalStore(state.storage, clock, malformedValidator);
      const prepared = await prepareJournalSession(store);
      await stagePreparedJournalSession(store, prepared);
      await expect(store.selectAndSeal(prepared.session.sessionId)).rejects.toThrow(
        "ACTIVATION_COMPONENT_JOURNAL_VALIDATOR_INVALID",
      );
      expect(await store.session(prepared.session.sessionId)).toMatchObject({ state: "STAGED" });
    });
  });

  it("normalizes a failing clock and rejects roster cardinality before admission", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-invalid-input-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const invalidClockStore = new ActivationComponentJournalStore(
        state.storage,
        JOURNAL_WORKER_VERSION,
        acceptingJournalValidator(),
        () => {
          throw new Error("CLOCK_UNAVAILABLE");
        },
      );
      await expect(invalidClockStore.beginInitial(syntheticJournalInput(1))).rejects.toThrow(
        "ACTIVATION_COMPONENT_JOURNAL_TIME_INVALID",
      );
      await expect(invalidClockStore.beginInitial({ components: [] })).rejects.toThrow(
        "ACTIVATION_COMPONENT_JOURNAL_ROSTER_INVALID",
      );
      expect(journalCount(state.storage, "activation_component_sessions_v2")).toBe(0);
    });
  });

  it("rolls back winner, effects, and superseded cleanup when loser deletion aborts", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-loser-rollback-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const store = journalStore(state.storage, journalClock());
      const winner = await prepareJournalSession(store, 1);
      const loser = await prepareJournalSession(store, 2);
      await stagePreparedJournalSession(store, winner);
      await stagePreparedJournalSession(store, loser);
      state.storage.sql.exec(`
        CREATE TRIGGER activation_component_test_abort_loser_cleanup
        BEFORE DELETE ON activation_component_session_entries_v2
        WHEN OLD.session_id = '${loser.session.sessionId}' AND OLD.ordinal = 14
        BEGIN
          SELECT RAISE(ABORT, 'TEST_ABORT_LOSER_CLEANUP');
        END;
      `);

      await expect(store.selectAndSeal(winner.session.sessionId)).rejects.toThrow(
        "TEST_ABORT_LOSER_CLEANUP",
      );
      expect(
        state.storage.sql
          .exec<{
            readonly selected_session_id: string | null;
            readonly state: string;
          }>(`SELECT selected_session_id, state FROM activation_component_selection_v2`)
          .one(),
      ).toEqual({ selected_session_id: null, state: "OPEN" });
      expect(
        state.storage.sql
          .exec<{
            readonly state: string;
          }>(`SELECT state FROM activation_component_sessions_v2 ORDER BY journal_ordinal`)
          .toArray(),
      ).toEqual([{ state: "STAGED" }, { state: "STAGED" }]);
      expect(journalCount(state.storage, "activation_component_session_entries_v2")).toBe(30);
    });
  });
});
