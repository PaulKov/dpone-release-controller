import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { ACTIVATION_COMPONENT_KINDS } from "../src/activation-component-contract";
import type {
  ActivationComponentSetSemanticInput,
  ActivationComponentSetSemanticValidator,
} from "../src/activation-component-journal-contract";
import type { ActivationComponentJournalStore } from "../src/activation-component-journal-store";
import {
  JOURNAL_EFFECT_PINS,
  acceptingJournalValidator,
  journalClock,
  journalRejectDecision,
  journalStore,
  prepareJournalSession,
  stagePreparedJournalSession,
} from "./activation-component-journal.fixtures";

interface Deferred<T> {
  readonly promise: Promise<T>;
  readonly resolve: (value: T | PromiseLike<T>) => void;
}

type EntrySummary = Readonly<{
  readonly count: number;
  readonly effects: number;
}>;

type SelectionSummary = Readonly<{
  readonly selected_session_id: string | null;
  readonly state: string;
}>;

afterEach(async () => {
  await reset();
});

describe("activation component journal asynchronous semantic validation", () => {
  it("keeps authority staged until a delayed ACCEPT and then seals exact local effects", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-async-accept-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const entered = deferred<undefined>();
      const release = deferred<undefined>();
      const closedValidator = acceptingJournalValidator();
      const validator: ActivationComponentSetSemanticValidator = {
        async validate(input) {
          entered.resolve(undefined);
          await release.promise;
          return closedValidator.validate(input);
        },
      };
      const store = journalStore(state.storage, journalClock(), validator);
      const prepared = await prepareJournalSession(store);
      await stagePreparedJournalSession(store, prepared);

      const pending = store.selectAndSeal(prepared.session.sessionId);
      await entered.promise;
      await expectStagedOpen(store, state.storage, prepared.session.sessionId);

      release.resolve(undefined);
      const result = await pending;
      if (result.outcome !== "SEALED") throw new Error("expected sealed selection");
      expect(result.sealed.effects).toHaveLength(ACTIVATION_COMPONENT_KINDS.length);
      expect(new Set(result.sealed.effects.map(({ effectId }) => effectId)).size).toBe(
        ACTIVATION_COMPONENT_KINDS.length,
      );
      expect(await store.sealedPlans(prepared.session.sessionId, JOURNAL_EFFECT_PINS)).toEqual(
        result.sealed,
      );
    });
  });

  it("keeps authority staged until a delayed REJECT and then deletes staged entries", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-async-reject-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const entered = deferred<undefined>();
      const release = deferred<undefined>();
      const validator: ActivationComponentSetSemanticValidator = {
        async validate() {
          entered.resolve(undefined);
          await release.promise;
          return journalRejectDecision();
        },
      };
      const store = journalStore(state.storage, journalClock(), validator);
      const prepared = await prepareJournalSession(store);
      await stagePreparedJournalSession(store, prepared);

      const pending = store.selectAndSeal(prepared.session.sessionId);
      await entered.promise;
      await expectStagedOpen(store, state.storage, prepared.session.sessionId);

      release.resolve(undefined);
      await expect(pending).resolves.toMatchObject({
        outcome: "REJECTED",
        session: {
          stagedCount: 0,
          state: "REJECTED",
          terminalCode: "ACTIVATION_COMPONENT_SET_SEMANTIC_INVALID",
        },
      });
      expect(entrySummary(state.storage, prepared.session.sessionId)).toEqual({
        count: 0,
        effects: 0,
      });
      expect(selectionSummary(state.storage)).toEqual({
        selected_session_id: null,
        state: "OPEN",
      });
    });
  });

  it("preserves STAGED/OPEN with no effects when the validator Promise rejects", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-async-error-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const validator: ActivationComponentSetSemanticValidator = {
        validate: () => Promise.reject(new Error("TEST_ASYNC_VALIDATOR_UNAVAILABLE")),
      };
      const store = journalStore(state.storage, journalClock(), validator);
      const prepared = await prepareJournalSession(store);
      await stagePreparedJournalSession(store, prepared);

      await expect(store.selectAndSeal(prepared.session.sessionId)).rejects.toThrow(
        "TEST_ASYNC_VALIDATOR_UNAVAILABLE",
      );
      await expectStagedOpen(store, state.storage, prepared.session.sessionId);
    });
  });

  it("fails closed when SQL authority drifts while a minted ACCEPT is delayed", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-async-sql-drift-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const entered = deferred<undefined>();
      const release = deferred<undefined>();
      const closedValidator = acceptingJournalValidator();
      const validator: ActivationComponentSetSemanticValidator = {
        async validate(input) {
          const decision = await closedValidator.validate(input);
          entered.resolve(undefined);
          await release.promise;
          return decision;
        },
      };
      const store = journalStore(state.storage, journalClock(), validator);
      const prepared = await prepareJournalSession(store);
      await stagePreparedJournalSession(store, prepared);

      const pending = store.selectAndSeal(prepared.session.sessionId);
      await entered.promise;
      state.storage.sql.exec(
        `UPDATE activation_component_sessions_v2 SET fresh_until = ? WHERE session_id = ?`,
        "2026-08-19T12:15:01.000Z",
        prepared.session.sessionId,
      );
      release.resolve(undefined);

      await expect(pending).rejects.toThrow("ACTIVATION_COMPONENT_JOURNAL_IDENTITY_CONFLICT");
      expect(selectionSummary(state.storage)).toEqual({ selected_session_id: null, state: "OPEN" });
      expect(entrySummary(state.storage, prepared.session.sessionId)).toEqual({
        count: ACTIVATION_COMPONENT_KINDS.length,
        effects: 0,
      });
    });
  });

  it("re-reads owned SQL authority after an async validator mutates its byte snapshots", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-async-mutation-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const closedValidator = acceptingJournalValidator();
      const validator: ActivationComponentSetSemanticValidator = {
        async validate(input: ActivationComponentSetSemanticInput) {
          const decision = await closedValidator.validate(input);
          input.descriptor.canonicalBytes.fill(0);
          for (const envelope of input.envelopes) envelope.canonicalBytes.fill(0);
          await Promise.resolve();
          return decision;
        },
      };
      const store = journalStore(state.storage, journalClock(), validator);
      const prepared = await prepareJournalSession(store);
      const expectedDescriptorBytes = Uint8Array.from(prepared.session.descriptor.canonicalBytes);
      const expectedEnvelopeBytes = prepared.envelopes.map(({ canonicalBytes }) =>
        Uint8Array.from(canonicalBytes),
      );
      await stagePreparedJournalSession(store, prepared);

      const result = await store.selectAndSeal(prepared.session.sessionId);
      if (result.outcome !== "SEALED") throw new Error("expected sealed selection");
      expect((await store.session(prepared.session.sessionId)).descriptor.canonicalBytes).toEqual(
        expectedDescriptorBytes,
      );
      expect(storedEnvelopeBytes(state.storage, prepared.session.sessionId)).toEqual(
        expectedEnvelopeBytes,
      );
      expect(result.sealed.effects).toHaveLength(ACTIVATION_COMPONENT_KINDS.length);
    });
  });

  it("selects one concurrent async winner and exposes its exact sealed plans without a port", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-async-race-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const bothEntered = deferred<undefined>();
      const release = deferred<undefined>();
      let validationCount = 0;
      const closedValidator = acceptingJournalValidator();
      const validator: ActivationComponentSetSemanticValidator = {
        async validate(input) {
          validationCount += 1;
          if (validationCount === 2) bothEntered.resolve(undefined);
          await release.promise;
          return closedValidator.validate(input);
        },
      };
      const store = journalStore(state.storage, journalClock(), validator);
      const left = await prepareJournalSession(store, 1);
      const right = await prepareJournalSession(store, 2);
      await stagePreparedJournalSession(store, left);
      await stagePreparedJournalSession(store, right);

      const pending = [
        store.selectAndSeal(left.session.sessionId),
        store.selectAndSeal(right.session.sessionId),
      ];
      await bothEntered.promise;
      await expectStagedOpen(store, state.storage, left.session.sessionId);
      await expectStagedOpen(store, state.storage, right.session.sessionId);
      release.resolve(undefined);

      const outcomes = await Promise.allSettled(pending);
      const fulfilled = outcomes.filter(
        (outcome): outcome is PromiseFulfilledResult<Awaited<(typeof pending)[number]>> =>
          outcome.status === "fulfilled",
      );
      expect(fulfilled).toHaveLength(1);
      expect(outcomes.filter(({ status }) => status === "rejected")).toHaveLength(1);
      const winner = fulfilled[0]?.value;
      if (winner?.outcome !== "SEALED") throw new Error("expected one sealed winner");
      const selectedSessionId = winner.sealed.session.sessionId;
      const exact = await store.sealedPlans(selectedSessionId, JOURNAL_EFFECT_PINS);
      expect(exact).toEqual(winner.sealed);
      expect(exact.effects).toHaveLength(ACTIVATION_COMPONENT_KINDS.length);
      expect(storedEffectIds(state.storage, selectedSessionId)).toEqual(
        exact.effects.map(({ effectId }) => effectId),
      );
      expect(selectionSummary(state.storage)).toEqual({
        selected_session_id: selectedSessionId,
        state: "COMPONENT_EFFECTS_SEALED",
      });
      const loserSessionId =
        selectedSessionId === left.session.sessionId
          ? right.session.sessionId
          : left.session.sessionId;
      await expect(store.session(loserSessionId)).resolves.toMatchObject({
        stagedCount: 0,
        state: "SUPERSEDED",
      });
    });
  });
});

function deferred<T>(): Deferred<T> {
  let resolve!: Deferred<T>["resolve"];
  const promise = new Promise<T>((promiseResolve) => {
    resolve = promiseResolve;
  });
  return { promise, resolve };
}

async function expectStagedOpen(
  store: ActivationComponentJournalStore,
  storage: DurableObjectStorage,
  sessionId: string,
): Promise<void> {
  await expect(store.session(sessionId)).resolves.toMatchObject({
    stagedCount: ACTIVATION_COMPONENT_KINDS.length,
    state: "STAGED",
    terminalCode: null,
  });
  expect(selectionSummary(storage)).toEqual({ selected_session_id: null, state: "OPEN" });
  expect(entrySummary(storage, sessionId)).toEqual({
    count: ACTIVATION_COMPONENT_KINDS.length,
    effects: 0,
  });
}

function selectionSummary(storage: DurableObjectStorage): SelectionSummary {
  return storage.sql
    .exec<SelectionSummary>(
      `SELECT selected_session_id, state
       FROM activation_component_selection_v2 WHERE singleton = 1`,
    )
    .one();
}

function entrySummary(storage: DurableObjectStorage, sessionId: string): EntrySummary {
  return storage.sql
    .exec<EntrySummary>(
      `SELECT COUNT(*) AS count, COUNT(effect_id) AS effects
       FROM activation_component_session_entries_v2 WHERE session_id = ?`,
      sessionId,
    )
    .one();
}

function storedEnvelopeBytes(storage: DurableObjectStorage, sessionId: string): Uint8Array[] {
  return storage.sql
    .exec<{ readonly envelope_bytes: ArrayBuffer }>(
      `SELECT envelope_bytes FROM activation_component_session_entries_v2
       WHERE session_id = ? ORDER BY ordinal`,
      sessionId,
    )
    .toArray()
    .map(({ envelope_bytes }) => new Uint8Array(envelope_bytes));
}

function storedEffectIds(storage: DurableObjectStorage, sessionId: string): string[] {
  return storage.sql
    .exec<{ readonly effect_id: string }>(
      `SELECT effect_id FROM activation_component_session_entries_v2
       WHERE session_id = ? ORDER BY ordinal`,
      sessionId,
    )
    .toArray()
    .map(({ effect_id }) => effect_id);
}
