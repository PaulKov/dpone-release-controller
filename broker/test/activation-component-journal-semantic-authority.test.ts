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
  journalStore,
  prepareJournalSession,
  stagePreparedJournalSession,
} from "./activation-component-journal.fixtures";

afterEach(async () => {
  await reset();
});

describe("activation component journal semantic authority", () => {
  it("rejects structural, spread, prototype, Proxy, and constructor ACCEPT forgeries", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-accept-forgery-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      let transform: (genuine: object) => unknown = () => "INVALID";
      const closedValidator = acceptingJournalValidator();
      const validator = {
        async validate(input: ActivationComponentSetSemanticInput) {
          const genuine = await closedValidator.validate(input);
          if (genuine.outcome !== "ACCEPT") throw new Error("expected genuine ACCEPT fixture");
          return transform(genuine);
        },
      } as unknown as ActivationComponentSetSemanticValidator;
      const store = journalStore(state.storage, journalClock(), validator);
      const prepared = await prepareJournalSession(store);
      await stagePreparedJournalSession(store, prepared);

      const invalidTransforms: readonly ((genuine: object) => unknown)[] = [
        () => ({ outcome: "ACCEPT", pins: JOURNAL_EFFECT_PINS }),
        (genuine) => ({ ...genuine }),
        (genuine) => new Proxy(genuine, {}),
        (genuine) =>
          Object.create(
            Reflect.getPrototypeOf(genuine),
            Object.getOwnPropertyDescriptors(genuine),
          ) as object,
        (genuine) => {
          const constructor = Reflect.getPrototypeOf(genuine)?.constructor;
          if (typeof constructor !== "function") throw new Error("decision constructor missing");
          return Object.assign(Reflect.construct(constructor, []), genuine) as object;
        },
        () => {
          const accessorDecision = { pins: JOURNAL_EFFECT_PINS };
          Object.defineProperty(accessorDecision, "outcome", {
            enumerable: true,
            get: () => "ACCEPT",
          });
          return accessorDecision;
        },
      ];
      for (const invalid of invalidTransforms) {
        transform = invalid;
        await expect(store.selectAndSeal(prepared.session.sessionId)).rejects.toThrow(
          "ACTIVATION_COMPONENT_JOURNAL_VALIDATOR_INVALID",
        );
        await expectStagedOpen(store, state.storage, prepared.session.sessionId);
      }
    });
  });

  it("rejects a genuine ACCEPT capability transplanted to another descriptor", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-accept-transplant-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const bootstrap = journalStore(state.storage, journalClock());
      const left = await prepareJournalSession(bootstrap, 1);
      const right = await prepareJournalSession(bootstrap, 2);
      const transplanted = await acceptingJournalValidator().validate({
        descriptor: left.session.descriptor,
        envelopes: left.envelopes,
      });
      if (transplanted.outcome !== "ACCEPT") throw new Error("expected genuine ACCEPT fixture");
      const store = journalStore(state.storage, journalClock(), {
        validate: () => transplanted,
      });
      await stagePreparedJournalSession(store, right);

      await expect(store.selectAndSeal(right.session.sessionId)).rejects.toThrow(
        "ACTIVATION_COMPONENT_JOURNAL_SEMANTIC_BINDING_CONFLICT",
      );
      await expectStagedOpen(store, state.storage, right.session.sessionId);
    });
  });
});

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
  expect(
    storage.sql
      .exec<{ readonly selected_session_id: string | null; readonly state: string }>(
        `SELECT selected_session_id, state
         FROM activation_component_selection_v2 WHERE singleton = 1`,
      )
      .one(),
  ).toEqual({ selected_session_id: null, state: "OPEN" });
  expect(
    storage.sql
      .exec<{ readonly effects: number }>(
        `SELECT COUNT(effect_id) AS effects
         FROM activation_component_session_entries_v2 WHERE session_id = ?`,
        sessionId,
      )
      .one().effects,
  ).toBe(0);
}
