import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { ACTIVATION_COMPONENT_KINDS } from "../src/activation-component-contract";
import { ACTIVATION_COMPONENT_JOURNAL_TTL_MS } from "../src/activation-component-journal-contract";
import type { ActivationComponentSetSemanticInput } from "../src/activation-component-journal-contract";
import {
  JOURNAL_EFFECT_PINS,
  JOURNAL_NOW,
  acceptingJournalValidator,
  journalClock,
  journalCount,
  journalInitialInput,
  journalPayloads,
  journalStore,
  prepareJournalSession,
  syntheticJournalInput,
} from "./activation-component-journal.fixtures";

afterEach(async () => {
  await reset();
});

describe("activation component journal admission and staging", () => {
  it("owns initial input and maps every exact retry to one immutable generation one", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-initial-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const clock = journalClock();
      const store = journalStore(state.storage, clock);
      const stableInput = await journalInitialInput(await journalPayloads());
      const mutableComponents = stableInput.components.map((component) => ({ ...component }));
      const pending = store.beginInitial({ components: mutableComponents });
      mutableComponents.reverse();
      const mutableFirst = mutableComponents[0];
      if (mutableFirst !== undefined) mutableFirst.payloadSha256 = `sha256:${"f".repeat(64)}`;
      const first = await pending;
      const descriptorBytes = Uint8Array.from(first.descriptor.canonicalBytes);

      clock.milliseconds += 30_000;
      const retry = await store.beginInitial(stableInput);
      expect(retry).toEqual(first);
      expect(retry).toMatchObject({
        freshUntil: "2026-08-19T12:15:00.000Z",
        generation: 1,
        journalOrdinal: 1,
        predecessorSessionId: null,
        stagedCount: 0,
        state: "PROVISIONAL",
        terminalCode: null,
      });

      first.descriptor.canonicalBytes.fill(0);
      expect((await store.session(first.sessionId)).descriptor.canonicalBytes).toEqual(
        descriptorBytes,
      );
      const entries = state.storage.sql
        .exec<{ component_kind: string; ordinal: number; status: string }>(
          `SELECT component_kind, ordinal, status
           FROM activation_component_session_entries_v2 ORDER BY ordinal`,
        )
        .toArray();
      expect(entries).toEqual(
        ACTIVATION_COMPONENT_KINDS.map((component_kind, ordinal) => ({
          component_kind,
          ordinal,
          status: "EXPECTED",
        })),
      );
      expect(journalCount(state.storage, "activation_component_sessions_v2")).toBe(1);
    });
  });

  it("stages exactly 15 owned envelopes and seals internally derived effects", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-seal-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      let semanticInput: ActivationComponentSetSemanticInput | undefined;
      const closedValidator = acceptingJournalValidator();
      const validator = {
        async validate(input: ActivationComponentSetSemanticInput) {
          const decision = await closedValidator.validate(input);
          semanticInput = input;
          input.envelopes[0]?.canonicalBytes.fill(0);
          return decision;
        },
      };
      const clock = journalClock();
      const store = journalStore(state.storage, clock, validator);
      const prepared = await prepareJournalSession(store);
      const firstEnvelope = prepared.envelopes[0];
      if (firstEnvelope === undefined) throw new Error("missing journal envelope fixture");
      const mutableEnvelope = Uint8Array.from(firstEnvelope.canonicalBytes);
      const staging = store.stageEnvelope(prepared.session.sessionId, mutableEnvelope);
      mutableEnvelope.fill(0);
      await staging;
      for (const envelope of prepared.envelopes.slice(1)) {
        await store.stageEnvelope(prepared.session.sessionId, envelope.canonicalBytes);
      }
      expect(
        await store.stageEnvelope(prepared.session.sessionId, firstEnvelope.canonicalBytes),
      ).toMatchObject({ stagedCount: 15, state: "STAGED" });

      const selection = await store.selectAndSeal(prepared.session.sessionId);
      if (selection.outcome !== "SEALED") throw new Error("expected sealed selection");
      expect(semanticInput?.envelopes.map(({ componentKind }) => componentKind)).toEqual(
        ACTIVATION_COMPONENT_KINDS,
      );
      expect(selection.sealed).toMatchObject({
        pins: JOURNAL_EFFECT_PINS,
        session: { stagedCount: 15, state: "SELECTED" },
      });
      expect(selection.sealed.effects).toHaveLength(15);
      expect(new Set(selection.sealed.effects.map(({ effectId }) => effectId)).size).toBe(15);

      const firstEffect = selection.sealed.effects[0];
      if (firstEffect === undefined) throw new Error("missing sealed effect");
      const originalEffectBytes = Uint8Array.from(firstEffect.canonicalBytes);
      firstEffect.canonicalBytes.fill(0);
      const reread = await store.sealedPlans(prepared.session.sessionId, JOURNAL_EFFECT_PINS);
      expect(reread.effects[0]?.canonicalBytes).toEqual(originalEffectBytes);
      expect(
        await store.stageEnvelope(prepared.session.sessionId, firstEnvelope.canonicalBytes),
      ).toMatchObject({ state: "SELECTED" });
      const sealedRows = state.storage.sql
        .exec<{ effect_id: string | null; status: string }>(
          `SELECT effect_id, status FROM activation_component_session_entries_v2
           WHERE session_id = ? ORDER BY ordinal`,
          prepared.session.sessionId,
        )
        .toArray();
      expect(sealedRows).toHaveLength(15);
      expect(
        sealedRows.every(({ effect_id, status }) => effect_id !== null && status === "SEALED"),
      ).toBe(true);
    });
  });

  it("keeps the TTL boundary fresh and explicitly reissues one immutable successor", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-reissue-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const clock = journalClock();
      const store = journalStore(state.storage, clock);
      const input = await journalInitialInput(await journalPayloads());
      const initial = await store.beginInitial(input);
      const predecessorBytes = Uint8Array.from(initial.descriptor.canonicalBytes);

      clock.milliseconds = JOURNAL_NOW + ACTIVATION_COMPONENT_JOURNAL_TTL_MS;
      await expect(store.abandonExpired(initial.sessionId)).rejects.toThrow(
        "ACTIVATION_COMPONENT_JOURNAL_SESSION_FRESH",
      );
      clock.milliseconds += 1;
      const abandoned = await store.abandonExpired(initial.sessionId);
      expect(abandoned).toMatchObject({
        stagedCount: 0,
        state: "ABANDONED",
        terminalCode: "ACTIVATION_COMPONENT_SESSION_EXPIRED",
      });
      expect(await store.beginInitial(input)).toEqual(abandoned);

      const reissueInput = {
        predecessorDescriptorId: initial.descriptor.descriptorId,
        predecessorDescriptorSha256: initial.descriptor.descriptorSha256,
        predecessorSessionId: initial.sessionId,
      };
      const successor = await store.reissueExpired(reissueInput);
      clock.milliseconds += 30_000;
      expect(await store.reissueExpired(reissueInput)).toEqual(successor);
      expect(successor).toMatchObject({
        generation: 2,
        journalOrdinal: 2,
        predecessorSessionId: initial.sessionId,
        stagedCount: 0,
        state: "PROVISIONAL",
      });
      expect(successor.descriptor.setId).toBe(initial.descriptor.setId);
      expect(successor.descriptor.descriptorId).not.toBe(initial.descriptor.descriptorId);
      expect((await store.session(initial.sessionId)).descriptor.canonicalBytes).toEqual(
        predecessorBytes,
      );
      expect(journalCount(state.storage, "activation_component_sessions_v2")).toBe(2);
      expect(journalCount(state.storage, "activation_component_session_entries_v2")).toBe(15);
    });
  });

  it("does not persist a successor when the broker clock regresses", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-clock-regression-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const clock = journalClock();
      const store = journalStore(state.storage, clock);
      const initial = await store.beginInitial(syntheticJournalInput(1));
      clock.milliseconds += ACTIVATION_COMPONENT_JOURNAL_TTL_MS + 1;
      await store.abandonExpired(initial.sessionId);
      clock.milliseconds = JOURNAL_NOW - 1;

      await expect(
        store.reissueExpired({
          predecessorDescriptorId: initial.descriptor.descriptorId,
          predecessorDescriptorSha256: initial.descriptor.descriptorSha256,
          predecessorSessionId: initial.sessionId,
        }),
      ).rejects.toThrow();
      expect(journalCount(state.storage, "activation_component_sessions_v2")).toBe(1);
      expect(journalCount(state.storage, "activation_component_session_entries_v2")).toBe(0);
      expect(await store.session(initial.sessionId)).toMatchObject({ state: "ABANDONED" });
    });
  });

  it("enforces four live and eight lifetime sessions without partial admission", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-capacity-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const clock = journalClock();
      const store = journalStore(state.storage, clock);
      for (let variant = 0; variant < 4; variant += 1) {
        await store.beginInitial(syntheticJournalInput(variant));
      }
      await expect(store.beginInitial(syntheticJournalInput(4))).rejects.toThrow(
        "ACTIVATION_COMPONENT_JOURNAL_LIVE_CAPACITY_EXHAUSTED",
      );
      expect(journalCount(state.storage, "activation_component_sessions_v2")).toBe(4);

      clock.milliseconds += ACTIVATION_COMPONENT_JOURNAL_TTL_MS + 1;
      for (let variant = 4; variant < 8; variant += 1) {
        await store.beginInitial(syntheticJournalInput(variant));
      }
      await expect(store.beginInitial(syntheticJournalInput(8))).rejects.toThrow(
        "ACTIVATION_COMPONENT_JOURNAL_LIFETIME_EXHAUSTED",
      );
      const states = state.storage.sql
        .exec<{
          count: number;
          state: string;
        }>(`SELECT state, COUNT(*) AS count FROM activation_component_sessions_v2 GROUP BY state`)
        .toArray();
      expect(states).toEqual([
        { count: 4, state: "ABANDONED" },
        { count: 4, state: "PROVISIONAL" },
      ]);
      expect(journalCount(state.storage, "activation_component_sessions_v2")).toBe(8);
      expect(journalCount(state.storage, "activation_component_session_entries_v2")).toBe(60);
    });
  });
});
