import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import type { PreparedWormExactObjectEffect } from "../src/worm-exact-object-effect-contract";
import { COMPONENT_RETENTION_UNTIL, resultBytes } from "./activation-component-manifest.fixtures";
import {
  JOURNAL_EFFECT_PINS,
  journalClock,
  journalStore,
  prepareJournalSession,
  stagePreparedJournalSession,
} from "./activation-component-journal.fixtures";

afterEach(async () => {
  await reset();
});

describe("activation component journal continuation", () => {
  it("confirms 15 exact effects, seals the manifest, and freezes one final pointer", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-continuation-happy-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const store = journalStore(state.storage, journalClock());
      const prepared = await prepareJournalSession(store);
      await stagePreparedJournalSession(store, prepared);
      const selected = await store.selectAndSeal(prepared.session.sessionId);
      if (selected.outcome !== "SEALED") throw new Error("expected journal selection");

      const effects = [...selected.sealed.effects].reverse();
      for (const [index, effect] of effects.entries()) {
        const pending = await store.confirmComponentEffect(
          prepared.session.sessionId,
          effect.effectId,
          componentResult(effect, 14 - index),
        );
        expect(pending.effects).toHaveLength(14 - index);
      }
      expect(await store.unresolvedComponentEffects(prepared.session.sessionId)).toMatchObject({
        effects: [],
        pins: JOURNAL_EFFECT_PINS,
      });

      const sealedManifest = await store.sealManifestEffect(prepared.session.sessionId);
      if (sealedManifest.outcome !== "SEALED") throw new Error("expected manifest seal");
      const manifestResult = resultBytes(
        sealedManifest.sealed.effect,
        {
          digest: sealedManifest.sealed.effect.digest,
          key: sealedManifest.sealed.effect.key,
          retentionUntil: COMPONENT_RETENTION_UNTIL,
          versionId: "4_z-journal-manifest-0001",
        },
        950,
      );
      const confirmed = await store.confirmManifestEffect(
        prepared.session.sessionId,
        sealedManifest.sealed.effect.effectId,
        manifestResult,
      );
      if (confirmed.outcome !== "CONFIRMED") throw new Error("expected manifest confirmation");
      const pointerBytes = Uint8Array.from(confirmed.authority.canonicalPointerBytes);
      confirmed.authority.canonicalPointerBytes.fill(0);
      const reread = await store.confirmedAuthority(prepared.session.sessionId);
      expect(reread.canonicalPointerBytes).toEqual(pointerBytes);
      expect(reread).toMatchObject({
        descriptor: {
          descriptorId: prepared.session.descriptor.descriptorId,
          setId: prepared.session.descriptor.setId,
        },
        session: { sessionId: prepared.session.sessionId, state: "SELECTED" },
        trust: "CONFIRMED_JOURNAL",
      });
      expect(
        state.storage.sql
          .exec<{
            readonly state: string;
          }>(`SELECT state FROM activation_component_selection_v2 WHERE singleton = 1`)
          .one().state,
      ).toBe("CONFIRMED");
    });
  });
});

function componentResult(effect: PreparedWormExactObjectEffect, ordinal: number): Uint8Array {
  return resultBytes(
    effect,
    {
      digest: effect.digest,
      key: effect.key,
      retentionUntil: COMPONENT_RETENTION_UNTIL,
      versionId: `4_z-journal-component-${String(ordinal).padStart(2, "0")}`,
    },
    700 + ordinal,
  );
}
