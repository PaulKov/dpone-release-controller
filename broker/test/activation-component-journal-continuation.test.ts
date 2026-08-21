import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { ACTIVATION_COMPONENT_KINDS } from "../src/activation-component-contract";
import { parseActivationComponentManifestPointer } from "../src/activation-component-manifest";
import {
  componentResults,
  componentVersion,
  confirmComponents,
  confirmManifest,
  continuationManifest,
  continuationResultBytes,
  continuationSelection,
  manifestResultBytes,
  sealManifest,
  selectedContinuationFixture,
} from "./activation-component-journal-continuation.fixtures";

afterEach(async () => {
  await reset();
});

describe("activation component journal continuation", () => {
  it("confirms all 15 components in reverse, seals the manifest, and exposes final authority", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-continuation-happy-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await selectedContinuationFixture(state.storage);
      const results = componentResults(fixture.sealed);
      for (let ordinal = ACTIVATION_COMPONENT_KINDS.length - 1; ordinal >= 0; ordinal -= 1) {
        const effect = required(fixture.sealed.effects[ordinal]);
        const unresolved = await fixture.store.confirmComponentEffect(
          fixture.prepared.session.sessionId,
          effect.effectId,
          required(results[ordinal]),
        );
        expect(unresolved.effects).toHaveLength(ordinal);
      }

      const manifestSeal = await sealManifest(fixture);
      const manifestBytes = manifestResultBytes(manifestSeal);
      const confirmation = await confirmManifest(fixture, manifestSeal, manifestBytes);
      if (confirmation.outcome !== "CONFIRMED") throw new Error("expected confirmed manifest");
      const authority = confirmation.authority;
      const pointer = parseActivationComponentManifestPointer(authority.canonicalPointerBytes);
      expect(authority.pointerSha256).toMatch(/^sha256:[0-9a-f]{64}$/u);
      expect(authority).toMatchObject({
        session: { state: "SELECTED" },
        trust: "CONFIRMED_JOURNAL",
      });
      expect(pointer).toMatchObject({
        manifestSha256: manifestSeal.effect.digest,
        setId: fixture.prepared.session.descriptor.setId,
        workerVersionId: fixture.prepared.session.descriptor.workerVersionId,
      });

      await expect(
        fixture.store.confirmComponentEffect(
          fixture.prepared.session.sessionId,
          required(fixture.sealed.effects[14]).effectId,
          required(results[14]),
        ),
      ).resolves.toMatchObject({ effects: [] });
      await expect(
        fixture.store.sealManifestEffect(fixture.prepared.session.sessionId),
      ).resolves.toMatchObject({
        outcome: "CONFIRMED",
      });
      await expect(
        fixture.store.confirmManifestEffect(
          fixture.prepared.session.sessionId,
          manifestSeal.effect.effectId,
          manifestBytes,
        ),
      ).resolves.toMatchObject({ outcome: "CONFIRMED" });

      const pointerBytes = Uint8Array.from(authority.canonicalPointerBytes);
      authority.canonicalPointerBytes.fill(0);
      expect(
        (await fixture.store.confirmedAuthority(fixture.prepared.session.sessionId))
          .canonicalPointerBytes,
      ).toEqual(pointerBytes);
    });
  });

  it("accepts exact retries and rejects divergent or transplanted component and manifest results", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-continuation-divergence-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await selectedContinuationFixture(state.storage);
      const results = componentResults(fixture.sealed);
      const first = required(fixture.sealed.effects[0]);
      const second = required(fixture.sealed.effects[1]);
      await fixture.store.confirmComponentEffect(
        fixture.prepared.session.sessionId,
        first.effectId,
        required(results[0]),
      );
      await expect(
        fixture.store.confirmComponentEffect(
          fixture.prepared.session.sessionId,
          first.effectId,
          required(results[0]),
        ),
      ).resolves.toBeDefined();
      await expect(
        fixture.store.confirmComponentEffect(
          fixture.prepared.session.sessionId,
          first.effectId,
          continuationResultBytes(first, componentVersion(0), 9_999),
        ),
      ).rejects.toThrow("ACTIVATION_COMPONENT_JOURNAL_RESULT_CONFLICT");
      await expect(
        fixture.store.confirmComponentEffect(
          fixture.prepared.session.sessionId,
          second.effectId,
          required(results[0]),
        ),
      ).rejects.toThrow("WORM_EXACT_OBJECT_EFFECT_RESULT_INVALID");

      await confirmComponents(fixture);
      const manifestSeal = await sealManifest(fixture);
      await expect(confirmManifest(fixture, manifestSeal, required(results[0]))).rejects.toThrow(
        "WORM_EXACT_OBJECT_EFFECT_RESULT_INVALID",
      );
      const manifestBytes = manifestResultBytes(manifestSeal);
      await expect(confirmManifest(fixture, manifestSeal, manifestBytes)).resolves.toMatchObject({
        outcome: "CONFIRMED",
      });
      await expect(
        confirmManifest(fixture, manifestSeal, manifestResultBytes(manifestSeal, undefined, 9_999)),
      ).rejects.toThrow("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_RESULT_CONFLICT");
    });
  });

  it("collapses concurrent exact last-component, manifest-seal, and manifest-confirm calls", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-continuation-concurrent-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await selectedContinuationFixture(state.storage);
      const results = componentResults(fixture.sealed);
      for (let ordinal = 0; ordinal < 14; ordinal += 1) {
        await fixture.store.confirmComponentEffect(
          fixture.prepared.session.sessionId,
          required(fixture.sealed.effects[ordinal]).effectId,
          required(results[ordinal]),
        );
      }
      const last = required(fixture.sealed.effects[14]);
      const lastOutcomes = await Promise.all([
        fixture.store.confirmComponentEffect(
          fixture.prepared.session.sessionId,
          last.effectId,
          required(results[14]),
        ),
        fixture.store.confirmComponentEffect(
          fixture.prepared.session.sessionId,
          last.effectId,
          required(results[14]),
        ),
      ]);
      expect(lastOutcomes.every(({ effects }) => effects.length === 0)).toBe(true);

      const seals = await Promise.all([
        fixture.store.sealManifestEffect(fixture.prepared.session.sessionId),
        fixture.store.sealManifestEffect(fixture.prepared.session.sessionId),
      ]);
      expect(seals.every(({ outcome }) => outcome === "SEALED")).toBe(true);
      const firstSeal = seals[0];
      if (firstSeal.outcome !== "SEALED") throw new Error("expected sealed manifest");
      const manifestBytes = manifestResultBytes(firstSeal.sealed);
      const confirmations = await Promise.all([
        confirmManifest(fixture, firstSeal.sealed, manifestBytes),
        confirmManifest(fixture, firstSeal.sealed, manifestBytes),
      ]);
      expect(confirmations.every(({ outcome }) => outcome === "CONFIRMED")).toBe(true);
      expect(continuationSelection(state.storage)).toEqual({ hold_code: null, state: "CONFIRMED" });
    });
  });

  it("enters terminal component-version HOLD before creating a manifest", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-continuation-component-hold-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await selectedContinuationFixture(state.storage);
      const results = await confirmComponents(fixture, undefined, (ordinal) =>
        ordinal < 2 ? "4_z-component-version-collision" : componentVersion(ordinal),
      );
      const held = await fixture.store.sealManifestEffect(fixture.prepared.session.sessionId);
      expect(held).toMatchObject({
        held: { holdCode: "ACTIVATION_COMPONENT_WORM_VERSION_CONFLICT" },
        outcome: "HOLD",
      });
      expect(
        continuationManifest(state.storage, fixture.prepared.session.sessionId),
      ).toBeUndefined();
      await expect(
        fixture.store.confirmComponentEffect(
          fixture.prepared.session.sessionId,
          required(fixture.sealed.effects[0]).effectId,
          required(results[0]),
        ),
      ).resolves.toMatchObject({ effects: [] });
      await expect(
        fixture.store.sealManifestEffect(fixture.prepared.session.sessionId),
      ).resolves.toEqual(held);
      await expect(
        fixture.store.confirmedAuthority(fixture.prepared.session.sessionId),
      ).rejects.toThrow("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_MISSING");
      expect(() =>
        state.storage.sql.exec(
          `UPDATE activation_component_selection_v2 SET state = 'CONFIRMED', hold_code = NULL`,
        ),
      ).toThrow();
    });
  });

  it("enters terminal manifest-version HOLD without emitting a compact pointer", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-continuation-manifest-hold-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await selectedContinuationFixture(state.storage);
      await confirmComponents(fixture);
      const manifestSeal = await sealManifest(fixture);
      const colliding = manifestResultBytes(manifestSeal, componentVersion(0));
      const held = await confirmManifest(fixture, manifestSeal, colliding);
      expect(held).toMatchObject({
        held: { holdCode: "ACTIVATION_COMPONENT_MANIFEST_VERSION_CONFLICT" },
        outcome: "HOLD",
      });
      expect(continuationManifest(state.storage, fixture.prepared.session.sessionId)).toMatchObject(
        {
          pointer_bytes: null,
          pointer_sha256: null,
          status: "RESULT_CONFIRMED",
        },
      );
      await expect(confirmManifest(fixture, manifestSeal, colliding)).resolves.toEqual(held);
      await expect(
        confirmManifest(
          fixture,
          manifestSeal,
          manifestResultBytes(manifestSeal, componentVersion(0), 9_999),
        ),
      ).rejects.toThrow("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_RESULT_CONFLICT");
      await expect(
        fixture.store.sealManifestEffect(fixture.prepared.session.sessionId),
      ).resolves.toMatchObject({
        outcome: "HOLD",
      });
      await expect(
        fixture.store.confirmedAuthority(fixture.prepared.session.sessionId),
      ).rejects.toThrow("ACTIVATION_COMPONENT_JOURNAL_NOT_CONFIRMED");
    });
  });
});

function required<T>(value: T | undefined | null): T {
  if (value === undefined || value === null) throw new Error("continuation fixture value missing");
  return value;
}
