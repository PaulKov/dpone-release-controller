import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { prepareWormExactObjectEffect } from "../src/worm-exact-object-effect-contract";
import { WormExactObjectEffectStore } from "../src/worm-exact-object-effect-store";
import {
  EFFECT_PINS,
  EFFECT_RETENTION_UNTIL,
  WRITER_VERSION_ID,
  exactEffectInput,
  inventory,
} from "./worm-exact-object-effect.fixtures";

afterEach(async () => {
  await reset();
});

describe("WORM exact-object durable store", () => {
  it("copies exact bytes before hashing and rejects body, clock, and pin drift", async () => {
    const input = await exactEffectInput();
    const original = Uint8Array.from(input.canonicalBytes);
    const stub = env.ACTIVATION_REGISTRY.getByName("worm-exact-seal-drift-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new WormExactObjectEffectStore(state.storage);
      const sealing = store.seal(input);
      input.canonicalBytes.fill(0xff);
      const sealed = await sealing;
      const retry = await store.seal(await exactEffectInput());
      const errors: string[] = [];
      for (const drifted of [
        await exactEffectInput(12),
        { ...(await exactEffectInput()), committedAt: "2026-08-19T12:00:00.001Z" },
        { ...(await exactEffectInput()), pins: alternativePins() },
      ]) {
        try {
          await store.seal(drifted);
        } catch (error) {
          errors.push(String(error));
        }
      }
      try {
        store.snapshot(sealed.effectId, alternativePins());
      } catch (error) {
        errors.push(String(error));
      }
      return {
        bytes: [...sealed.canonicalBytes],
        errors,
        firstEffectId: sealed.effectId,
        retryEffectId: retry.effectId,
        status: retry.status,
      };
    });

    expect(result.bytes).toEqual([...original]);
    expect(result.firstEffectId).toBe(result.retryEffectId);
    expect(result.status).toBe("PREPARED");
    expect(result.errors).toHaveLength(4);
    expect(result.errors.slice(0, 3).join("\n")).toContain(
      "WORM_EXACT_OBJECT_EFFECT_SEAL_CONFLICT",
    );
    expect(result.errors[3]).toContain("WORM_EXACT_OBJECT_EFFECT_PIN_CONFLICT");
  });

  it("enforces exact byte bounds, digest binding, key syntax, and canonical time", async () => {
    const minimum = await prepareWormExactObjectEffect(await exactEffectInput(1));
    const maximum = await prepareWormExactObjectEffect(await exactEffectInput(65_536));
    expect(minimum.canonicalBytes.byteLength).toBe(1);
    expect(maximum.canonicalBytes.byteLength).toBe(65_536);

    const mutable = { ...(await exactEffectInput()) };
    const originalDigest = mutable.digest;
    const originalKey = mutable.key;
    const preparing = prepareWormExactObjectEffect(mutable);
    mutable.digest = `sha256:${"f".repeat(64)}`;
    mutable.key = "unreviewed/mutated-after-call";
    await expect(preparing).resolves.toMatchObject({
      digest: originalDigest,
      key: originalKey,
    });

    const empty = await exactEffectInput(0);
    const tooLarge = await exactEffectInput(65_537);
    const exact = await exactEffectInput();
    for (const invalid of [
      empty,
      tooLarge,
      { ...exact, digest: `sha256:${"0".repeat(64)}` },
      { ...exact, key: "unreviewed/object" },
      { ...exact, committedAt: "2026-08-19T12:00:00Z" },
    ]) {
      await expect(prepareWormExactObjectEffect(invalid)).rejects.toThrow(
        /WORM_EXACT_OBJECT_EFFECT_/u,
      );
    }
  });

  it("never rearms IN_FLIGHT and preserves an accepted writer pin through hold", async () => {
    const input = await exactEffectInput();
    const absenceDigest = (await inventory(input.key, [])).digest;
    const stub = env.ACTIVATION_REGISTRY.getByName("worm-exact-states-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new WormExactObjectEffectStore(state.storage);
      const sealed = await store.seal(input);
      const actions = [store.next(sealed.effectId, sealed.pins).action];
      store.markAbsent(sealed.effectId, sealed.pins, absenceDigest);
      actions.push(store.next(sealed.effectId, sealed.pins).action);
      actions.push(store.next(sealed.effectId, sealed.pins).action);
      store.accept(sealed.effectId, sealed.pins, WRITER_VERSION_ID);
      store.markDispatchedHold(sealed.effectId, sealed.pins);
      const held = store.snapshot(sealed.effectId, sealed.pins);
      const errors: string[] = [];
      try {
        store.confirm(sealed.effectId, sealed.pins, {
          digest: input.digest,
          key: input.key,
          retentionUntil: EFFECT_RETENTION_UNTIL,
          versionId: "wrong-version",
        });
      } catch (error) {
        errors.push(String(error));
      }
      const worm = {
        digest: input.digest,
        key: input.key,
        retentionUntil: EFFECT_RETENTION_UNTIL,
        versionId: WRITER_VERSION_ID,
      };
      store.confirm(sealed.effectId, sealed.pins, worm);
      store.confirm(sealed.effectId, sealed.pins, worm);
      const first = store.confirmed(sealed.effectId, sealed.pins);
      const second = store.confirmed(sealed.effectId, sealed.pins);
      return {
        actions,
        errors,
        first: JSON.stringify(first),
        heldStatus: held.status,
        heldWriterVersionId: held.writerVersionId,
        second: JSON.stringify(second),
      };
    });

    expect(result.actions).toEqual(["CHECK_ABSENCE", "DISPATCH", "RECONCILE"]);
    expect(result.heldStatus).toBe("DISPATCHED_HOLD");
    expect(result.heldWriterVersionId).toBe(WRITER_VERSION_ID);
    expect(result.errors.join("\n")).toContain("WORM_EXACT_OBJECT_EFFECT_WRITER_VERSION_CONFLICT");
    expect(result.first).toBe(result.second);
  });

  it("keeps HOLD reason immutable and never makes a terminal effect dispatchable", async () => {
    const input = await exactEffectInput();
    const stub = env.ACTIVATION_REGISTRY.getByName("worm-exact-hold-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new WormExactObjectEffectStore(state.storage);
      const sealed = await store.seal(input);
      store.hold(sealed.effectId, sealed.pins, "B2_VERSION_HISTORY_CONFLICT");
      store.hold(sealed.effectId, sealed.pins, "B2_VERSION_HISTORY_CONFLICT");
      let conflict = "";
      try {
        store.hold(sealed.effectId, sealed.pins, "B2_VERSION_INVENTORY_INVALID");
      } catch (error) {
        conflict = String(error);
      }
      const next = store.next(sealed.effectId, sealed.pins);
      return { action: next.action, conflict, holdCode: next.effect.holdCode };
    });

    expect(result).toMatchObject({
      action: "STOP_HOLD",
      holdCode: "B2_VERSION_HISTORY_CONFLICT",
    });
    expect(result.conflict).toContain("WORM_EXACT_OBJECT_EFFECT_HOLD_CONFLICT");
  });

  it("serializes identical concurrent seal and dispatch claims to one CAS winner", async () => {
    const input = await exactEffectInput();
    const absenceDigest = (await inventory(input.key, [])).digest;
    const stub = env.ACTIVATION_REGISTRY.getByName("worm-exact-concurrent-cas-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new WormExactObjectEffectStore(state.storage);
      const [left, right] = await Promise.all([store.seal(input), store.seal(input)]);
      store.markAbsent(left.effectId, left.pins, absenceDigest);
      const actions = await Promise.all([
        Promise.resolve().then(() => store.next(left.effectId, left.pins).action),
        Promise.resolve().then(() => store.next(right.effectId, right.pins).action),
      ]);
      return {
        actions: actions.sort(),
        effectIds: [left.effectId, right.effectId],
        status: store.snapshot(left.effectId, left.pins).status,
      };
    });

    expect(result.effectIds[0]).toBe(result.effectIds[1]);
    expect(result.actions).toEqual(["DISPATCH", "RECONCILE"]);
    expect(result.status).toBe("IN_FLIGHT");
  });
});

function alternativePins(): typeof EFFECT_PINS {
  const version = "44444444-4444-4444-8444-444444444444";
  return {
    ...EFFECT_PINS,
    executorServiceIdentity: EFFECT_PINS.executorServiceIdentity.replace(
      EFFECT_PINS.executorVersionId,
      version,
    ),
    executorVersionId: version,
  };
}
