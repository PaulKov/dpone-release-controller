import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { assertExactObjectAbsent } from "../src/b2-exact-reconciliation";
import { WormExactObjectEffectRunner } from "../src/worm-exact-object-effect-runner";
import { WormExactObjectEffectStore } from "../src/worm-exact-object-effect-store";
import type { WormExactObjectEffectInput } from "../src/worm-exact-object-effect-contract";
import {
  EFFECT_RETENTION_UNTIL,
  FakeExactObjectB2,
  WRITER_VERSION_ID,
  contentSha1,
  exactEffectInput,
  type ExactObjectFailureMode,
} from "./worm-exact-object-effect.fixtures";

afterEach(async () => {
  await reset();
});

describe("WORM exact-object crash-safe runner", () => {
  it("seals bytes before the first provider call and returns byte-identical retries", async () => {
    const input = await exactEffectInput();
    const stub = env.ACTIVATION_REGISTRY.getByName("worm-exact-runner-success-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new WormExactObjectEffectStore(state.storage);
      const fake = new FakeExactObjectB2();
      const providerEntryStates: string[] = [];
      const writerEntryStates: string[] = [];
      fake.onObserve = () => {
        const row = state.storage.sql
          .exec<{
            readonly bytes: ArrayBuffer;
            readonly status: string;
          }>(`SELECT canonical_bytes AS bytes, status FROM worm_exact_object_effect`)
          .one();
        providerEntryStates.push(`${row.status}:${new Uint8Array(row.bytes).byteLength}`);
      };
      fake.onWrite = () => {
        const row = state.storage.sql
          .exec<{ readonly absence: string | null; readonly status: string }>(
            `SELECT absence_inventory_digest AS absence, status
             FROM worm_exact_object_effect`,
          )
          .one();
        writerEntryStates.push(`${row.status}:${row.absence ?? "NULL"}`);
      };
      const runner = new WormExactObjectEffectRunner(store, fake.writer, fake.observer);
      const first = await runner.execute(input);
      const providerCalls = { observer: fake.observerCalls, writer: fake.writerCalls };
      const second = await runner.execute(await exactEffectInput());
      return {
        first: JSON.stringify(first),
        providerCalls,
        providerCallsAfterRetry: { observer: fake.observerCalls, writer: fake.writerCalls },
        providerEntryStates,
        second: JSON.stringify(second),
        writerEntryStates,
      };
    });

    expect(result.providerEntryStates[0]).toMatch(/^PREPARED:[1-9][0-9]*$/u);
    expect(result.providerEntryStates).toContainEqual(expect.stringMatching(/^ACCEPTED:/u));
    expect(result.writerEntryStates).toEqual([
      expect.stringMatching(/^IN_FLIGHT:sha256:[0-9a-f]{64}$/u),
    ]);
    expect(result.providerCalls).toEqual({ observer: 2, writer: 1 });
    expect(result.providerCallsAfterRetry).toEqual(result.providerCalls);
    expect(result.first).toBe(result.second);
  });

  it("recovers a successful write whose response was lost using only the observer", async () => {
    const input = await exactEffectInput();
    const stub = env.ACTIVATION_REGISTRY.getByName("worm-exact-response-loss-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new WormExactObjectEffectStore(state.storage);
      const fake = new FakeExactObjectB2();
      fake.setMode("RESPONSE_LOSS");
      const confirmed = await new WormExactObjectEffectRunner(
        store,
        fake.writer,
        fake.observer,
      ).execute(input);
      return {
        status: store.snapshot(confirmed.effectId, confirmed.pins).status,
        versionId: confirmed.worm.versionId,
        writerCalls: fake.writerCalls,
      };
    });

    expect(result).toEqual({
      status: "CONFIRMED",
      versionId: WRITER_VERSION_ID,
      writerCalls: 1,
    });
  });

  it("turns observer-zero into DISPATCHED_HOLD and never uploads on retries", async () => {
    const input = await exactEffectInput();
    const stub = env.ACTIVATION_REGISTRY.getByName("worm-exact-zero-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new WormExactObjectEffectStore(state.storage);
      const fake = new FakeExactObjectB2();
      fake.setMode("PRE_WRITE_ERROR");
      const runner = new WormExactObjectEffectRunner(store, fake.writer, fake.observer);
      const errors: string[] = [];
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          await runner.execute(input);
        } catch (error) {
          errors.push(String(error));
        }
      }
      const sealed = await store.seal(input);
      return {
        errors,
        nextAction: store.next(sealed.effectId, sealed.pins).action,
        status: store.snapshot(sealed.effectId, sealed.pins).status,
        writerCalls: fake.writerCalls,
      };
    });

    expect(result.writerCalls).toBe(1);
    expect(result.status).toBe("DISPATCHED_HOLD");
    expect(result.nextAction).toBe("RECONCILE");
    expect(result.errors).toHaveLength(3);
    expect(result.errors.join("\n")).toContain("B2_RECONCILIATION_PENDING");
  });

  it.each<[ExactObjectFailureMode, string]>([
    ["DUPLICATE", "B2_RECONCILIATION_DUPLICATE_DISPATCH"],
    ["WRONG_LATEST", "B2_VERSION_INVENTORY_INVALID"],
    ["DIVERGENT", "B2_VERSION_HISTORY_CONFLICT"],
  ])("moves %s observer evidence to immutable HOLD", async (mode, code) => {
    const input = await exactEffectInput();
    const stub = env.ACTIVATION_REGISTRY.getByName(`worm-exact-hold-${mode.toLowerCase()}`);
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new WormExactObjectEffectStore(state.storage);
      const fake = new FakeExactObjectB2();
      fake.setMode(mode);
      const runner = new WormExactObjectEffectRunner(store, fake.writer, fake.observer);
      let firstError = "";
      let retryError = "";
      try {
        await runner.execute(input);
      } catch (error) {
        firstError = String(error);
      }
      const sealed = await store.seal(input);
      try {
        await runner.execute(input);
      } catch (error) {
        retryError = String(error);
      }
      const held = store.snapshot(sealed.effectId, sealed.pins);
      return {
        firstError,
        holdCode: held.holdCode,
        retryError,
        status: held.status,
        writerCalls: fake.writerCalls,
      };
    });

    expect(result.firstError).toContain(code);
    expect(result).toMatchObject({ holdCode: code, status: "HOLD", writerCalls: 1 });
    expect(result.retryError).toContain(code);
  });

  it("resumes every durable crash boundary without an alternate write", async () => {
    const cases = [
      "OBSERVED_BEFORE_MARK",
      "ABSENT",
      "IN_FLIGHT_BEFORE_WRITE",
      "WRITTEN_BEFORE_ACCEPT",
      "ACCEPTED",
      "CONFIRMED_RESPONSE_LOSS",
    ] as const;
    const results: Record<string, { readonly status: string; readonly writes: number }> = {};
    for (const boundary of cases) {
      const input = await exactEffectInput();
      const stub = env.ACTIVATION_REGISTRY.getByName(
        `worm-exact-boundary-${boundary.toLowerCase().replaceAll("_", "-")}`,
      );
      results[boundary] = await runInDurableObject(stub, async (_instance, state) =>
        exerciseBoundary(state.storage, input, boundary),
      );
    }

    expect(results).toEqual({
      ABSENT: { status: "CONFIRMED", writes: 1 },
      ACCEPTED: { status: "CONFIRMED", writes: 1 },
      CONFIRMED_RESPONSE_LOSS: { status: "CONFIRMED", writes: 1 },
      IN_FLIGHT_BEFORE_WRITE: { status: "DISPATCHED_HOLD", writes: 0 },
      OBSERVED_BEFORE_MARK: { status: "CONFIRMED", writes: 1 },
      WRITTEN_BEFORE_ACCEPT: { status: "CONFIRMED", writes: 1 },
    });
  });

  it("converges concurrent identical executions with exactly one writer call", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("worm-exact-concurrent-runner-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new WormExactObjectEffectStore(state.storage);
      const fake = new FakeExactObjectB2();
      const runner = new WormExactObjectEffectRunner(store, fake.writer, fake.observer);
      const settled = await Promise.allSettled([
        runner.execute(await exactEffectInput()),
        runner.execute(await exactEffectInput()),
      ]);
      const final = await runner.execute(await exactEffectInput());
      return {
        fulfilled: settled.filter((item) => item.status === "fulfilled").length,
        status: store.snapshot(final.effectId, final.pins).status,
        writerCalls: fake.writerCalls,
      };
    });

    expect(result.fulfilled).toBeGreaterThanOrEqual(1);
    expect(result.status).toBe("CONFIRMED");
    expect(result.writerCalls).toBe(1);
  });
});

async function exerciseBoundary(
  storage: DurableObjectStorage,
  input: WormExactObjectEffectInput,
  boundary:
    | "ABSENT"
    | "ACCEPTED"
    | "CONFIRMED_RESPONSE_LOSS"
    | "IN_FLIGHT_BEFORE_WRITE"
    | "OBSERVED_BEFORE_MARK"
    | "WRITTEN_BEFORE_ACCEPT",
): Promise<{ readonly status: string; readonly writes: number }> {
  const store = new WormExactObjectEffectStore(storage);
  const fake = new FakeExactObjectB2();
  const sealed = await store.seal(input);
  const exact = {
    bytes: Uint8Array.from(input.canonicalBytes),
    committedAt: input.committedAt,
    contentSha1: await contentSha1(input.canonicalBytes),
    digest: input.digest,
    key: input.key,
  };
  const absenceDigest = await assertExactObjectAbsent({ ...exact, observer: fake.observer });
  if (boundary !== "OBSERVED_BEFORE_MARK") {
    store.markAbsent(sealed.effectId, sealed.pins, absenceDigest);
  }
  if (
    boundary === "IN_FLIGHT_BEFORE_WRITE" ||
    boundary === "WRITTEN_BEFORE_ACCEPT" ||
    boundary === "ACCEPTED" ||
    boundary === "CONFIRMED_RESPONSE_LOSS"
  ) {
    expect(store.next(sealed.effectId, sealed.pins).action).toBe("DISPATCH");
  }
  if (
    boundary === "WRITTEN_BEFORE_ACCEPT" ||
    boundary === "ACCEPTED" ||
    boundary === "CONFIRMED_RESPONSE_LOSS"
  ) {
    await fake.writer.uploadExact({
      canonicalBytes: exact.bytes,
      contentSha1: exact.contentSha1,
      digest: exact.digest,
      key: exact.key,
    });
  }
  if (boundary === "ACCEPTED" || boundary === "CONFIRMED_RESPONSE_LOSS") {
    store.accept(sealed.effectId, sealed.pins, WRITER_VERSION_ID);
  }
  if (boundary === "CONFIRMED_RESPONSE_LOSS") {
    store.confirm(sealed.effectId, sealed.pins, {
      digest: input.digest,
      key: input.key,
      retentionUntil: EFFECT_RETENTION_UNTIL,
      versionId: WRITER_VERSION_ID,
    });
  }
  const runner = new WormExactObjectEffectRunner(store, fake.writer, fake.observer);
  try {
    await runner.execute(input);
  } catch (error) {
    if (boundary !== "IN_FLIGHT_BEFORE_WRITE") throw error;
  }
  return {
    status: store.snapshot(sealed.effectId, sealed.pins).status,
    writes: fake.writerCalls,
  };
}
