import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { cloudflareEvidenceWormKey } from "../src/cloudflare-evidence-batch-contract";
import { buildCloudflareEvidenceBatchResult } from "../src/cloudflare-evidence-batch-result";
import { CloudflareEvidenceBatchStore } from "../src/cloudflare-evidence-batch-store";
import { canonicalJson } from "../src/canonical";
import { CloudflareEvidenceBatchRunner } from "../src/private/cloudflare-evidence-batch-runner";
import {
  BATCH_COMMITTED_AT,
  BATCH_OBSERVED_AT,
  cloudflareEvidenceBatchExecution,
  cloudflareEvidenceBatchFixture,
} from "./cloudflare-evidence-batch.fixtures";
import { CloudflareEvidenceBatchFakeB2 } from "./cloudflare-evidence-batch-runner.fixtures";

afterEach(async () => {
  await reset();
});

describe("Cloudflare evidence batch effect runner", () => {
  it("seals all fifteen slots before writing and reconciles a lost PUT response exactly once", async () => {
    const fixture = await cloudflareEvidenceBatchFixture();
    const fake = new CloudflareEvidenceBatchFakeB2();
    const targetKey = slotKey(fixture.slots[7]);
    fake.fail(targetKey, "PUT_LOSS");
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-runner-put-loss-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new CloudflareEvidenceBatchStore(state.storage);
      await expect(
        new CloudflareEvidenceBatchRunner(store, fake.writer, fake.observer).run(),
      ).rejects.toThrow("CLOUDFLARE_EVIDENCE_BATCH_MISSING");
      expect(fake.totalWrites()).toBe(0);
      await seal(store, fixture);
      const firstSlots = await new CloudflareEvidenceBatchRunner(
        store,
        fake.writer,
        fake.observer,
      ).run();
      const firstContext = requireContext(
        store.resume(fixture.binding.batchId, cloudflareEvidenceBatchExecution()),
      );
      const firstResult = canonicalJson(
        buildCloudflareEvidenceBatchResult(firstContext, firstSlots),
      );
      const resumedSlots = await new CloudflareEvidenceBatchRunner(
        store,
        fake.writer,
        fake.observer,
      ).run();
      const resumedContext = requireContext(
        store.resume(fixture.binding.batchId, cloudflareEvidenceBatchExecution()),
      );
      return {
        firstResult,
        resumedResult: canonicalJson(
          buildCloudflareEvidenceBatchResult(resumedContext, resumedSlots),
        ),
        slots: resumedSlots.length,
      };
    });

    expect(result.slots).toBe(15);
    expect(result.resumedResult).toBe(result.firstResult);
    expect(fake.totalWrites()).toBe(15);
    expect(fake.writesFor(targetKey)).toBe(1);
  });

  it("resumes an in-flight slot after observer response loss without a second write", async () => {
    const fixture = await cloudflareEvidenceBatchFixture();
    const fake = new CloudflareEvidenceBatchFakeB2();
    const targetKey = slotKey(fixture.slots[7]);
    fake.fail(targetKey, "OBSERVER_LOSS");
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-runner-observer-loss-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new CloudflareEvidenceBatchStore(state.storage);
      await seal(store, fixture);
      await expect(
        new CloudflareEvidenceBatchRunner(store, fake.writer, fake.observer).run(),
      ).rejects.toThrow("simulated observer response loss");
      const writesAfterLoss = fake.totalWrites();
      const resumed = await new CloudflareEvidenceBatchRunner(
        store,
        fake.writer,
        fake.observer,
      ).run();
      return { resumed: resumed.length, writesAfterLoss };
    });

    expect(result).toEqual({ resumed: 15, writesAfterLoss: 15 });
    expect(fake.totalWrites()).toBe(15);
    expect(fake.writesFor(targetKey)).toBe(1);
  });

  it("keeps a zero-version ambiguity in-flight and never redispatches it", async () => {
    const fixture = await cloudflareEvidenceBatchFixture();
    const fake = new CloudflareEvidenceBatchFakeB2();
    const targetKey = slotKey(fixture.slots[7]);
    fake.fail(targetKey, "ZERO");
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-runner-zero-0001");
    const messages = await runInDurableObject(stub, async (_instance, state) => {
      const store = new CloudflareEvidenceBatchStore(state.storage);
      await seal(store, fixture);
      const errors: string[] = [];
      for (let retry = 0; retry < 2; retry += 1) {
        try {
          await new CloudflareEvidenceBatchRunner(store, fake.writer, fake.observer).run();
        } catch (error) {
          errors.push(String(error));
        }
      }
      return errors;
    });

    expect(messages.join("\n")).toContain("B2_RECONCILIATION_PENDING");
    expect(fake.writesFor(targetKey)).toBe(1);
  });

  it("holds a duplicate-version batch and never emits a confirmed result", async () => {
    const fixture = await cloudflareEvidenceBatchFixture();
    const fake = new CloudflareEvidenceBatchFakeB2();
    const targetKey = slotKey(fixture.slots[7]);
    fake.fail(targetKey, "DUPLICATE");
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-runner-duplicate-0001");
    const messages = await runInDurableObject(stub, async (_instance, state) => {
      const store = new CloudflareEvidenceBatchStore(state.storage);
      await seal(store, fixture);
      const errors: string[] = [];
      for (let retry = 0; retry < 2; retry += 1) {
        try {
          await new CloudflareEvidenceBatchRunner(store, fake.writer, fake.observer).run();
        } catch (error) {
          errors.push(String(error));
        }
      }
      return errors;
    });

    expect(messages.join("\n")).toContain("B2_RECONCILIATION_DUPLICATE_DISPATCH");
    expect(messages.join("\n")).toContain("CLOUDFLARE_EVIDENCE_BATCH_NOT_DISPATCHABLE");
    expect(fake.writesFor(targetKey)).toBe(1);
  });
});

async function seal(
  store: CloudflareEvidenceBatchStore,
  fixture: Awaited<ReturnType<typeof cloudflareEvidenceBatchFixture>>,
): Promise<void> {
  await store.seal(
    fixture.binding,
    BATCH_OBSERVED_AT,
    BATCH_COMMITTED_AT,
    fixture.observation,
    cloudflareEvidenceBatchExecution(),
    fixture.slots,
  );
}

function slotKey(
  slot: Awaited<ReturnType<typeof cloudflareEvidenceBatchFixture>>["slots"][number] | undefined,
): string {
  if (slot === undefined) throw new Error("fixture slot missing");
  return cloudflareEvidenceWormKey(
    slot.sanitized.record.observer_worker_version_id as string,
    slot.kind,
    slot.sanitized.recordId,
  );
}

function requireContext<T>(value: T | undefined): T {
  if (value === undefined) throw new Error("sealed batch context missing");
  return value;
}
