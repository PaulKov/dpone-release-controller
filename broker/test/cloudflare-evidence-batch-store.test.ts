import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { CloudflareEvidenceBatchStore } from "../src/cloudflare-evidence-batch-store";
import { canonicalJson } from "../src/canonical";
import {
  BATCH_COMMITTED_AT,
  BATCH_OBSERVED_AT,
  cloudflareEvidenceBatchExecution as execution,
  cloudflareEvidenceBatchFixture as batchFixture,
  cloudflareEvidenceBatchWorm as worm,
} from "./cloudflare-evidence-batch.fixtures";
import { digest } from "./cloudflare-deployment-observer-provider.fixtures";

afterEach(async () => {
  await reset();
});

describe("sanitized Cloudflare evidence batch journal", () => {
  it("persists all fifteen sanitized slots atomically before any dispatch state", async () => {
    const { binding, observation, slots } = await batchFixture();
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-batch-seal-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new CloudflareEvidenceBatchStore(state.storage);
      expect(() => store.next(0)).toThrow("CLOUDFLARE_EVIDENCE_BATCH_MISSING");
      const before = count(state.storage, "cloudflare_evidence_slots");
      await store.seal(
        binding,
        BATCH_OBSERVED_AT,
        BATCH_COMMITTED_AT,
        observation,
        execution(),
        slots,
      );
      await store.seal(
        binding,
        BATCH_OBSERVED_AT,
        BATCH_COMMITTED_AT,
        observation,
        execution(),
        slots,
      );
      const persisted = state.storage.sql
        .exec<{ readonly canonical_bytes: ArrayBuffer }>(
          `SELECT canonical_bytes FROM cloudflare_evidence_slots ORDER BY slot_index`,
        )
        .toArray()
        .map((row) => new TextDecoder().decode(row.canonical_bytes))
        .join("\n");
      return {
        before,
        persisted,
        prepared: countWhere(state.storage, "PREPARED"),
        total: count(state.storage, "cloudflare_evidence_slots"),
      };
    });

    expect(result.before).toBe(0);
    expect(result.total).toBe(15);
    expect(result.prepared).toBe(15);
    expect(result.persisted).not.toMatch(
      /raw_body_base64|author_email|author_id|operator\+secret@example|workers\/message/iu,
    );
  });

  it("resumes only the byte-identical sealed context under the original executor pins", async () => {
    const { binding, observation, slots } = await batchFixture();
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-batch-resume-pins-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new CloudflareEvidenceBatchStore(state.storage);
      const expectedExecution = execution();
      await store.seal(
        binding,
        BATCH_OBSERVED_AT,
        BATCH_COMMITTED_AT,
        observation,
        expectedExecution,
        slots,
      );
      const resumed = store.resume(binding.batchId, expectedExecution);
      const errors: string[] = [];
      const alternativeVersion = "44444444-4444-4444-4444-444444444444";
      for (const drifted of [
        {
          ...expectedExecution,
          b2ObserverServiceIdentity: expectedExecution.b2ObserverServiceIdentity.replace(
            "22222222-2222-2222-2222-222222222222",
            alternativeVersion,
          ),
        },
        {
          ...expectedExecution,
          wormServiceIdentity: expectedExecution.wormServiceIdentity.replace(
            expectedExecution.wormWorkerVersionId,
            alternativeVersion,
          ),
          wormWorkerVersionId: alternativeVersion,
        },
      ]) {
        try {
          store.resume(binding.batchId, drifted);
        } catch (error) {
          errors.push(String(error));
        }
      }
      return {
        errors,
        observation: canonicalJson(resumed?.observation ?? {}),
        providerDigest: resumed?.providerObservationSha256,
      };
    });

    expect(result.observation).toBe(canonicalJson(observation));
    expect(result.providerDigest).toBe(observation.provider_observation_sha256);
    expect(result.errors).toHaveLength(2);
    expect(result.errors.join("\n")).toContain("CLOUDFLARE_EVIDENCE_BATCH_EXECUTION_CONFLICT");
  });

  it("advances each slot through absence, in-flight, accepted and confirmed", async () => {
    const { binding, observation, slots } = await batchFixture();
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-batch-states-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new CloudflareEvidenceBatchStore(state.storage);
      await store.seal(
        binding,
        BATCH_OBSERVED_AT,
        BATCH_COMMITTED_AT,
        observation,
        execution(),
        slots,
      );
      const states: string[] = [store.next(0).slot.status];
      const actions: string[] = [store.next(0).action];
      store.markAbsent(0, digest(700));
      const dispatch = store.next(0);
      states.push(dispatch.slot.status);
      actions.push(dispatch.action);
      const first = store.next(0).slot;
      const firstWorm = worm(first);
      store.accept(0, firstWorm.versionId);
      const accepted = store.next(0);
      states.push(accepted.slot.status);
      actions.push(accepted.action);
      store.confirm(0, firstWorm);
      const confirmed = store.next(0);
      states.push(confirmed.slot.status);
      actions.push(confirmed.action);

      for (let index = 1; index < slots.length; index += 1) {
        store.markAbsent(index, digest(700 + index));
        const current = store.next(index).slot;
        store.confirm(index, worm(current));
      }
      return { actions, confirmed: store.confirmed().length, states };
    });

    expect(result).toEqual({
      confirmed: 15,
      actions: ["CHECK_ABSENCE", "DISPATCH", "RECONCILE", "COMPLETE"],
      states: ["PREPARED", "IN_FLIGHT", "ACCEPTED", "CONFIRMED"],
    });
  });

  it("reconciles a lost writer response without returning a slot to dispatchable absence", async () => {
    const { binding, observation, slots } = await batchFixture();
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-batch-response-loss-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new CloudflareEvidenceBatchStore(state.storage);
      await store.seal(
        binding,
        BATCH_OBSERVED_AT,
        BATCH_COMMITTED_AT,
        observation,
        execution(),
        slots,
      );
      store.markAbsent(0, digest(800));
      const dispatched = store.next(0).slot;
      const recovered = worm(dispatched);
      store.confirm(0, recovered);
      return { afterDispatch: dispatched.status, afterRecovery: store.next(0).slot.status };
    });

    expect(result).toEqual({ afterDispatch: "IN_FLIGHT", afterRecovery: "CONFIRMED" });
  });

  it("stops new dispatch after HOLD while allowing pre-HOLD in-flight slots to reconcile", async () => {
    const { binding, observation, slots } = await batchFixture();
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-batch-hold-barrier-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new CloudflareEvidenceBatchStore(state.storage);
      await store.seal(
        binding,
        BATCH_OBSERVED_AT,
        BATCH_COMMITTED_AT,
        observation,
        execution(),
        slots,
      );
      for (let slotIndex = 0; slotIndex < 4; slotIndex += 1) {
        store.markAbsent(slotIndex, digest(850 + slotIndex));
        expect(store.next(slotIndex).action).toBe("DISPATCH");
      }
      store.hold(0);
      const drainActions: string[] = [];
      for (let slotIndex = 1; slotIndex < 4; slotIndex += 1) {
        const action = store.next(slotIndex);
        drainActions.push(action.action);
        store.confirm(slotIndex, worm(action.slot));
        drainActions.push(store.next(slotIndex).action);
      }
      let blocked = "";
      try {
        store.next(4);
      } catch (error) {
        blocked = String(error);
      }
      return { blocked, drainActions };
    });

    expect(result.drainActions).toEqual([
      "RECONCILE",
      "COMPLETE",
      "RECONCILE",
      "COMPLETE",
      "RECONCILE",
      "COMPLETE",
    ]);
    expect(result.blocked).toContain("CLOUDFLARE_EVIDENCE_BATCH_NOT_DISPATCHABLE");
  });

  it("rejects short retention, wrong keys, binding drift and a permanent HOLD", async () => {
    const { binding, observation, slots } = await batchFixture();
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-batch-negative-0001");
    const messages = await runInDurableObject(stub, async (_instance, state) => {
      const store = new CloudflareEvidenceBatchStore(state.storage);
      await store.seal(
        binding,
        BATCH_OBSERVED_AT,
        BATCH_COMMITTED_AT,
        observation,
        execution(),
        slots,
      );
      const errors: string[] = [];
      store.markAbsent(0, digest(900));
      try {
        store.markAbsent(0, digest(901));
      } catch (error) {
        errors.push(String(error));
      }
      const current = store.next(0).slot;
      const valid = worm(current);
      try {
        store.accept(0, "");
      } catch (error) {
        errors.push(String(error));
      }
      for (const invalid of [
        { ...valid, key: `${valid.key}.wrong` },
        { ...valid, retentionUntil: "2026-08-20T12:00:00.000Z" },
      ]) {
        try {
          store.confirm(0, invalid);
        } catch (error) {
          errors.push(String(error));
        }
      }
      store.hold(0);
      try {
        store.next(0);
      } catch (error) {
        errors.push(String(error));
      }
      return errors;
    });

    expect(messages.join("\n")).toContain("CLOUDFLARE_EVIDENCE_BATCH_WORM_INVALID");
    expect(messages.join("\n")).toContain("CLOUDFLARE_EVIDENCE_ABSENCE_CONFLICT");
    expect(messages.join("\n")).toContain("CLOUDFLARE_EVIDENCE_BATCH_NOT_DISPATCHABLE");

    const drifted = { ...binding, batchId: digest(999) };
    await expect(
      runInDurableObject(stub, (_instance, state) =>
        new CloudflareEvidenceBatchStore(state.storage).seal(
          drifted,
          BATCH_OBSERVED_AT,
          BATCH_COMMITTED_AT,
          observation,
          execution(),
          slots,
        ),
      ),
    ).rejects.toThrow("CLOUDFLARE_EVIDENCE_BATCH_BINDING_CONFLICT");
  });
});

function count(storage: DurableObjectStorage, table: string): number {
  return storage.sql
    .exec<{ readonly count: number }>(`SELECT COUNT(*) AS count FROM ${table}`)
    .one().count;
}

function countWhere(storage: DurableObjectStorage, status: string): number {
  return storage.sql
    .exec<{
      readonly count: number;
    }>(`SELECT COUNT(*) AS count FROM cloudflare_evidence_slots WHERE status = ?`, status)
    .one().count;
}
