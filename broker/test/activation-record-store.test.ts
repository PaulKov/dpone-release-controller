import { env } from "cloudflare:workers";
import { evictDurableObject, reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { ActivationRecordStore } from "../src/activation-record-store";
import { ACTIVATED_RECORD_SCHEMA, PROVISIONED_RECORD_SCHEMA } from "../src/activation-contract";
import { canonicalBytes, sha256Hex } from "../src/canonical";
import type { ActivationWorm, JsonObject } from "../src/types";

afterEach(async () => {
  await reset();
});

describe("append-only activation record storage", () => {
  it("collapses concurrent identical appends into one immutable row", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-store-identical-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new ActivationRecordStore(state.storage);
      const storedRecord = await record(0, "identical");
      const operations = await Promise.all([
        store.append(0, tagged(10), storedRecord, COMMITTED_AT),
        store.append(0, tagged(10), storedRecord, COMMITTED_AT),
      ]);
      return {
        count: state.storage.sql
          .exec<{ readonly count: number }>("SELECT COUNT(*) AS count FROM activation_records")
          .one().count,
        recordIds: operations.map((row) => row.record_id),
        expectedRecordId: storedRecord.record_id,
      };
    });

    expect(result.count).toBe(1);
    expect(new Set(result.recordIds)).toEqual(new Set([result.expectedRecordId]));
  });

  it("allows only one winner for concurrent different activation requests", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-store-conflict-0001");
    const outcomes = await runInDurableObject(stub, async (_instance, state) => {
      const store = new ActivationRecordStore(state.storage);
      const firstRecord = await record(0, "first");
      const secondRecord = await record(0, "second");
      return Promise.allSettled([
        store.append(0, tagged(11), firstRecord, COMMITTED_AT),
        store.append(0, tagged(12), secondRecord, COMMITTED_AT),
      ]);
    });

    expect(outcomes.filter((item) => item.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((item) => item.status === "rejected")).toHaveLength(1);
    const rejection = outcomes.find((item) => item.status === "rejected");
    expect(rejection?.reason).toBeInstanceOf(Error);
    expect(String(rejection?.reason)).toContain("ACTIVATION_APPEND_ONLY_CONFLICT");
  });

  it("rejects divergent record bytes under the same request digest", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-store-byte-conflict-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const store = new ActivationRecordStore(state.storage);
      await store.append(0, tagged(18), await record(0, "first"), COMMITTED_AT);
      await expect(
        store.append(0, tagged(18), await record(0, "different"), COMMITTED_AT),
      ).rejects.toThrow("ACTIVATION_APPEND_ONLY_CONFLICT");
    });
  });

  it("recovers an unconfirmed local commit after eviction and confirms exactly once", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-store-restart-0001");
    const storedRecord = await record(0, "restart");
    const pendingDigest = await runInDurableObject(stub, async (_instance, state) => {
      const store = new ActivationRecordStore(state.storage);
      const row = await store.append(0, tagged(13), storedRecord, COMMITTED_AT);
      expect(() => store.requireConfirmed(0)).toThrow("ACTIVATION_WORM_PENDING");
      return row.record_digest;
    });

    await evictDurableObject(stub);

    const worm = mirror(pendingDigest, "activation-a0-version-0001", 0);
    const recovered = await runInDurableObject(stub, (_instance, state) => {
      const store = new ActivationRecordStore(state.storage);
      const first = store.confirm(0, worm);
      const retry = store.confirm(0, worm);
      return {
        canonicalBytes: new TextDecoder().decode(first.canonical_bytes),
        firstVersion: first.worm_version_id,
        retryVersion: retry.worm_version_id,
      };
    });

    expect(recovered.firstVersion).toBe(worm.versionId);
    expect(recovered.retryVersion).toBe(worm.versionId);
    expect(JSON.parse(recovered.canonicalBytes)).toEqual(storedRecord);
  });

  it("rejects a divergent mirror version after confirmation", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-store-worm-conflict-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const store = new ActivationRecordStore(state.storage);
      const row = await store.append(1, tagged(14), await record(1, "worm-conflict"), COMMITTED_AT);
      store.confirm(1, mirror(row.record_digest, "activation-a1-version-0001", 1));
      expect(() =>
        store.confirm(1, mirror(row.record_digest, "activation-a1-version-0002", 1)),
      ).toThrow("ACTIVATION_WORM_VERSION_CONFLICT");
    });
  });

  it("rejects a 65,537-byte record before storage and accepts the 65,536-byte boundary", async () => {
    const accepted = await sizedRecord(65_536, "accepted");
    const rejected = await sizedRecord(65_537, "rejected");
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-store-size-boundary-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = new ActivationRecordStore(state.storage);
      const row = await store.append(0, tagged(15), accepted, COMMITTED_AT);
      await expect(store.append(1, tagged(16), rejected, COMMITTED_AT)).rejects.toThrow(
        "ACTIVATION_RECORD_SIZE_INVALID",
      );
      return {
        acceptedBytes: new Uint8Array(row.canonical_bytes).byteLength,
        count: state.storage.sql
          .exec<{ readonly count: number }>("SELECT COUNT(*) AS count FROM activation_records")
          .one().count,
      };
    });

    expect(result).toEqual({ acceptedBytes: 65_536, count: 1 });
  });

  it("rejects a wrong self-derived record id before a row can be inserted", async () => {
    const valid = await record(0, "wrong-id");
    const invalid = { ...valid, record_id: tagged(99) };
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-store-wrong-id-0001");
    const count = await runInDurableObject(stub, async (_instance, state) => {
      const store = new ActivationRecordStore(state.storage);
      await expect(store.append(0, tagged(17), invalid, COMMITTED_AT)).rejects.toThrow(
        "ACTIVATION_RECORD_DIGEST_INVALID",
      );
      return state.storage.sql
        .exec<{ readonly count: number }>("SELECT COUNT(*) AS count FROM activation_records")
        .one().count;
    });
    expect(count).toBe(0);
  });
});

const COMMITTED_AT = "2026-08-15T12:00:00.000Z";

async function record(sequence: 0 | 1, marker: string): Promise<JsonObject> {
  const withoutId: JsonObject = {
    committed_at: COMMITTED_AT,
    ...workerVersionBinding(sequence),
    marker,
    schema: sequence === 0 ? PROVISIONED_RECORD_SCHEMA : ACTIVATED_RECORD_SCHEMA,
    schema_version: 1,
    sequence,
  };
  return {
    ...withoutId,
    record_id: `sha256:${await sha256Hex(canonicalBytes(withoutId))}`,
  };
}

async function sizedRecord(targetBytes: number, marker: string): Promise<JsonObject> {
  const withoutId: JsonObject = {
    committed_at: COMMITTED_AT,
    ...workerVersionBinding(0),
    marker,
    padding: "",
    schema: PROVISIONED_RECORD_SCHEMA,
    schema_version: 1,
    sequence: 0,
  };
  const placeholder = { ...withoutId, record_id: tagged(0) };
  const paddingLength = targetBytes - canonicalBytes(placeholder).byteLength;
  const padded = { ...withoutId, padding: "x".repeat(paddingLength) };
  return { ...padded, record_id: `sha256:${await sha256Hex(canonicalBytes(padded))}` };
}

function mirror(digest: string, versionId: string, sequence: 0 | 1): ActivationWorm {
  return {
    digest,
    key: `receipts/v1/activation/${WORKER_VERSION}/${sequence}-${digest.slice(7)}.json`,
    retentionUntil: "2033-08-15T12:00:00.000Z",
    versionId,
  };
}

function workerVersionBinding(sequence: 0 | 1): JsonObject {
  return sequence === 0
    ? { evidence: { broker: { worker_version_id: WORKER_VERSION } } }
    : { provisioned: { worker_version_id: WORKER_VERSION } };
}

const WORKER_VERSION = "00000000-0000-0000-0000-000000000001";

function tagged(value: number): string {
  return `sha256:${value.toString(16).padStart(64, "0")}`;
}
