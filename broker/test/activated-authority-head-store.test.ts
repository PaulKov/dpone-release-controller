import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import {
  activatedAuthorityHeadKey,
  activatedAuthorityHeadRecordSha256,
  buildActivatedAuthorityHead,
} from "../src/activated-authority-head";
import { ActivatedAuthorityHeadStore } from "../src/activated-authority-head-store";
import type { JsonObject } from "../src/types";

afterEach(async () => reset());

describe("account-global activated authority head store", () => {
  it("persists one self-verified generation and confirms only its exact WORM object", async () => {
    const stub = env.GLOBAL_ACTIVATED_AUTHORITY_HEAD.getByName("global:v1");
    await runInDurableObject(stub, async (_instance, state) => {
      const store = new ActivatedAuthorityHeadStore(state.storage);
      const input = await reservation(1, "GENESIS", 1);
      const reserved = await store.reserveHead(input);
      expect(reserved.mirror_state).toBe("PREPARED");
      expect(store.current()).toBeUndefined();

      store.markDispatched(1);
      await expect(
        store.confirm(1, {
          digest: input.recordSha256,
          key: await activatedAuthorityHeadKey(input.head),
          retentionUntil: "2034-08-15T12:00:00.000Z",
          versionId: "head-version-0001",
        }),
      ).resolves.toMatchObject({ generation: 1, mirror_state: "CONFIRMED" });
      expect(store.pending()).toBeUndefined();
      expect(store.current()?.record_id).toBe(input.recordId);
    });
  });

  it("rejects wrong self projections and exact-key or retention drift before confirmation", async () => {
    const stub = env.GLOBAL_ACTIVATED_AUTHORITY_HEAD.getByName("global:v1");
    await runInDurableObject(stub, async (_instance, state) => {
      const store = new ActivatedAuthorityHeadStore(state.storage);
      const input = await reservation(1, "GENESIS", 1);
      await expect(store.reserveHead({ ...input, recordSha256: tagged(999) })).rejects.toThrow(
        "ACTIVATED_AUTHORITY_HEAD_BINDING_INVALID",
      );
      expect(store.pending()).toBeUndefined();

      await store.reserveHead(input);
      store.markDispatched(1);
      await expect(
        store.confirm(1, {
          digest: input.recordSha256,
          key: "receipts/v1/activation-head/generations/wrong.json",
          retentionUntil: "2034-08-15T12:00:00.000Z",
          versionId: "head-version-0001",
        }),
      ).rejects.toThrow("ACTIVATED_AUTHORITY_HEAD_WORM_CONFLICT");
      await expect(
        store.confirm(1, {
          digest: input.recordSha256,
          key: await activatedAuthorityHeadKey(input.head),
          retentionUntil: "2026-08-15T12:00:04.000Z",
          versionId: "head-version-0001",
        }),
      ).rejects.toThrow("ACTIVATED_AUTHORITY_HEAD_WORM_CONFLICT");
    });
  });

  it("serializes generations, blocks divergence while pending and forbids rollback aliases", async () => {
    const stub = env.GLOBAL_ACTIVATED_AUTHORITY_HEAD.getByName("global:v1");
    await runInDurableObject(stub, async (_instance, state) => {
      const store = new ActivatedAuthorityHeadStore(state.storage);
      const first = await reservation(1, "GENESIS", 1);
      await store.reserveHead(first);
      const divergent = await reservation(1, "GENESIS", 2);
      await expect(store.reserveHead(divergent)).rejects.toThrow(
        "ACTIVATED_AUTHORITY_HEAD_ADVANCE_BLOCKED",
      );
      store.markDispatched(1);
      await store.confirm(1, {
        digest: first.recordSha256,
        key: await activatedAuthorityHeadKey(first.head),
        retentionUntil: "2034-08-15T12:00:00.000Z",
        versionId: "head-version-0001",
      });

      const previous = {
        generation: 1,
        record_id: first.recordId,
        record_sha256: first.recordSha256,
      };
      const reused = await reservation(2, previous, 1);
      await expect(store.reserveHead({ ...reused, requestDigest: tagged(999) })).rejects.toThrow(
        "ACTIVATED_AUTHORITY_HEAD_ROLLBACK_FORBIDDEN",
      );
      const wrongPrevious = await reservation(2, { ...previous, record_sha256: tagged(500) }, 3);
      await expect(store.reserveHead(wrongPrevious)).rejects.toThrow(
        "ACTIVATED_AUTHORITY_HEAD_PREVIOUS_INVALID",
      );
    });
  });

  it("returns one byte-identical reservation for the same semantic request only", async () => {
    const stub = env.GLOBAL_ACTIVATED_AUTHORITY_HEAD.getByName("global:v1");
    await runInDurableObject(stub, async (_instance, state) => {
      const store = new ActivatedAuthorityHeadStore(state.storage);
      const input = await reservation(1, "GENESIS", 1);
      const first = await store.reserveHead(input);
      const replayed = await store.reserveHead(input);
      expect(replayed.record_sha256).toBe(first.record_sha256);
      const drifted = await reservation(1, "GENESIS", 2);
      await expect(
        store.reserveHead({ ...drifted, requestDigest: input.requestDigest }),
      ).rejects.toThrow("ACTIVATED_AUTHORITY_HEAD_APPEND_CONFLICT");
    });
  });
});

async function reservation(generation: number, previous: "GENESIS" | JsonObject, seed: number) {
  const ingress = uuid(seed);
  const activatedRecordSha256 = tagged(seed * 10 + 2);
  const head = await buildActivatedAuthorityHead({
    activatedRecordId: tagged(seed * 10 + 1),
    activatedRecordSha256,
    activatedServiceAuthoritiesSha256: tagged(seed * 10 + 3),
    activatedWorm: {
      digest: activatedRecordSha256,
      key: `receipts/v1/activation/${ingress}/1-${activatedRecordSha256.slice(7)}.json`,
      retentionUntil: "2034-08-15T12:00:00.000Z",
      versionId: `activation-version-${seed}`,
    },
    committedAt: "2026-08-15T12:00:03.000Z",
    generation,
    ingressWorkerVersionId: ingress,
    previous,
  });
  return {
    activatedRecordId: tagged(seed * 10 + 1),
    activatedRecordSha256,
    activatedServiceAuthoritiesSha256: tagged(seed * 10 + 3),
    committedAt: "2026-08-15T12:00:03.000Z",
    generation,
    head,
    ingressWorkerVersionId: ingress,
    recordId: requiredString(head, "record_id"),
    recordSha256: await activatedAuthorityHeadRecordSha256(head),
    requestDigest: tagged(seed * 10 + 4),
  };
}

function tagged(value: number): string {
  return `sha256:${value.toString(16).padStart(64, "0")}`;
}

function uuid(value: number): string {
  return `00000000-0000-0000-0000-${String(value).padStart(12, "0")}`;
}

function requiredString(value: JsonObject, key: string): string {
  const candidate = value[key];
  if (typeof candidate !== "string") throw new Error(`missing ${key}`);
  return candidate;
}
