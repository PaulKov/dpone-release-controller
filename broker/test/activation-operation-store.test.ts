import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { PROVISION_REQUEST_SCHEMA } from "../src/activation-contract";
import { ActivationOperationEffects } from "../src/activation-operation-effects";
import { activationOperationIdentity } from "../src/activation-operation-identity";
import { ActivationOperationStore } from "../src/activation-operation-store";
import { canonicalBytes } from "../src/canonical";
import type { JsonObject } from "../src/types";

const WORKER_VERSION = "11111111-1111-1111-1111-111111111111";
const NOW = Date.parse("2026-08-19T12:00:00.000Z");

afterEach(async () => {
  await reset();
});

describe("activation operation intent and issuance journal", () => {
  it("atomically reserves the complete fixed roster before a provider callback", async () => {
    const identity = await activationOperationIdentity(provisionBody(), 0, WORKER_VERSION);
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-operation-roster-0001");
    let providerCalls = 0;
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = operationStore(state.storage);
      const issuance = await store.reserve(identity, NOW);
      const slotsBeforeProvider = store.slots(issuance.issuanceId).map((slot) => ({
        id: slot.slot_id,
        index: slot.slot_index,
        kind: slot.slot_kind,
        state: slot.state,
      }));
      providerCalls += 1;
      return { issuance, slotsBeforeProvider };
    });

    expect(providerCalls).toBe(1);
    expect(result.issuance.ordinal).toBe(1);
    expect(result.slotsBeforeProvider).toEqual([
      { id: "CONTROLLER_ACTION", index: 0, kind: "READ_ONLY", state: "PREPARED" },
      { id: "CONTROLLER_OIDC", index: 1, kind: "DIRECT_WORM", state: "PREPARED" },
      { id: "TARGET_OIDC", index: 2, kind: "DIRECT_WORM", state: "PREPARED" },
      { id: "TARGET_RULESET", index: 3, kind: "DIRECT_WORM", state: "PREPARED" },
      { id: "CLOUDFLARE_BATCH", index: 4, kind: "CLOUDFLARE_BATCH", state: "PREPARED" },
    ]);
  });

  it("collapses transport drift and concurrent retries into one semantic issuance", async () => {
    const first = await activationOperationIdentity(provisionBody(), 0, WORKER_VERSION);
    const retry = await activationOperationIdentity(
      provisionBody({ observedAt: "2026-08-19T12:00:30.000Z", requestId: "request-retry-0002" }),
      0,
      WORKER_VERSION,
    );
    expect(retry).toMatchObject({ attemptId: first.attemptId, intentSha256: first.intentSha256 });
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-operation-collapse-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = operationStore(state.storage);
      const [left, right] = await Promise.all([
        store.reserve(first, NOW),
        store.reserve(retry, NOW),
      ]);
      return {
        attempts: count(state.storage, "activation_operation_intents"),
        issuanceIds: [left.issuanceId, right.issuanceId],
        issuances: count(state.storage, "activation_operation_issuances"),
        slots: count(state.storage, "activation_operation_slots"),
      };
    });

    expect(result).toEqual({
      attempts: 1,
      issuanceIds: [result.issuanceIds[0], result.issuanceIds[0]],
      issuances: 1,
      slots: 5,
    });
  });

  it("rejects semantic drift and caller mutation after identity derivation", async () => {
    const identity = await activationOperationIdentity(provisionBody(), 0, WORKER_VERSION);
    const drifted = await activationOperationIdentity(
      provisionBody({ evidence: { reviewed: "different" } }),
      0,
      WORKER_VERSION,
    );
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-operation-drift-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const store = operationStore(state.storage);
      await store.reserve(identity, NOW);
      await expect(store.reserve(drifted, NOW)).rejects.toThrow(
        "ACTIVATION_OPERATION_INTENT_CONFLICT",
      );
      const firstByte = identity.semanticRequestBytes[0];
      if (firstByte === undefined) throw new Error("semantic request fixture empty");
      identity.semanticRequestBytes[0] = firstByte ^ 1;
      await expect(store.reserve(identity, NOW)).rejects.toThrow(
        "ACTIVATION_OPERATION_IDENTITY_INVALID",
      );
    });
  });

  it("rejects split semantic object and canonical byte authorities", async () => {
    const identity = await activationOperationIdentity(provisionBody(), 0, WORKER_VERSION);
    const split = {
      ...identity,
      semanticRequest: { ...identity.semanticRequest, evidence: { reviewed: "different" } },
    };
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-operation-split-identity-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const store = operationStore(state.storage);
      await expect(store.reserve(split, NOW)).rejects.toThrow(
        "ACTIVATION_OPERATION_IDENTITY_INVALID",
      );
      expect(count(state.storage, "activation_operation_intents")).toBe(0);
    });
  });

  it("issues ordinal two only after a stale issuance with no durable dispatch", async () => {
    const first = await activationOperationIdentity(provisionBody(), 0, WORKER_VERSION);
    const freshAssertionRetry = await activationOperationIdentity(
      provisionBody({ observedAt: "2026-08-19T12:02:00.000Z", requestId: "fresh-access-0002" }),
      0,
      WORKER_VERSION,
    );
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-operation-stale-reissue-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = operationStore(state.storage);
      const original = await store.reserve(first, NOW);
      await expect(store.reissueStale(freshAssertionRetry, NOW + 60_000)).rejects.toThrow(
        "ACTIVATION_OPERATION_ISSUANCE_FRESH",
      );
      const reissued = await store.reissueStale(freshAssertionRetry, NOW + 60_001);
      await expect(
        store.prepareRead(
          original.issuanceId,
          "CONTROLLER_ACTION",
          canonicalBytes({ request: "late-old-ordinal" }),
        ),
      ).rejects.toThrow("ACTIVATION_OPERATION_ISSUANCE_STALE");
      const effects = new ActivationOperationEffects(state.storage, () => NOW + 60_001);
      await expect(
        effects.delegate(original.issuanceId, "CONTROLLER_OIDC", "2026-08-19T12:01:00.001Z", {
          executorServiceIdentity: workerIdentity("worm-mirror", "2"),
          executorWorkerVersionId: workerVersion("2"),
          observerServiceIdentity: workerIdentity("worm-version-observer", "3"),
          observerWorkerVersionId: workerVersion("3"),
        }),
      ).rejects.toThrow("ACTIVATION_OPERATION_ISSUANCE_STALE");
      await expect(
        effects.confirmDirect(
          original.issuanceId,
          "CONTROLLER_OIDC",
          canonicalBytes({ result: "late-old-ordinal" }),
        ),
      ).rejects.toThrow("ACTIVATION_OPERATION_ISSUANCE_STALE");
      const oldState = state.storage.sql
        .exec<{
          readonly state: string;
        }>(
          `SELECT state FROM activation_operation_issuances WHERE issuance_id = ?`,
          original.issuanceId,
        )
        .one().state;
      return {
        oldState,
        original,
        reissued,
        roster: store.slots(reissued.issuanceId).map((slot) => slot.slot_id),
      };
    });

    expect(result.reissued).toMatchObject({
      attemptId: result.original.attemptId,
      ordinal: 2,
      state: "RESERVED",
    });
    expect(result.reissued.issuanceId).not.toBe(result.original.issuanceId);
    expect(result.oldState).toBe("EXPIRED_UNDISPATCHED");
    expect(result.roster).toEqual([
      "CONTROLLER_ACTION",
      "CONTROLLER_OIDC",
      "TARGET_OIDC",
      "TARGET_RULESET",
      "CLOUDFLARE_BATCH",
    ]);
  });

  it("blocks reissue after a partial or HOLD effect and keeps HOLD live in SQLite", async () => {
    const identity = await activationOperationIdentity(provisionBody(), 0, WORKER_VERSION);
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-operation-stale-hold-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const store = operationStore(state.storage);
      const issuance = await store.reserve(identity, NOW);
      await store.prepareRead(
        issuance.issuanceId,
        "CONTROLLER_OIDC",
        canonicalBytes({ request: "controller-oidc" }),
      );
      await store.freezeRead(
        issuance.issuanceId,
        "CONTROLLER_OIDC",
        canonicalBytes({ payload: "controller-oidc" }),
        "2026-08-19T12:00:01.000Z",
      );
      await new ActivationOperationEffects(state.storage, () => NOW + 2_000).delegate(
        issuance.issuanceId,
        "CONTROLLER_OIDC",
        "2026-08-19T12:00:02.000Z",
        {
          executorServiceIdentity: workerIdentity("worm-mirror", "2"),
          executorWorkerVersionId: workerVersion("2"),
          observerServiceIdentity: workerIdentity("worm-version-observer", "3"),
          observerWorkerVersionId: workerVersion("3"),
        },
      );
      await expect(store.reissueStale(identity, NOW + 60_001)).rejects.toThrow(
        "ACTIVATION_OPERATION_REISSUE_BLOCKED",
      );
      state.storage.sql.exec(
        `UPDATE activation_operation_issuances SET state = 'HOLD' WHERE issuance_id = ?`,
        issuance.issuanceId,
      );
      await expect(store.reissueStale(identity, NOW + 60_001)).rejects.toThrow(
        "ACTIVATION_OPERATION_REISSUE_BLOCKED",
      );
      expect(() =>
        state.storage.sql.exec(
          `INSERT INTO activation_operation_issuances(
             attempt_id, ordinal, issuance_id, internal_request_id,
             issued_at, fresh_until, state
           ) VALUES (?, 2, ?, ?, ?, ?, 'RESERVED')`,
          identity.attemptId,
          `sha256:${"4".repeat(64)}`,
          "activation-sql-hold-probe",
          "2026-08-19T12:02:00.000Z",
          "2026-08-19T12:03:00.000Z",
        ),
      ).toThrow();
    });
  });

  it("repeats an unresolved read but reuses frozen bytes without another provider call", async () => {
    const identity = await activationOperationIdentity(provisionBody(), 0, WORKER_VERSION);
    const requestBytes = canonicalBytes({ operation: "controller-action" });
    const resultBytes = canonicalBytes({ observation: "sealed" });
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-operation-read-freeze-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = operationStore(state.storage);
      const issuance = await store.reserve(identity, NOW);
      await expect(
        store.prepareRead(
          issuance.issuanceId,
          "CLOUDFLARE_BATCH",
          canonicalBytes({ operation: "forbidden-unsealed-cloudflare-call" }),
        ),
      ).rejects.toThrow("ACTIVATION_OPERATION_CLOUDFLARE_DELEGATION_REQUIRED");
      const first = await store.prepareRead(issuance.issuanceId, "CONTROLLER_ACTION", requestBytes);
      const unresolvedRetry = await store.prepareRead(
        issuance.issuanceId,
        "CONTROLLER_ACTION",
        requestBytes,
      );
      await store.freezeRead(
        issuance.issuanceId,
        "CONTROLLER_ACTION",
        resultBytes,
        "2026-08-19T12:00:01.000Z",
      );
      const frozenRetry = await store.prepareRead(
        issuance.issuanceId,
        "CONTROLLER_ACTION",
        requestBytes,
      );
      return {
        calls: [first.callProvider, unresolvedRetry.callProvider, frozenRetry.callProvider],
        frozenPayload: new TextDecoder().decode(frozenRetry.slot.frozen_payload_bytes ?? undefined),
      };
    });

    expect(result).toEqual({
      calls: [true, true, false],
      frozenPayload: '{"observation":"sealed"}',
    });
  });

  it("owns request and payload bytes before asynchronous hashing", async () => {
    const identity = await activationOperationIdentity(provisionBody(), 0, WORKER_VERSION);
    const requestBytes = canonicalBytes({ operation: "controller-action" });
    const originalRequest = Uint8Array.from(requestBytes);
    const payloadBytes = canonicalBytes({ observation: "sealed" });
    const originalPayload = Uint8Array.from(payloadBytes);
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-operation-owned-bytes-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const store = operationStore(state.storage);
      const issuance = await store.reserve(identity, NOW);
      const preparing = store.prepareRead(issuance.issuanceId, "CONTROLLER_ACTION", requestBytes);
      requestBytes.fill(0x78);
      await preparing;
      const freezing = store.freezeRead(
        issuance.issuanceId,
        "CONTROLLER_ACTION",
        payloadBytes,
        "2026-08-19T12:00:01.000Z",
      );
      payloadBytes.fill(0x79);
      const frozen = await freezing;
      return {
        payload: new Uint8Array(frozen.frozen_payload_bytes ?? new ArrayBuffer()),
        request: new Uint8Array(frozen.provider_request_bytes ?? new ArrayBuffer()),
      };
    });

    expect(result.request).toEqual(originalRequest);
    expect(result.payload).toEqual(originalPayload);
  });
});

function provisionBody(overrides?: {
  readonly evidence?: JsonObject;
  readonly observedAt?: string;
  readonly requestId?: string;
}): JsonObject {
  return {
    evidence: overrides?.evidence ?? { reviewed: "same" },
    observed_at: overrides?.observedAt ?? "2026-08-19T12:00:00.000Z",
    request_id: overrides?.requestId ?? "request-provision-0001",
    schema: PROVISION_REQUEST_SCHEMA,
    schema_version: 1,
  };
}

function count(storage: DurableObjectStorage, table: string): number {
  return storage.sql
    .exec<{ readonly count: number }>(`SELECT COUNT(*) AS count FROM ${table}`)
    .one().count;
}

function operationStore(storage: DurableObjectStorage): ActivationOperationStore {
  return new ActivationOperationStore(storage, () => NOW + 1_000);
}

function workerVersion(nibble: string): string {
  return `${nibble.repeat(8)}-${nibble.repeat(4)}-${nibble.repeat(4)}-${nibble.repeat(4)}-${nibble.repeat(12)}`;
}

function workerIdentity(service: string, nibble: string): string {
  return `cloudflare-worker:${"a".repeat(32)}/${service}@${workerVersion(nibble)}`;
}
