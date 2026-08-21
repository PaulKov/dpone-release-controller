import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { canonicalBytes } from "../src/canonical";
import {
  activationOperationCloudflareFixture,
  prepareCloudflarePredecessors,
} from "./activation-operation-cloudflare.fixtures";
import {
  COMMITTED_AT,
  confirmedDirectResult,
  digest,
  freeze,
  operationJournal,
  PINS,
} from "./activation-operation-effects.fixtures";

afterEach(async () => {
  await reset();
});

describe("activation operation current-issuance fencing", () => {
  it("never starts a prepared Cloudflare batch from DISPATCHED_HOLD", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-hold-cloudflare-prepared-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      await prepareCloudflarePredecessors(state.storage, journal);
      const cloudflare = await activationOperationCloudflareFixture(journal);
      state.storage.sql.exec(
        `UPDATE activation_operation_issuances SET state = 'DISPATCHED_HOLD'
         WHERE issuance_id = ?`,
        journal.issuanceId,
      );

      const outcome = await settle(
        journal.effects.delegateCloudflare(journal.issuanceId, cloudflare.outerRequestBytes),
      );
      const slot = operationSlot(state.storage, journal.issuanceId, "CLOUDFLARE_BATCH");

      expect(outcome).toEqual({
        error: "ACTIVATION_OPERATION_SLOT_STATE_CONFLICT",
        value: null,
      });
      expect(slot).toMatchObject({
        batch_id: null,
        cloudflare_observer_service_identity: null,
        provider_request_bytes: null,
        state: "PREPARED",
      });
    });
  });

  it("rejects a superseded direct read after its digest await without mutating the old slot", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-direct-read-fence-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      const preparing = journal.store.prepareRead(
        journal.issuanceId,
        "CONTROLLER_ACTION",
        canonicalBytes({ operation: "direct-read-race" }),
      );
      supersedeCurrent(state.storage, journal.issuanceId, 601);

      expect(await settle(preparing)).toEqual({
        error: "ACTIVATION_OPERATION_ISSUANCE_STALE",
        value: null,
      });
      expect(operationSlot(state.storage, journal.issuanceId, "CONTROLLER_ACTION")).toMatchObject({
        provider_request_bytes: null,
        state: "PREPARED",
      });
    });
  });

  it("rejects a superseded Cloudflare delegation after its digest await", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-cloudflare-delegate-fence-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      await prepareCloudflarePredecessors(state.storage, journal);
      const cloudflare = await activationOperationCloudflareFixture(journal);
      const delegating = journal.effects.delegateCloudflare(
        journal.issuanceId,
        cloudflare.outerRequestBytes,
      );
      supersedeCurrent(state.storage, journal.issuanceId, 602);

      expect(await settle(delegating)).toEqual({
        error: "ACTIVATION_OPERATION_ISSUANCE_STALE",
        value: null,
      });
      expect(operationSlot(state.storage, journal.issuanceId, "CLOUDFLARE_BATCH")).toMatchObject({
        batch_id: null,
        provider_request_bytes: null,
        state: "PREPARED",
      });
    });
  });

  it("rejects a superseded direct confirmation after its digest await", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-direct-confirm-fence-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      await freeze(journal.store, journal.issuanceId, "CONTROLLER_OIDC", 7);
      const delegated = await journal.effects.delegate(
        journal.issuanceId,
        "CONTROLLER_OIDC",
        COMMITTED_AT,
        PINS,
      );
      const confirming = journal.effects.confirmDirect(
        journal.issuanceId,
        "CONTROLLER_OIDC",
        confirmedDirectResult(delegated.effect, "CONTROLLER_OIDC", 603),
      );
      supersedeCurrent(state.storage, journal.issuanceId, 603);

      expect(await settle(confirming)).toEqual({
        error: "ACTIVATION_OPERATION_ISSUANCE_STALE",
        value: null,
      });
      expect(operationSlot(state.storage, journal.issuanceId, "CONTROLLER_OIDC")).toMatchObject({
        result_bytes: null,
        state: "DELEGATED_IN_FLIGHT",
        worm_digest: null,
      });
    });
  });

  it("rejects a superseded Cloudflare confirmation after its digest await", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-cloudflare-confirm-fence-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      await prepareCloudflarePredecessors(state.storage, journal);
      const cloudflare = await activationOperationCloudflareFixture(journal);
      await journal.effects.delegateCloudflare(journal.issuanceId, cloudflare.outerRequestBytes);
      const confirming = journal.effects.confirmCloudflare(
        journal.issuanceId,
        cloudflare.resultBytes,
      );
      supersedeCurrent(state.storage, journal.issuanceId, 604);

      expect(await settle(confirming)).toEqual({
        error: "ACTIVATION_OPERATION_ISSUANCE_STALE",
        value: null,
      });
      expect(operationSlot(state.storage, journal.issuanceId, "CLOUDFLARE_BATCH")).toMatchObject({
        result_bytes: null,
        state: "DELEGATED_IN_FLIGHT",
      });
      expect(anchorCount(state.storage, journal.issuanceId)).toBe(0);
    });
  });

  it("rejects a 65,537-byte direct result before attempting to copy it", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-direct-result-cap-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      const oversized = new Uint8Array(65_537);
      let copyAttempted = false;
      Object.defineProperty(oversized, Symbol.iterator, {
        configurable: true,
        get() {
          copyAttempted = true;
          throw new Error("COPY_TRAP");
        },
      });

      const outcome = await settle(
        journal.effects.confirmDirect(journal.issuanceId, "CONTROLLER_OIDC", oversized),
      );

      expect(outcome).toEqual({
        error: "ACTIVATION_OPERATION_EFFECT_RESULT_SIZE_INVALID",
        value: null,
      });
      expect(copyAttempted).toBe(false);
    });
  });

  it("rejects a 65,537-byte direct payload before attempting to copy it", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-direct-payload-cap-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      await journal.store.prepareRead(
        journal.issuanceId,
        "CONTROLLER_OIDC",
        canonicalBytes({ operation: "direct-payload-cap" }),
      );
      const oversized = new Uint8Array(65_537);
      let copyAttempted = false;
      Object.defineProperty(oversized, Symbol.iterator, {
        configurable: true,
        get() {
          copyAttempted = true;
          throw new Error("COPY_TRAP");
        },
      });

      const outcome = await settle(
        journal.store.freezeRead(
          journal.issuanceId,
          "CONTROLLER_OIDC",
          oversized,
          "2026-08-19T12:00:01.000Z",
        ),
      );

      expect(outcome).toEqual({
        error: "ACTIVATION_OPERATION_SLOT_SIZE_INVALID",
        value: null,
      });
      expect(copyAttempted).toBe(false);
    });
  });
});

interface IssuanceIdentityRow extends Record<string, SqlStorageValue> {
  readonly attempt_id: string;
  readonly ordinal: number;
}

function supersedeCurrent(
  storage: DurableObjectStorage,
  issuanceId: string,
  identityIndex: number,
): void {
  const current = storage.sql
    .exec<IssuanceIdentityRow>(
      `SELECT attempt_id, ordinal FROM activation_operation_issuances WHERE issuance_id = ?`,
      issuanceId,
    )
    .one();
  const nextOrdinal = current.ordinal + 1;
  storage.transactionSync(() => {
    storage.sql.exec(
      `UPDATE activation_operation_issuances
       SET state = 'SUPERSEDED_STALE', superseded_by_ordinal = ?
       WHERE issuance_id = ?`,
      nextOrdinal,
      issuanceId,
    );
    storage.sql.exec(
      `INSERT INTO activation_operation_issuances(
         attempt_id, ordinal, issuance_id, internal_request_id,
         issued_at, fresh_until, state
       ) VALUES (?, ?, ?, ?, ?, ?, 'RESERVED')`,
      current.attempt_id,
      nextOrdinal,
      digest(identityIndex),
      `activation-fence-${identityIndex}`,
      "2026-08-19T12:02:00.000Z",
      "2026-08-19T12:03:00.000Z",
    );
  });
}

function operationSlot(
  storage: DurableObjectStorage,
  issuanceId: string,
  slotId: string,
): Record<string, SqlStorageValue> {
  return storage.sql
    .exec(
      `SELECT * FROM activation_operation_slots WHERE issuance_id = ? AND slot_id = ?`,
      issuanceId,
      slotId,
    )
    .one();
}

function anchorCount(storage: DurableObjectStorage, issuanceId: string): number {
  return storage.sql
    .exec<{
      readonly count: number;
    }>(
      `SELECT COUNT(*) AS count FROM activation_cloudflare_anchors WHERE issuance_id = ?`,
      issuanceId,
    )
    .one().count;
}

async function settle<T>(promise: Promise<T>): Promise<{
  readonly error: string | null;
  readonly value: T | null;
}> {
  try {
    return { error: null, value: await promise };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error), value: null };
  }
}
