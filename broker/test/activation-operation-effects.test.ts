import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import {
  activationOperationCloudflareFixture,
  mutatedCloudflareResultBytes,
  prepareCloudflarePredecessors,
} from "./activation-operation-cloudflare.fixtures";
import {
  anchorFixture,
  COMMITTED_AT,
  confirmedDirectResult,
  digest,
  DIRECT_SLOTS,
  DRIFTED_PINS,
  freeze,
  operationJournal,
  PINS,
  worm,
} from "./activation-operation-effects.fixtures";

afterEach(async () => {
  await reset();
});

describe("activation operation delegated effects", () => {
  it("confirms all three direct WORM slots and exactly 15 Cloudflare anchors", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-effects-complete-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      await freeze(journal.store, journal.issuanceId, "CONTROLLER_ACTION", 0);
      const direct = [];
      for (const [index, slotId] of DIRECT_SLOTS.entries()) {
        await freeze(journal.store, journal.issuanceId, slotId, index + 1);
        const delegated = await journal.effects.delegate(
          journal.issuanceId,
          slotId,
          COMMITTED_AT,
          PINS,
        );
        const confirmed = await journal.effects.confirmDirect(
          journal.issuanceId,
          slotId,
          confirmedDirectResult(delegated.effect, slotId, index),
        );
        direct.push({
          effectId: confirmed.effect_id,
          executor: confirmed.executor_service_identity,
          observer: confirmed.observer_service_identity,
          state: confirmed.state,
          wormDigest: confirmed.worm_digest,
        });
      }
      await prepareCloudflarePredecessors(state.storage, journal);
      const cloudflare = await activationOperationCloudflareFixture(journal);
      await journal.effects.delegateCloudflare(journal.issuanceId, cloudflare.outerRequestBytes);
      const beforeBatch = journal.effects.readyToAppend(journal.issuanceId);
      await journal.effects.confirmCloudflare(journal.issuanceId, cloudflare.resultBytes);
      const ready = journal.effects.readyToAppend(journal.issuanceId);
      const storedAnchors = state.storage.sql
        .exec<{ readonly authority_role: string | null; readonly slot_index: number }>(
          `SELECT authority_role, slot_index FROM activation_cloudflare_anchors
           WHERE issuance_id = ? ORDER BY slot_index`,
          journal.issuanceId,
        )
        .toArray();
      const issuanceState = state.storage.sql
        .exec<{
          readonly state: string;
        }>(
          `SELECT state FROM activation_operation_issuances WHERE issuance_id = ?`,
          journal.issuanceId,
        )
        .one().state;
      state.storage.sql.exec(
        `DELETE FROM activation_operation_slots
         WHERE issuance_id = ? AND slot_id = 'TARGET_RULESET'`,
        journal.issuanceId,
      );
      const missingRosterReady = journal.effects.readyToAppend(journal.issuanceId);
      return { beforeBatch, direct, issuanceState, missingRosterReady, ready, storedAnchors };
    });

    expect(result.beforeBatch).toBe(false);
    expect(result.direct).toHaveLength(3);
    expect(result.direct).toEqual(
      result.direct.map((slot) => ({
        effectId: slot.effectId,
        executor: PINS.executorServiceIdentity,
        observer: PINS.observerServiceIdentity,
        state: "CONFIRMED",
        wormDigest: slot.wormDigest,
      })),
    );
    expect(result.storedAnchors).toEqual(
      anchorFixture().map((anchor, slotIndex) => ({
        authority_role: anchor.authorityRole,
        slot_index: slotIndex,
      })),
    );
    expect(result).toMatchObject({ issuanceState: "READY_TO_APPEND", ready: true });
    expect(result.missingRosterReady).toBe(false);
  });

  it("owns result, WORM, and anchor snapshots before asynchronous hashing", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-effects-owned-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      const frozen = await freeze(journal.store, journal.issuanceId, "CONTROLLER_OIDC", 1);
      const delegatedDirect = await journal.effects.delegate(
        journal.issuanceId,
        "CONTROLLER_OIDC",
        COMMITTED_AT,
        PINS,
      );
      const directBytes = confirmedDirectResult(delegatedDirect.effect, "CONTROLLER_OIDC", 20);
      const expectedDirect = Uint8Array.from(directBytes);
      const expectedDirectKey = worm(frozen.frozen_payload_sha256, "CONTROLLER_OIDC", 20).key;
      const directConfirmation = journal.effects.confirmDirect(
        journal.issuanceId,
        "CONTROLLER_OIDC",
        directBytes,
      );
      directBytes.fill(0x78);
      const confirmedDirect = await directConfirmation;

      await prepareCloudflarePredecessors(state.storage, journal);
      const cloudflare = await activationOperationCloudflareFixture(journal);
      await journal.effects.delegateCloudflare(journal.issuanceId, cloudflare.outerRequestBytes);
      const resultBytes = Uint8Array.from(cloudflare.resultBytes);
      const expectedResult = Uint8Array.from(resultBytes);
      const expectedAnchorKey = cloudflare.anchorKeys[0];
      const cloudflareConfirmation = journal.effects.confirmCloudflare(
        journal.issuanceId,
        resultBytes,
      );
      resultBytes.fill(0x79);
      const confirmedCloudflare = await cloudflareConfirmation;
      const storedAnchorKey = state.storage.sql
        .exec<{ readonly worm_key: string }>(
          `SELECT worm_key FROM activation_cloudflare_anchors
           WHERE issuance_id = ? AND slot_index = 0`,
          journal.issuanceId,
        )
        .one().worm_key;
      return {
        cloudflareBytes: new Uint8Array(confirmedCloudflare.result_bytes ?? new ArrayBuffer()),
        directBytes: new Uint8Array(confirmedDirect.result_bytes ?? new ArrayBuffer()),
        directKey: confirmedDirect.worm_key,
        expectedAnchorKey,
        expectedDirect,
        expectedDirectKey,
        expectedResult,
        storedAnchorKey,
      };
    });

    expect(result.directBytes).toEqual(result.expectedDirect);
    expect(result.directKey).toBe(result.expectedDirectKey);
    expect(result.cloudflareBytes).toEqual(result.expectedResult);
    expect(result.storedAnchorKey).toBe(result.expectedAnchorKey);
  });

  it("rejects pin, result, and valid-but-different anchor drift", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-effects-drift-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      await freeze(journal.store, journal.issuanceId, "CONTROLLER_OIDC", 2);
      const delegated = await journal.effects.delegate(
        journal.issuanceId,
        "CONTROLLER_OIDC",
        COMMITTED_AT,
        PINS,
      );
      await expect(
        journal.effects.delegate(journal.issuanceId, "CONTROLLER_OIDC", COMMITTED_AT, DRIFTED_PINS),
      ).rejects.toThrow("ACTIVATION_OPERATION_EFFECT_BINDING_CONFLICT");
      const directBytes = confirmedDirectResult(delegated.effect, "CONTROLLER_OIDC", 30);
      await journal.effects.confirmDirect(journal.issuanceId, "CONTROLLER_OIDC", directBytes);
      const different = Uint8Array.from(directBytes);
      const last = different.at(-2);
      if (last === undefined) throw new Error("direct result fixture too short");
      different[different.length - 2] = last ^ 1;
      await expect(
        journal.effects.confirmDirect(journal.issuanceId, "CONTROLLER_OIDC", different),
      ).rejects.toThrow();

      await prepareCloudflarePredecessors(state.storage, journal);
      const cloudflare = await activationOperationCloudflareFixture(journal);
      await journal.effects.delegateCloudflare(journal.issuanceId, cloudflare.outerRequestBytes);
      await expect(
        journal.effects.confirmCloudflare(
          journal.issuanceId,
          mutatedCloudflareResultBytes(cloudflare, "PIN_DRIFT"),
        ),
      ).rejects.toThrow("CLOUDFLARE_EVIDENCE_BATCH_RESULT_WORKER_INVALID");
      await journal.effects.confirmCloudflare(journal.issuanceId, cloudflare.resultBytes);
      await expect(
        journal.effects.confirmCloudflare(
          journal.issuanceId,
          mutatedCloudflareResultBytes(cloudflare, "RESULT_DRIFT"),
        ),
      ).rejects.toThrow("CLOUDFLARE_EVIDENCE_BATCH_RESULT_BINDING_INVALID");
    });
  });

  it("rejects 14, swapped, and duplicate Cloudflare anchor rosters", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-effects-anchors-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      await prepareCloudflarePredecessors(state.storage, journal);
      const cloudflare = await activationOperationCloudflareFixture(journal);
      await journal.effects.delegateCloudflare(journal.issuanceId, cloudflare.outerRequestBytes);
      for (const mutation of ["DROP_RECORD", "SWAP_RECORDS", "DUPLICATE_RECORD"] as const) {
        await expect(
          journal.effects.confirmCloudflare(
            journal.issuanceId,
            mutatedCloudflareResultBytes(cloudflare, mutation),
          ),
        ).rejects.toThrow();
      }
      expect(
        state.storage.sql
          .exec<{
            readonly count: number;
          }>(`SELECT COUNT(*) AS count FROM activation_cloudflare_anchors`)
          .one().count,
      ).toBe(0);
    });
  });

  it("rejects direct WORM retention shorter than 2557 days", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-effects-retention-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      const frozen = await freeze(journal.store, journal.issuanceId, "CONTROLLER_OIDC", 3);
      const delegated = await journal.effects.delegate(
        journal.issuanceId,
        "CONTROLLER_OIDC",
        COMMITTED_AT,
        PINS,
      );
      const short = {
        ...worm(frozen.frozen_payload_sha256, "CONTROLLER_OIDC", 40),
        retentionUntil: new Date(Date.parse(COMMITTED_AT) + 2557 * 86_400_000 - 1).toISOString(),
      };
      await expect(
        journal.effects.confirmDirect(
          journal.issuanceId,
          "CONTROLLER_OIDC",
          confirmedDirectResult(delegated.effect, "CONTROLLER_OIDC", 40, short),
        ),
      ).rejects.toThrow("WORM_EXACT_OBJECT_EFFECT_RESULT_INVALID");
    });
  });

  it("keeps readiness closed for a missing roster slot and rejects impossible SQL states", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-effects-constraints-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      const sql = state.storage.sql;
      expect(() =>
        sql.exec(
          `UPDATE activation_operation_slots SET effect_id = ?
           WHERE issuance_id = ? AND slot_id = 'CONTROLLER_ACTION'`,
          digest(50),
          journal.issuanceId,
        ),
      ).toThrow();
      expect(() =>
        sql.exec(
          `UPDATE activation_operation_slots SET executor_service_identity = ?
           WHERE issuance_id = ? AND slot_id = 'CONTROLLER_OIDC'`,
          PINS.executorServiceIdentity,
          journal.issuanceId,
        ),
      ).toThrow();
      expect(() =>
        sql.exec(
          `UPDATE activation_operation_slots SET state = 'CONFIRMED'
           WHERE issuance_id = ? AND slot_id IN ('CONTROLLER_OIDC', 'CLOUDFLARE_BATCH')`,
          journal.issuanceId,
        ),
      ).toThrow();
      expect(journal.effects.readyToAppend(journal.issuanceId)).toBe(false);
    });
  });
});
