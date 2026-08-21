import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { ActivationOperationEffects } from "../src/activation-operation-effects";
import { activationOperationCloudflareFixture } from "./activation-operation-cloudflare.fixtures";
import { DIRECT_SLOTS, freeze, operationJournal } from "./activation-operation-effects.fixtures";

afterEach(async () => {
  await reset();
});

describe("activation operation atomic A0 delegation", () => {
  it("seals three direct effects and the Cloudflare delegation in one durable transition", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-provision-seal-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const journal = await frozenProvisionJournal(state.storage);
      const cloudflare = await activationOperationCloudflareFixture(journal);
      const first = await journal.effects.delegateProvision(
        journal.issuanceId,
        cloudflare.outerRequestBytes,
      );
      const retry = await journal.effects.delegateProvision(
        journal.issuanceId,
        cloudflare.outerRequestBytes,
      );
      return {
        first: first.cloudflareAction,
        firstDirect: first.direct.map(({ action }) => action),
        retry: retry.cloudflareAction,
        states: slotStates(state.storage, journal.issuanceId),
      };
    });

    expect(result).toEqual({
      first: "OBSERVE_AND_SEAL",
      firstDirect: ["EXECUTE_EFFECT", "EXECUTE_EFFECT", "EXECUTE_EFFECT"],
      retry: "RESUME_BATCH",
      states: [
        "CONTROLLER_ACTION:FROZEN",
        "CONTROLLER_OIDC:DELEGATED_IN_FLIGHT",
        "TARGET_OIDC:DELEGATED_IN_FLIGHT",
        "TARGET_RULESET:DELEGATED_IN_FLIGHT",
        "CLOUDFLARE_BATCH:DELEGATED_IN_FLIGHT",
      ],
    });
  });

  it("rolls back every direct seal when the final Cloudflare row update aborts", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-provision-rollback-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const journal = await frozenProvisionJournal(state.storage);
      const cloudflare = await activationOperationCloudflareFixture(journal);
      state.storage.sql.exec(`
        CREATE TRIGGER reject_cloudflare_seal
        BEFORE UPDATE OF batch_id ON activation_operation_slots
        WHEN NEW.slot_id = 'CLOUDFLARE_BATCH'
        BEGIN
          SELECT RAISE(ABORT, 'injected Cloudflare seal crash');
        END;
      `);
      let rejected = false;
      try {
        await journal.effects.delegateProvision(journal.issuanceId, cloudflare.outerRequestBytes);
      } catch {
        rejected = true;
      }
      return {
        rejected,
        states: slotStates(state.storage, journal.issuanceId),
      };
    });

    expect(result.rejected).toBe(true);
    expect(result.states).toEqual([
      "CONTROLLER_ACTION:FROZEN",
      "CONTROLLER_OIDC:FROZEN",
      "TARGET_OIDC:FROZEN",
      "TARGET_RULESET:FROZEN",
      "CLOUDFLARE_BATCH:PREPARED",
    ]);
  });

  it("expires an undispatched plan without leaving a partial durable delegation", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-provision-expired-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const journal = await frozenProvisionJournal(state.storage);
      const cloudflare = await activationOperationCloudflareFixture(journal);
      const freshUntil = state.storage.sql
        .exec<{
          readonly fresh_until: string;
        }>(
          "SELECT fresh_until FROM activation_operation_issuances WHERE issuance_id = ?",
          journal.issuanceId,
        )
        .one().fresh_until;
      const expired = new ActivationOperationEffects(
        state.storage,
        () => Date.parse(freshUntil) + 1,
      );
      let code = "";
      try {
        await expired.delegateProvision(journal.issuanceId, cloudflare.outerRequestBytes);
      } catch (error) {
        code = error instanceof Error ? error.message : "unknown";
      }
      return {
        code,
        issuanceState: state.storage.sql
          .exec<{
            readonly state: string;
          }>(
            "SELECT state FROM activation_operation_issuances WHERE issuance_id = ?",
            journal.issuanceId,
          )
          .one().state,
        states: slotStates(state.storage, journal.issuanceId),
      };
    });

    expect(result.code).toContain("ACTIVATION_OPERATION_ISSUANCE_EXPIRED");
    expect(result.issuanceState).toBe("EXPIRED_UNDISPATCHED");
    expect(result.states.slice(1)).toEqual([
      "CONTROLLER_OIDC:FROZEN",
      "TARGET_OIDC:FROZEN",
      "TARGET_RULESET:FROZEN",
      "CLOUDFLARE_BATCH:PREPARED",
    ]);
  });
});

async function frozenProvisionJournal(storage: DurableObjectStorage) {
  const journal = await operationJournal(storage);
  await freeze(journal.store, journal.issuanceId, "CONTROLLER_ACTION", 700);
  for (const [index, slotId] of DIRECT_SLOTS.entries()) {
    await freeze(journal.store, journal.issuanceId, slotId, 710 + index);
  }
  return journal;
}

function slotStates(storage: DurableObjectStorage, issuanceId: string): readonly string[] {
  return storage.sql
    .exec<{ readonly slot_id: string; readonly state: string }>(
      `SELECT slot_id, state FROM activation_operation_slots
       WHERE issuance_id = ? ORDER BY slot_index`,
      issuanceId,
    )
    .toArray()
    .map(({ slot_id, state }) => `${slot_id}:${state}`);
}
