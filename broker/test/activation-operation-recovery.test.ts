import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { parseActivationOperationCloudflareRequest } from "../src/activation-operation-cloudflare-request";
import { canonicalBytes } from "../src/canonical";
import type { JsonObject } from "../src/types";
import {
  activationOperationCloudflareFixture,
  prepareCloudflarePredecessors,
} from "./activation-operation-cloudflare.fixtures";
import {
  COMMITTED_AT,
  confirmedDirectResult,
  DIRECT_SLOTS,
  freeze,
  operationJournal,
  PINS,
} from "./activation-operation-effects.fixtures";

afterEach(async () => {
  await reset();
});

describe("activation operation recovery gates", () => {
  it("recovers DISPATCHED_HOLD only after the exact full roster is confirmed", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-effects-hold-ready-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      await freeze(journal.store, journal.issuanceId, "CONTROLLER_ACTION", 0);
      for (const [index, slotId] of DIRECT_SLOTS.entries()) {
        await freeze(journal.store, journal.issuanceId, slotId, index + 1);
        const delegated = await journal.effects.delegate(
          journal.issuanceId,
          slotId,
          COMMITTED_AT,
          PINS,
        );
        await journal.effects.confirmDirect(
          journal.issuanceId,
          slotId,
          confirmedDirectResult(delegated.effect, slotId, index + 70),
        );
      }
      await prepareCloudflarePredecessors(state.storage, journal);
      const cloudflare = await activationOperationCloudflareFixture(journal);
      await journal.effects.delegateCloudflare(journal.issuanceId, cloudflare.outerRequestBytes);
      state.storage.sql.exec(
        `UPDATE activation_operation_issuances SET state = 'DISPATCHED_HOLD'
         WHERE issuance_id = ?`,
        journal.issuanceId,
      );
      const incomplete = journal.effects.readyToAppend(journal.issuanceId);
      await journal.effects.confirmCloudflare(journal.issuanceId, cloudflare.resultBytes);
      const recovered = journal.effects.readyToAppend(journal.issuanceId);
      const stateAfterRecovery = state.storage.sql
        .exec<{
          readonly state: string;
        }>(
          `SELECT state FROM activation_operation_issuances WHERE issuance_id = ?`,
          journal.issuanceId,
        )
        .one().state;
      return { incomplete, recovered, stateAfterRecovery };
    });

    expect(result).toEqual({
      incomplete: false,
      recovered: true,
      stateAfterRecovery: "READY_TO_APPEND",
    });
  });

  it("rejects a Cloudflare observer request timestamp before its issuance", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-effects-observer-time-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      const cloudflare = await activationOperationCloudflareFixture(journal);
      const document = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(cloudflare.outerRequestBytes),
      ) as JsonObject;
      const observerRequest = document.observer_request as JsonObject;
      observerRequest.requested_at = new Date(
        Date.parse(journal.issuance.issuedAt) - 1,
      ).toISOString();

      await expect(
        parseActivationOperationCloudflareRequest(canonicalBytes(document), {
          ingressWorkerVersionId: cloudflare.delegation.issuance.ingressWorkerVersionId,
          internalRequestId: journal.issuance.internalRequestId,
          issuanceId: journal.issuance.issuanceId,
          issuedAt: journal.issuance.issuedAt,
          ordinal: journal.issuance.ordinal,
          sequence: journal.issuance.sequence,
          freshUntil: journal.issuance.freshUntil,
        }),
      ).rejects.toThrow("ACTIVATION_OPERATION_CLOUDFLARE_REQUEST_BINDING_INVALID");
    });
  });
});
