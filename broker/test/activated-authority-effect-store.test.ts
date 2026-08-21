import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import {
  buildAuthorityEffectTransitionRequest,
  parseAuthorityEffectReserveResult,
  parseAuthorityEffectStatus,
} from "../src/activated-authority-effect-rpc";
import { ActivatedAuthorityEffectStore } from "../src/activated-authority-effect-store";
import { ActivatedAuthorityHeadStore } from "../src/activated-authority-head-store";
import { canonicalJson } from "../src/canonical";
import {
  confirmedHead,
  effect,
  headInput,
  headWorm,
  previous,
  requiredString,
  reserveRequestFor,
} from "./activated-authority-effect.fixtures";

afterEach(async () => reset());

describe("activated-authority one-use effect reservations", () => {
  it("pins one activation-proof effect to the current head through dispatch and confirmation", async () => {
    const stub = env.GLOBAL_ACTIVATED_AUTHORITY_HEAD.getByName("global:v1");
    await runInDurableObject(stub, async (_instance, state) => {
      const headStore = new ActivatedAuthorityHeadStore(state.storage);
      const head = await confirmedHead(headStore, 1, "GENESIS", 1);
      const effects = new ActivatedAuthorityEffectStore(state.storage);
      const reservation = await effect(head, 1);

      await expect(effects.reserve(reservation)).resolves.toMatchObject({ status: "RESERVED" });
      const result = await sealResult(effects, requiredString(reservation, "reservation_id"), 901);
      expect(
        effects.dispatch(requiredString(reservation, "reservation_id"), Date.now()).status,
      ).toBe("DISPATCHED_HOLD");
      expect(effects.confirm(requiredString(reservation, "reservation_id"), result)).toMatchObject({
        result_sha256: result,
        status: "CONFIRMED",
      });
      expect(effects.confirm(requiredString(reservation, "reservation_id"), result).status).toBe(
        "CONFIRMED",
      );
    });
  });

  it("blocks head advance during reserved or ambiguous effects but releases terminal effects", async () => {
    const stub = env.GLOBAL_ACTIVATED_AUTHORITY_HEAD.getByName("global:v1");
    await runInDurableObject(stub, async (_instance, state) => {
      const headStore = new ActivatedAuthorityHeadStore(state.storage);
      const first = await confirmedHead(headStore, 1, "GENESIS", 2);
      const effects = new ActivatedAuthorityEffectStore(state.storage);
      const reserved = await effect(first, 2);
      await effects.reserve(reserved);
      const second = await headInput(2, previous(first), 3);
      await expect(headStore.reserveHead(second)).rejects.toThrow(
        "ACTIVATED_AUTHORITY_HEAD_ADVANCE_BLOCKED",
      );

      effects.cancelUndispatched(requiredString(reserved, "reservation_id"));
      await expect(headStore.reserveHead(second)).resolves.toMatchObject({ generation: 2 });
      headStore.markDispatched(2);
      await headStore.confirm(2, await headWorm(second));

      const ambiguous = await effect(second, 3);
      await effects.reserve(ambiguous);
      await sealResult(effects, requiredString(ambiguous, "reservation_id"), 902);
      effects.dispatch(requiredString(ambiguous, "reservation_id"), Date.now());
      const third = await headInput(3, previous(second), 4);
      await expect(headStore.reserveHead(third)).rejects.toThrow(
        "ACTIVATED_AUTHORITY_HEAD_ADVANCE_BLOCKED",
      );
    });
  });

  it("rejects stale heads and expires only never-dispatched reservations", async () => {
    const stub = env.GLOBAL_ACTIVATED_AUTHORITY_HEAD.getByName("global:v1");
    await runInDurableObject(stub, async (_instance, state) => {
      const headStore = new ActivatedAuthorityHeadStore(state.storage);
      const current = await confirmedHead(headStore, 1, "GENESIS", 5);
      const effects = new ActivatedAuthorityEffectStore(state.storage);
      const stale = await effect(await headInput(1, "GENESIS", 10), 10);
      await expect(effects.reserve(stale)).rejects.toThrow("ACTIVATED_AUTHORITY_HEAD_STALE");

      const expiring = await effect(current, 6, 1);
      await effects.reserve(expiring);
      expect(() =>
        effects.dispatch(requiredString(expiring, "reservation_id"), Date.now() + 2_000),
      ).toThrow("ACTIVATED_AUTHORITY_EFFECT_NOT_DISPATCHABLE");
      expect(effects.find(requiredString(expiring, "reservation_id"))?.status).toBe(
        "EXPIRED_UNDISPATCHED",
      );
    });
  });

  it("atomically reserves the current head through the account-global RPC", async () => {
    const stub = env.GLOBAL_ACTIVATED_AUTHORITY_HEAD.getByName("global:v1");
    await runInDurableObject(stub, async (instance, state) => {
      const head = await confirmedHead(
        new ActivatedAuthorityHeadStore(state.storage),
        1,
        "GENESIS",
        7,
      );
      const requestId = "activation-effect-rpc-request-0001";
      const now = Date.now();
      const reserveRequest = reserveRequestFor(head, requestId, now, 707);
      const accepted = await parseAuthorityEffectReserveResult(
        await instance.reserveActivationProofEffect(reserveRequest),
      );
      const reservationId = requiredString(accepted.reservation, "reservation_id");
      expect(accepted.headProof.request_id).toBe(requestId);

      const sealed = parseAuthorityEffectStatus(
        await instance.sealActivationProofEffect(
          buildAuthorityEffectTransitionRequest({
            action: "SEAL",
            requestId,
            requestedAt: new Date(Date.now()).toISOString(),
            reservationId,
          }),
          canonicalJson({ proof: "sealed" }),
        ),
        reservationId,
      );
      expect(sealed.status).toBe("SEALED");

      const dispatched = parseAuthorityEffectStatus(
        await instance.transitionActivationProofEffect(
          buildAuthorityEffectTransitionRequest({
            action: "DISPATCH",
            requestId,
            requestedAt: new Date(Date.now()).toISOString(),
            reservationId,
          }),
        ),
        reservationId,
      );
      expect(dispatched.status).toBe("DISPATCHED_HOLD");
      if (sealed.resultSha256 === null) throw new Error("sealed result digest missing");
      const result = sealed.resultSha256;
      const confirmed = parseAuthorityEffectStatus(
        await instance.transitionActivationProofEffect(
          buildAuthorityEffectTransitionRequest({
            action: "CONFIRM",
            requestId,
            requestedAt: new Date(Date.now()).toISOString(),
            reservationId,
            resultSha256: result,
          }),
        ),
        reservationId,
      );
      expect(confirmed).toEqual({ resultSha256: result, status: "CONFIRMED" });
    });
  });

  it("never relabels a historical confirmed generation as the current head", async () => {
    const stub = env.GLOBAL_ACTIVATED_AUTHORITY_HEAD.getByName("global:v1");
    await runInDurableObject(stub, async (instance, state) => {
      const store = new ActivatedAuthorityHeadStore(state.storage);
      const first = await confirmedHead(store, 1, "GENESIS", 8);
      await confirmedHead(store, 2, previous(first), 9);

      await expect(
        instance.reserveActivationProofEffect(
          reserveRequestFor(first, "activation-effect-old-head-0001", Date.now(), 709),
        ),
      ).rejects.toThrow("ACTIVATED_AUTHORITY_HEAD_STALE");
    });
  });
});

async function sealResult(
  store: ActivatedAuthorityEffectStore,
  reservationId: string,
  seed: number,
): Promise<string> {
  const row = await store.seal(reservationId, canonicalJson({ proof: seed }));
  if (row.result_sha256 === null) throw new Error("sealed result digest missing");
  return row.result_sha256;
}
