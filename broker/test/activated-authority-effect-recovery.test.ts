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
import { effectReplayBindingBody } from "../src/auth-replay-ledger";
import { canonicalJson } from "../src/canonical";
import type { GlobalActivatedAuthorityHead } from "../src/global-activated-authority-head";
import type { JsonObject } from "../src/types";
import {
  confirmedHead,
  requiredString,
  reserveRequestFor,
} from "./activated-authority-effect.fixtures";

afterEach(async () => reset());

describe("activated-authority effect crash recovery", () => {
  it("cancels PREPARED atomically before rearming and fences a late original commit", async () => {
    const stub = env.GLOBAL_ACTIVATED_AUTHORITY_HEAD.getByName("global:v1");
    let originalBinding: JsonObject | undefined;
    await runInDurableObject(stub, async (instance, state) => {
      const head = await confirmedHead(
        new ActivatedAuthorityHeadStore(state.storage),
        1,
        "GENESIS",
        31,
      );
      const original = await reserveAndSeal(
        instance,
        head,
        "activation-effect-original-0031",
        731,
        831,
      );
      await dispatch(instance, original.reservation, "activation-effect-original-0031");
      originalBinding = replayBinding(original.reservation);

      const refreshed = await parseAuthorityEffectReserveResult(
        await instance.reserveActivationProofEffect(
          reserveRequestFor(head, "activation-effect-refreshed-0031", Date.now(), 731, 931),
        ),
      );
      expect(refreshed.status).toBe("RESERVED");
      expect(refreshed.reservation.reservation_id).toBe(original.reservation.reservation_id);
      expect(refreshed.reservation.request_id).toBe("activation-effect-refreshed-0031");

      const ledger = env.AUTH_REPLAY_LEDGER.getByName("github-oidc-v1");
      await expect(ledger.observePreparedEffectExact(originalBinding)).resolves.toMatchObject({
        state: "CANCELLED",
      });
    });
    if (originalBinding === undefined) throw new Error("original binding missing");
    const committedBinding = originalBinding;
    await runInDurableObject(
      env.AUTH_REPLAY_LEDGER.getByName("github-oidc-v1"),
      async (instance) => {
        expect(() => instance.commitPreparedEffectExact(committedBinding)).toThrow(
          "OIDC_REPLAY_RECONCILIATION_CONFLICT",
        );
      },
    );
  });

  it("confirms sealed bytes when replay commit succeeded but the head confirmation was lost", async () => {
    const stub = env.GLOBAL_ACTIVATED_AUTHORITY_HEAD.getByName("global:v1");
    await runInDurableObject(stub, async (instance, state) => {
      const head = await confirmedHead(
        new ActivatedAuthorityHeadStore(state.storage),
        1,
        "GENESIS",
        32,
      );
      const original = await reserveAndSeal(
        instance,
        head,
        "activation-effect-original-0032",
        732,
        832,
      );
      await dispatch(instance, original.reservation, "activation-effect-original-0032");
      await env.AUTH_REPLAY_LEDGER.getByName("github-oidc-v1").commitPreparedEffectExact(
        replayBinding(original.reservation),
      );

      const recovered = await parseAuthorityEffectReserveResult(
        await instance.reserveActivationProofEffect(
          reserveRequestFor(head, "activation-effect-recovery-0032", Date.now(), 732, 932),
        ),
      );
      expect(recovered.status).toBe("CONFIRMED");
      expect(recovered.sealedResult).toEqual({ proof: "sealed-832" });
      expect(recovered.sealedResultSha256).toBe(original.resultSha256);
      expect(recovered.reservation.request_id).toBe("activation-effect-original-0032");
      expect(recovered.headProof.request_id).toBe("activation-effect-recovery-0032");
    });
  });

  it("returns the same sealed result after confirmation response loss", async () => {
    const stub = env.GLOBAL_ACTIVATED_AUTHORITY_HEAD.getByName("global:v1");
    await runInDurableObject(stub, async (instance, state) => {
      const head = await confirmedHead(
        new ActivatedAuthorityHeadStore(state.storage),
        1,
        "GENESIS",
        33,
      );
      const original = await reserveAndSeal(
        instance,
        head,
        "activation-effect-original-0033",
        733,
        833,
      );
      await dispatch(instance, original.reservation, "activation-effect-original-0033");
      await confirm(
        instance,
        original.reservation,
        "activation-effect-original-0033",
        original.resultSha256,
      );

      const recovered = await parseAuthorityEffectReserveResult(
        await instance.reserveActivationProofEffect(
          reserveRequestFor(head, "activation-effect-recovery-0033", Date.now(), 733, 933),
        ),
      );
      expect(recovered.status).toBe("CONFIRMED");
      expect(recovered.sealedResultSha256).toBe(original.resultSha256);
    });
  });

  it("never treats DISPATCHED_HOLD plus an absent replay tombstone as safe to retry", async () => {
    const stub = env.GLOBAL_ACTIVATED_AUTHORITY_HEAD.getByName("global:v1");
    await runInDurableObject(stub, async (instance, state) => {
      const head = await confirmedHead(
        new ActivatedAuthorityHeadStore(state.storage),
        1,
        "GENESIS",
        34,
      );
      const original = await reserveAndSeal(
        instance,
        head,
        "activation-effect-original-0034",
        734,
        834,
      );
      const effects = new ActivatedAuthorityEffectStore(state.storage);
      effects.dispatch(requiredString(original.reservation, "reservation_id"), Date.now());

      await expect(
        instance.reserveActivationProofEffect(
          reserveRequestFor(head, "activation-effect-recovery-0034", Date.now(), 734, 934),
        ),
      ).rejects.toThrow("ACTIVATED_AUTHORITY_EFFECT_RECONCILIATION_AMBIGUOUS");
    });
  });
});

async function reserveAndSeal(
  instance: GlobalActivatedAuthorityHead,
  head: Awaited<ReturnType<typeof confirmedHead>>,
  requestId: string,
  intentSeed: number,
  resultSeed: number,
) {
  const accepted = await parseAuthorityEffectReserveResult(
    await instance.reserveActivationProofEffect(
      reserveRequestFor(head, requestId, Date.now(), intentSeed, resultSeed),
    ),
  );
  const reservationId = requiredString(accepted.reservation, "reservation_id");
  const result = canonicalJson({ proof: `sealed-${resultSeed}` });
  const sealed = parseAuthorityEffectStatus(
    await instance.sealActivationProofEffect(transition("SEAL", reservationId, requestId), result),
    reservationId,
  );
  if (sealed.resultSha256 === null) throw new Error("sealed result digest missing");
  return { reservation: accepted.reservation, resultSha256: sealed.resultSha256 };
}

async function dispatch(
  instance: GlobalActivatedAuthorityHead,
  reservation: JsonObject,
  requestId: string,
): Promise<void> {
  const reservationId = requiredString(reservation, "reservation_id");
  const status = parseAuthorityEffectStatus(
    await instance.transitionActivationProofEffect(
      transition("DISPATCH", reservationId, requestId),
    ),
    reservationId,
  );
  expect(status.status).toBe("DISPATCHED_HOLD");
}

async function confirm(
  instance: GlobalActivatedAuthorityHead,
  reservation: JsonObject,
  requestId: string,
  resultSha256: string,
): Promise<void> {
  const reservationId = requiredString(reservation, "reservation_id");
  const status = parseAuthorityEffectStatus(
    await instance.transitionActivationProofEffect(
      transition("CONFIRM", reservationId, requestId, resultSha256),
    ),
    reservationId,
  );
  expect(status.status).toBe("CONFIRMED");
}

function transition(
  action: "CONFIRM" | "DISPATCH" | "SEAL",
  reservationId: string,
  requestId: string,
  resultSha256?: string,
): string {
  return buildAuthorityEffectTransitionRequest({
    action,
    requestId,
    requestedAt: new Date().toISOString(),
    reservationId,
    ...(resultSha256 === undefined ? {} : { resultSha256 }),
  });
}

function replayBinding(reservation: JsonObject): JsonObject {
  const replay = requiredObject(reservation, "replay");
  return effectReplayBindingBody(
    requiredString(replay, "jti_sha256"),
    requiredNumber(replay, "expires_at"),
    requiredString(reservation, "request_id"),
    requiredString(replay, "claims_sha256"),
    requiredString(reservation, "reservation_id"),
  );
}

function requiredObject(value: JsonObject, key: string): JsonObject {
  const candidate = value[key];
  if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
    throw new Error(`missing ${key}`);
  }
  return candidate;
}

function requiredNumber(value: JsonObject, key: string): number {
  const candidate = value[key];
  if (!Number.isSafeInteger(candidate)) throw new Error(`missing ${key}`);
  return candidate as number;
}
