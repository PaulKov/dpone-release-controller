import { buildActivationProofEffectReservation } from "../src/activated-authority-effect";
import { buildAuthorityEffectReserveRequest } from "../src/activated-authority-effect-rpc";
import {
  activatedAuthorityHeadKey,
  activatedAuthorityHeadRecordSha256,
  buildActivatedAuthorityHead,
} from "../src/activated-authority-head";
import { buildCurrentHeadProof } from "../src/activated-authority-head-proof";
import type { ActivatedAuthorityHeadStore } from "../src/activated-authority-head-store";
import type { JsonObject } from "../src/types";

export async function confirmedHead(
  store: ActivatedAuthorityHeadStore,
  generation: number,
  previousValue: "GENESIS" | JsonObject,
  seed: number,
) {
  const input = await headInput(generation, previousValue, seed);
  await store.reserveHead(input);
  store.markDispatched(generation);
  await store.confirm(generation, await headWorm(input));
  return input;
}

export async function headInput(
  generation: number,
  previousValue: "GENESIS" | JsonObject,
  seed: number,
) {
  const ingress = uuid(seed);
  const activatedDigest = tagged(seed * 10 + 2);
  const committedAt = new Date(Date.now() - 5_000).toISOString();
  const head = await buildActivatedAuthorityHead({
    activatedRecordId: tagged(seed * 10 + 1),
    activatedRecordSha256: activatedDigest,
    activatedServiceAuthoritiesSha256: tagged(seed * 10 + 3),
    activatedWorm: {
      digest: activatedDigest,
      key: `receipts/v1/activation/${ingress}/1-${activatedDigest.slice(7)}.json`,
      retentionUntil: new Date(Date.now() + 2558 * 86_400_000).toISOString(),
      versionId: `activation-version-${seed}`,
    },
    committedAt,
    generation,
    ingressWorkerVersionId: ingress,
    previous: previousValue,
  });
  return {
    activatedRecordId: tagged(seed * 10 + 1),
    activatedRecordSha256: activatedDigest,
    activatedServiceAuthoritiesSha256: tagged(seed * 10 + 3),
    committedAt,
    generation,
    head,
    ingressWorkerVersionId: ingress,
    recordId: requiredString(head, "record_id"),
    recordSha256: await activatedAuthorityHeadRecordSha256(head),
    requestDigest: tagged(seed * 10 + 4),
  };
}

export async function effect(
  head: Awaited<ReturnType<typeof headInput>>,
  seed: number,
  lifetimeMs = 60_000,
): Promise<JsonObject> {
  const createdAt = Date.now();
  const requestId = `activation-effect-request-${String(seed).padStart(4, "0")}`;
  return buildActivationProofEffectReservation({
    createdAt: new Date(createdAt).toISOString(),
    expiresAt: new Date(createdAt + lifetimeMs).toISOString(),
    headGeneration: head.generation,
    headRecordId: head.recordId,
    headRecordSha256: head.recordSha256,
    headProof: await buildCurrentHeadProof({
      brokerAcceptedAt: new Date(createdAt).toISOString(),
      head: head.head,
      observedAt: new Date(createdAt).toISOString(),
      requestId,
      requestedAt: new Date(createdAt).toISOString(),
      worm: await headWorm(head),
    }),
    intentSha256: tagged(700 + seed),
    replayClaimsSha256: tagged(800 + seed),
    replayExpiresAt: Math.floor((createdAt + 300_000) / 1000),
    replayJtiSha256: tagged(900 + seed),
    requestId,
  });
}

export async function headWorm(input: Awaited<ReturnType<typeof headInput>>) {
  return {
    digest: input.recordSha256,
    key: await activatedAuthorityHeadKey(input.head),
    retentionUntil: new Date(Date.now() + 2558 * 86_400_000).toISOString(),
    versionId: `head-version-${input.generation}`,
  };
}

export function reserveRequestFor(
  head: Awaited<ReturnType<typeof headInput>>,
  requestId: string,
  nowMs: number,
  intentSeed: number,
  replaySeed = intentSeed,
): string {
  return buildAuthorityEffectReserveRequest({
    activatedRecordId: head.activatedRecordId,
    activatedRecordSha256: head.activatedRecordSha256,
    activatedServiceAuthoritiesSha256: head.activatedServiceAuthoritiesSha256,
    expiresAt: new Date(nowMs + 60_000).toISOString(),
    ingressWorkerVersionId: head.ingressWorkerVersionId,
    intentSha256: tagged(intentSeed),
    replayClaimsSha256: tagged(replaySeed + 1),
    replayExpiresAt: Math.floor((nowMs + 300_000) / 1000),
    replayJtiSha256: tagged(replaySeed + 2),
    requestId,
    requestedAt: new Date(nowMs).toISOString(),
  });
}

export function previous(input: Awaited<ReturnType<typeof headInput>>): JsonObject {
  return {
    generation: input.generation,
    record_id: input.recordId,
    record_sha256: input.recordSha256,
  };
}

export function tagged(value: number): string {
  return `sha256:${value.toString(16).padStart(64, "0")}`;
}

export function requiredString(value: JsonObject, key: string): string {
  const candidate = value[key];
  if (typeof candidate !== "string") throw new Error(`missing ${key}`);
  return candidate;
}

function uuid(value: number): string {
  return `00000000-0000-0000-0000-${String(value).padStart(12, "0")}`;
}
