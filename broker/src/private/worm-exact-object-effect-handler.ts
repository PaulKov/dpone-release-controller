import { BrokerError, canonicalTextResponse } from "../errors";
import {
  prepareWormExactObjectEffect,
  type WormExactObjectEffectPins,
} from "../worm-exact-object-effect-contract";
import { parseWormExactObjectEffectResult } from "../worm-exact-object-effect-result";
import {
  assertWormExactObjectEffectKeyBinding,
  parseWormExactObjectEffectDocument,
  WORM_EXACT_OBJECT_EFFECT_REQUEST_ID,
} from "../worm-exact-object-effect-rpc";
import {
  type WormMirrorEnv,
  assertExpectedB2ObserverPin,
  exactHeader,
  observerPinFromHeaders,
  requireVersionId,
  requireWormServiceIdentity,
  TAGGED_DIGEST,
  TIMESTAMP,
  VERSION,
} from "./worm-mirror-worker-helpers";

const OBJECT_KEY = /^receipts\/v1\/(?:activation|activation-evidence)\/[A-Za-z0-9._/-]+\.json$/u;

/** Bind signed headers to raw bytes, then delegate to the effect-id singleton DO. */
export async function handleWormExactObjectEffect(
  canonicalBytes: Uint8Array,
  headers: Headers,
  env: WormMirrorEnv,
): Promise<Response> {
  exactHeader(headers, "x-request-id", WORM_EXACT_OBJECT_EFFECT_REQUEST_ID, 75);
  const document = parseWormExactObjectEffectDocument(canonicalBytes);
  const observerPin = observerPinFromHeaders(headers);
  assertExpectedB2ObserverPin(observerPin, env);
  const pins: WormExactObjectEffectPins = {
    executorServiceIdentity: requireWormServiceIdentity(env),
    executorVersionId: requireVersionId(env),
    observerServiceIdentity: observerPin.serviceIdentity,
    observerVersionId: observerPin.versionId,
  };
  const input = {
    canonicalBytes,
    committedAt: exactHeader(headers, "x-dpone-committed-at", TIMESTAMP, 24),
    digest: exactHeader(headers, "x-dpone-canonical-sha256", TAGGED_DIGEST, 71),
    key: exactHeader(headers, "x-dpone-object-key", OBJECT_KEY, 512),
    pins,
  };
  const ingressVersionId = exactHeader(headers, "x-dpone-ingress-worker-version", VERSION, 36);
  await assertWormExactObjectEffectKeyBinding(document, input.key, input.digest, ingressVersionId);
  const prepared = await prepareWormExactObjectEffect(input);
  const expectedEffectId = exactHeader(headers, "x-dpone-effect-id", TAGGED_DIGEST, 71);
  if (prepared.effectId !== expectedEffectId) {
    throw new BrokerError("WORM_EXACT_OBJECT_EFFECT_RPC_BINDING_INVALID", 409, false);
  }
  const namespace = env.WORM_EXACT_OBJECT_EFFECTS;
  if (namespace === undefined || typeof namespace.getByName !== "function") {
    throw new BrokerError("WORM_EXACT_OBJECT_EFFECT_RPC_UNAVAILABLE", 503, true);
  }
  const result = new Uint8Array(
    await namespace.getByName(prepared.effectId).execute({
      canonicalBytes: Uint8Array.from(prepared.canonicalBytes).buffer,
      committedAt: prepared.committedAt,
      digest: prepared.digest,
      effectId: prepared.effectId,
      ingressVersionId,
      key: prepared.key,
      observerServiceIdentity: observerPin.serviceIdentity,
      observerServiceName: observerPin.serviceName,
      observerVersionId: observerPin.versionId,
    }),
  );
  parseWormExactObjectEffectResult(result, prepared);
  return canonicalTextResponse(new TextDecoder("utf-8", { fatal: true }).decode(result));
}
