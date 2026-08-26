import { INTERNAL_RESPONSE_READ_POLICY, readBoundedBytes } from "./bounded";
import { BrokerError } from "./errors";
import { callPinnedService } from "./service-version";
import type { PrivateServicePin } from "./types";
import {
  prepareWormExactObjectEffect,
  WORM_EXACT_OBJECT_MAX_BYTES,
  type ConfirmedWormExactObjectEffect,
  type WormExactObjectEffectInput,
} from "./worm-exact-object-effect-contract";
import { parseWormExactObjectEffectResult } from "./worm-exact-object-effect-result";
import {
  assertWormExactObjectEffectKeyBinding,
  parseWormExactObjectEffectDocument,
  WORM_EXACT_OBJECT_EFFECT_RPC_PATH,
  WORM_EXACT_OBJECT_EFFECT_REQUEST_ID,
} from "./worm-exact-object-effect-rpc";
import { signWormRpcRequest, type WormRpcCallerAuth } from "./worm-rpc-auth";

/** Pinned ingress client for one crash-safe exact immutable object effect. */
export class WormExactObjectEffectClient {
  public constructor(
    private readonly service: Fetcher,
    private readonly executorPin: PrivateServicePin,
    private readonly observerPin: PrivateServicePin,
    private readonly callerAuth: WormRpcCallerAuth,
  ) {}

  public async execute(
    input: WormExactObjectEffectInput,
    requestId: string,
    signal?: AbortSignal,
  ): Promise<WormExactObjectEffectResponse> {
    if (!WORM_EXACT_OBJECT_EFFECT_REQUEST_ID.test(requestId)) {
      throw new BrokerError("WORM_EXACT_OBJECT_EFFECT_RPC_REQUEST_ID_INVALID", 400, false);
    }
    const prepared = await prepareWormExactObjectEffect(input);
    const document = parseWormExactObjectEffectDocument(prepared.canonicalBytes);
    this.assertPins(prepared);
    await assertWormExactObjectEffectKeyBinding(
      document,
      prepared.key,
      prepared.digest,
      this.callerAuth.versionId,
    );
    const bytes = prepared.canonicalBytes;
    const headers = new Headers({
      "content-length": String(bytes.byteLength),
      "content-type": "application/json",
      "x-dpone-callee-service": this.executorPin.serviceName,
      "x-dpone-callee-service-identity": this.executorPin.serviceIdentity,
      "x-dpone-callee-version": this.executorPin.versionId,
      "x-dpone-canonical-sha256": prepared.digest,
      "x-dpone-committed-at": prepared.committedAt,
      "x-dpone-effect-id": prepared.effectId,
      "x-dpone-ingress-worker-version": this.callerAuth.versionId,
      "x-dpone-object-key": prepared.key,
      "x-dpone-observer-service": this.observerPin.serviceName,
      "x-dpone-observer-service-identity": this.observerPin.serviceIdentity,
      "x-dpone-observer-version": this.observerPin.versionId,
      "x-request-id": requestId,
    });
    await signWormRpcRequest(headers, WORM_EXACT_OBJECT_EFFECT_RPC_PATH, this.callerAuth);
    const response = await callPinnedService(this.service, this.executorPin, {
      body: Uint8Array.from(bytes).buffer,
      headers: Object.fromEntries(headers),
      method: "POST",
      path: WORM_EXACT_OBJECT_EFFECT_RPC_PATH,
      ...(signal === undefined ? {} : { signal }),
    });
    await requireExactResponse(response);
    const resultBytes = await readBoundedBytes(
      response,
      WORM_EXACT_OBJECT_MAX_BYTES,
      "WORM_EXACT_OBJECT_EFFECT_RPC_RESPONSE_INVALID",
      INTERNAL_RESPONSE_READ_POLICY,
    );
    return {
      canonicalResultBytes: Uint8Array.from(resultBytes),
      confirmed: parseWormExactObjectEffectResult(resultBytes, prepared),
    };
  }

  private assertPins(input: Awaited<ReturnType<typeof prepareWormExactObjectEffect>>): void {
    if (
      input.pins.executorServiceIdentity !== this.executorPin.serviceIdentity ||
      input.pins.executorVersionId !== this.executorPin.versionId ||
      input.pins.observerServiceIdentity !== this.observerPin.serviceIdentity ||
      input.pins.observerVersionId !== this.observerPin.versionId
    ) {
      throw new BrokerError("WORM_EXACT_OBJECT_EFFECT_RPC_PIN_INVALID", 409, false);
    }
  }
}

export interface WormExactObjectEffectResponse {
  readonly canonicalResultBytes: Uint8Array;
  readonly confirmed: ConfirmedWormExactObjectEffect;
}

async function requireExactResponse(response: Response): Promise<void> {
  const media = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (
    response.status !== 200 ||
    media !== "application/json" ||
    response.headers.get("cache-control") !== "no-store" ||
    response.headers.get("x-content-type-options") !== "nosniff" ||
    response.headers.has("content-encoding") ||
    response.headers.has("content-range") ||
    response.headers.has("location") ||
    response.headers.has("set-cookie") ||
    response.headers.has("transfer-encoding")
  ) {
    await response.body
      ?.cancel("WORM_EXACT_OBJECT_EFFECT_RPC_RESPONSE_INVALID")
      .catch(() => undefined);
    throw new BrokerError("WORM_EXACT_OBJECT_EFFECT_RPC_RESPONSE_INVALID", 503, false);
  }
}
