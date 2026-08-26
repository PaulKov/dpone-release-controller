import { DurableObject } from "cloudflare:workers";

import { B2VersionObserverClient } from "../b2-version-observer-client";
import { BrokerError, errorResponse } from "../errors";
import {
  prepareWormExactObjectEffect,
  type WormExactObjectEffectInput,
} from "../worm-exact-object-effect-contract";
import { buildWormExactObjectEffectResult } from "../worm-exact-object-effect-result";
import { parseWormExactObjectEffectDocument } from "../worm-exact-object-effect-rpc";
import { assertWormExactObjectEffectKeyBinding } from "../worm-exact-object-effect-rpc";
import { WormExactObjectEffectRunner } from "../worm-exact-object-effect-runner";
import { WormExactObjectEffectStore } from "../worm-exact-object-effect-store";
import { B2NativeWriter } from "./b2-native";
import {
  type WormMirrorEnv,
  assertExpectedB2ObserverPin,
  requireConfig,
  requireVersionId,
  requireWormServiceIdentity,
} from "./worm-mirror-worker-helpers";

export interface WormExactObjectEffectRpcInput {
  readonly canonicalBytes: ArrayBuffer;
  readonly committedAt: string;
  readonly digest: string;
  readonly effectId: string;
  readonly key: string;
  readonly ingressVersionId: string;
  readonly observerServiceIdentity: string;
  readonly observerServiceName: string;
  readonly observerVersionId: string;
}

/** WORM-owned singleton journal; retries after dispatch are observer-only. */
export class WormExactObjectEffect extends DurableObject<WormMirrorEnv> {
  private readonly store: WormExactObjectEffectStore;
  private serialTail: Promise<void> = Promise.resolve();

  public constructor(ctx: DurableObjectState, env: WormMirrorEnv) {
    super(ctx, env);
    this.store = new WormExactObjectEffectStore(ctx.storage);
  }

  public execute(input: WormExactObjectEffectRpcInput): Promise<ArrayBuffer> {
    return this.exclusive(async () => {
      const bytes = boundedBytes(input.canonicalBytes);
      const document = parseWormExactObjectEffectDocument(bytes);
      const observerPin = {
        serviceIdentity: input.observerServiceIdentity,
        serviceName: input.observerServiceName,
        versionId: input.observerVersionId,
      };
      assertExpectedB2ObserverPin(observerPin, this.env);
      const effectInput: WormExactObjectEffectInput = {
        canonicalBytes: bytes,
        committedAt: input.committedAt,
        digest: input.digest,
        key: input.key,
        pins: {
          executorServiceIdentity: requireWormServiceIdentity(this.env),
          executorVersionId: requireVersionId(this.env),
          observerServiceIdentity: observerPin.serviceIdentity,
          observerVersionId: observerPin.versionId,
        },
      };
      const prepared = await prepareWormExactObjectEffect(effectInput);
      await assertWormExactObjectEffectKeyBinding(
        document,
        prepared.key,
        prepared.digest,
        input.ingressVersionId,
      );
      if (prepared.effectId !== input.effectId) {
        throw new BrokerError("WORM_EXACT_OBJECT_EFFECT_RPC_BINDING_INVALID", 409, false);
      }
      const observer = this.env.WORM_VERSION_OBSERVER;
      if (observer === undefined || typeof observer.fetch !== "function") {
        throw new BrokerError("B2_OBSERVER_UNAVAILABLE", 503, true);
      }
      const confirmed = await new WormExactObjectEffectRunner(
        this.store,
        new B2NativeWriter(requireConfig(this.env)),
        new B2VersionObserverClient(observer, observerPin),
      ).execute(prepared);
      return Uint8Array.from(buildWormExactObjectEffectResult(confirmed)).buffer;
    });
  }

  public override fetch(request: Request): Response {
    const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
    return errorResponse(new BrokerError("INTERNAL_RPC_REQUIRED", 404, false), requestId);
  }

  private async exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.serialTail;
    let release: (() => void) | undefined;
    this.serialTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release?.();
    }
  }
}

function boundedBytes(value: ArrayBuffer): Uint8Array {
  if (value.byteLength < 1 || value.byteLength > 65_536) {
    throw new BrokerError("WORM_EXACT_OBJECT_EFFECT_RPC_SIZE_INVALID", 413, false);
  }
  return Uint8Array.from(new Uint8Array(value));
}
