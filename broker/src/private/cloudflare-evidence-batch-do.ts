import { DurableObject } from "cloudflare:workers";

import type { ActivationOperationCloudflareRequest } from "../activation-operation-cloudflare-request";
import { B2VersionObserverClient } from "../b2-version-observer-client";
import { canonicalJson } from "../canonical";
import {
  assertCanonicalCloudflareEvidenceBatchText,
  buildCloudflareEvidenceBatchResult,
  canonicalCloudflareEvidenceBatchBytes,
  prepareCloudflareEvidenceBatch,
  prepareCloudflareEvidenceBatchV2,
} from "../cloudflare-evidence-batch-rpc";
import { buildCloudflareEvidenceBatchResultV2 } from "../cloudflare-evidence-batch-result-v2";
import { parseCloudflareEvidenceBatchResumeV2 } from "../cloudflare-evidence-batch-resume-v2";
import type {
  AnyCloudflareEvidenceBatchBinding,
  CloudflareEvidenceBatchContext,
  CloudflareEvidenceBatchExecution,
  CloudflareEvidenceBatchSlotInput,
} from "../cloudflare-evidence-batch-contract";
import { CloudflareEvidenceBatchStore } from "../cloudflare-evidence-batch-store";
import { BrokerError, errorResponse } from "../errors";
import type { JsonObject, PrivateServicePin } from "../types";
import { B2NativeWriter } from "./b2-native";
import { CloudflareEvidenceBatchRunner } from "./cloudflare-evidence-batch-runner";
import {
  type WormMirrorEnv,
  assertExpectedB2ObserverPin,
  requireConfig,
  requireVersionId,
  requireWormServiceIdentity,
} from "./worm-mirror-worker-helpers";

/**
 * WORM-owned staged Cloudflare evidence batch. Raw control-plane bytes exist
 * only in the RPC argument and are independently reparsed before this object
 * stores the sanitized 15-slot projection.
 */
export class CloudflareEvidenceBatch extends DurableObject<WormMirrorEnv> {
  private readonly store: CloudflareEvidenceBatchStore;
  private serialTail: Promise<void> = Promise.resolve();

  public constructor(ctx: DurableObjectState, env: WormMirrorEnv) {
    super(ctx, env);
    this.store = new CloudflareEvidenceBatchStore(ctx.storage);
  }

  public mirrorBatch(
    canonicalRequest: string,
    expectedBatchId: string,
    committedAt: string,
    observerPin: PrivateServicePin,
  ): Promise<string> {
    return this.exclusive(async () => {
      const request = assertCanonicalCloudflareEvidenceBatchText(canonicalRequest);
      const prepared = await prepareCloudflareEvidenceBatch(request);
      const result = await this.execute(
        prepared,
        expectedBatchId,
        committedAt,
        observerPin,
        buildCloudflareEvidenceBatchResult,
      );
      canonicalCloudflareEvidenceBatchBytes(result);
      return canonicalJson(result);
    });
  }

  public mirrorBatchV2(
    canonicalRequest: string,
    expectedBatchId: string,
    observerPin: PrivateServicePin,
  ): Promise<string> {
    return this.exclusive(async () => {
      const request = assertCanonicalCloudflareEvidenceBatchText(canonicalRequest);
      const prepared = await prepareCloudflareEvidenceBatchV2(request);
      const result = await this.execute(
        prepared,
        expectedBatchId,
        prepared.batchSealedAt,
        observerPin,
        buildCloudflareEvidenceBatchResultV2,
        prepared.delegation,
      );
      canonicalCloudflareEvidenceBatchBytes(result);
      return canonicalJson(result);
    });
  }

  /** Reconcile an existing operation batch without any provider evidence input. */
  public resumeBatchV2(
    canonicalRequest: string,
    observerPin: PrivateServicePin,
  ): Promise<string | null> {
    return this.exclusive(async () => {
      const request = assertCanonicalCloudflareEvidenceBatchText(canonicalRequest);
      const expected = parseCloudflareEvidenceBatchResumeV2(request);
      const execution = this.execution(observerPin);
      const context = this.store.resumeV2(expected, execution);
      if (context === undefined) return null;
      const result = buildCloudflareEvidenceBatchResultV2(context, await this.run(observerPin));
      canonicalCloudflareEvidenceBatchBytes(result);
      return canonicalJson(result);
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

  private async execute(
    prepared: {
      readonly binding: AnyCloudflareEvidenceBatchBinding;
      readonly observation: JsonObject;
      readonly observedAt: string;
      readonly slots: readonly CloudflareEvidenceBatchSlotInput[];
    },
    expectedBatchId: string,
    committedAt: string,
    observerPin: PrivateServicePin,
    buildResult: typeof buildCloudflareEvidenceBatchResult,
    operation?: ActivationOperationCloudflareRequest,
  ): Promise<JsonObject> {
    if (prepared.binding.batchId !== expectedBatchId) {
      throw new BrokerError("CLOUDFLARE_EVIDENCE_BATCH_BINDING_INVALID", 400, false);
    }
    const execution = this.execution(observerPin);
    let context = this.store.resume(expectedBatchId, execution);
    if (context === undefined) {
      await this.store.seal(
        prepared.binding,
        prepared.observedAt,
        committedAt,
        prepared.observation,
        execution,
        prepared.slots,
        operation,
      );
      context = requireContext(this.store.resume(expectedBatchId, execution));
    }
    return buildResult(context, await this.run(observerPin));
  }

  private execution(observerPin: PrivateServicePin): CloudflareEvidenceBatchExecution {
    assertExpectedB2ObserverPin(observerPin, this.env);
    return {
      b2ObserverServiceIdentity: observerPin.serviceIdentity,
      b2ObserverWorkerVersionId: observerPin.versionId,
      wormServiceIdentity: requireWormServiceIdentity(this.env),
      wormWorkerVersionId: requireVersionId(this.env),
    };
  }

  private run(observerPin: PrivateServicePin) {
    const observer = this.env.WORM_VERSION_OBSERVER;
    if (observer === undefined || typeof observer.fetch !== "function") {
      throw new BrokerError("B2_OBSERVER_UNAVAILABLE", 503, true);
    }
    return new CloudflareEvidenceBatchRunner(
      this.store,
      new B2NativeWriter(requireConfig(this.env)),
      new B2VersionObserverClient(observer, observerPin),
    ).run();
  }
}

function requireContext(
  value: CloudflareEvidenceBatchContext | undefined,
): CloudflareEvidenceBatchContext {
  if (value === undefined) {
    throw new BrokerError("CLOUDFLARE_EVIDENCE_BATCH_MISSING", 500, false);
  }
  return value;
}
