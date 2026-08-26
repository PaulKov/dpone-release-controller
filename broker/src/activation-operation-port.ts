import type { ActivationOperationCloudflareRequest } from "./activation-operation-cloudflare-request";
import type { ActivationOperationReadPlan } from "./activation-operation-read-plan";
import type { ProvisionRequest } from "./activation-schema";
import type { PrivateServicePin } from "./types";
import type { PreparedWormExactObjectEffect } from "./worm-exact-object-effect-contract";

export interface ActivationOperationProviderRead {
  readonly canonicalPayloadBytes: Uint8Array;
  readonly observedAt: string;
}

/**
 * Side-effect port used by the durable coordinator. Implementations may perform
 * provider or WORM I/O only after the runner has persisted the matching intent.
 */
export interface ActivationOperationPort {
  observeCloudflare(
    delegation: ActivationOperationCloudflareRequest,
    observerPin: PrivateServicePin,
  ): Promise<Uint8Array>;

  readProvisionEvidence(
    plan: ActivationOperationReadPlan,
    request: ProvisionRequest,
  ): Promise<ActivationOperationProviderRead>;

  executeWorm(
    effect: PreparedWormExactObjectEffect,
    executorPin: PrivateServicePin,
    observerPin: PrivateServicePin,
    internalRequestId: string,
  ): Promise<Uint8Array>;
}
