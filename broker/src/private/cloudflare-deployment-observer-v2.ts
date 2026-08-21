import { parseEmbeddedActivationOperationCloudflareRequest } from "../activation-operation-cloudflare-request";
import {
  assertCloudflareObserverRequestFreshness,
  CloudflareDeploymentObserver,
  type CloudflareDeploymentObservationRpcRequest,
} from "../cloudflare-deployment-observation";
import { CloudflareEvidenceWormBatchV2Client } from "../cloudflare-evidence-worm-batch-v2-client";
import { BrokerError } from "../errors";
import type { JsonObject, PrivateServicePin } from "../types";
import { CloudflareWorkersDeploymentReader } from "./cloudflare-provider";
import type { CloudflareDeploymentObserverConfig } from "./cloudflare-deployment-observer-config";

const ABSOLUTE_TIMEOUT_MS = 45_000;

/** Resume before any provider read; only a proven-missing batch may observe Cloudflare. */
export async function observeCloudflareDeploymentV2(
  body: JsonObject,
  requestId: string,
  config: CloudflareDeploymentObserverConfig,
  now: () => number = Date.now,
): Promise<Uint8Array> {
  const delegation = await parseEmbeddedActivationOperationCloudflareRequest(body);
  if (
    delegation.observerRequest.requestId !== requestId ||
    delegation.pins.cloudflareObserverServiceIdentity !== config.serviceIdentity ||
    delegation.pins.cloudflareObserverWorkerVersionId !== config.workerVersionId
  ) {
    throw new BrokerError("CLOUDFLARE_OBSERVER_V2_BINDING_INVALID", 409, false);
  }
  assertIngressPin(delegation.observerRequest.inventory, config.expectedIngressServiceIdentity);
  assertNetworkScope(delegation.observerRequest.expectedNetworkSurface, config);
  const worm = new CloudflareEvidenceWormBatchV2Client(
    config.wormService,
    authorityPin(delegation.observerRequest.inventory, "worm_mirror"),
    authorityPin(delegation.observerRequest.inventory, "worm_version_observer"),
    config.wormCallerAuth,
  );
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort("CLOUDFLARE_OBSERVER_V2_TIMEOUT"),
    ABSOLUTE_TIMEOUT_MS,
  );
  try {
    const resumed = await worm.resume(delegation, controller.signal);
    if (resumed !== undefined) return resumed.canonicalResultBytes;
    const admittedAt = now();
    assertCloudflareObserverRequestFreshness(delegation.observerRequest.requestedAt, admittedAt);
    if (
      !Number.isSafeInteger(admittedAt) ||
      admittedAt < Date.parse(delegation.committedAt) ||
      admittedAt > Date.parse(delegation.freshUntil) ||
      admittedAt - Date.parse(delegation.committedAt) > 60_000
    ) {
      throw new BrokerError("CLOUDFLARE_OBSERVER_V2_STALE", 409, false);
    }
    const result = await new CloudflareDeploymentObserver(
      new CloudflareWorkersDeploymentReader(config.accountId, config.apiToken),
      config.accountId,
      config.serviceIdentity,
      config.workerVersionId,
      now,
    ).observe(delegation.observerRequest);
    const sealedAtMs = now();
    const observedAt = result.observation.observed_at;
    if (
      typeof observedAt !== "string" ||
      !Number.isSafeInteger(sealedAtMs) ||
      sealedAtMs < Date.parse(observedAt) ||
      sealedAtMs > Date.parse(delegation.freshUntil)
    ) {
      throw new BrokerError("CLOUDFLARE_OBSERVER_V2_STALE", 409, false);
    }
    return (
      await worm.mirror(result, delegation, new Date(sealedAtMs).toISOString(), controller.signal)
    ).canonicalResultBytes;
  } catch (error) {
    if (controller.signal.aborted) {
      throw new BrokerError("CLOUDFLARE_OBSERVER_V2_TIMEOUT", 503, true);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function assertIngressPin(
  inventory: CloudflareDeploymentObservationRpcRequest["inventory"],
  expectedServiceIdentity: string,
): void {
  const ingress = inventory.find((row) => row.authority_role === "release_authority_ingress");
  const expectedVersion = expectedServiceIdentity.slice(
    expectedServiceIdentity.lastIndexOf("@") + 1,
  );
  if (
    ingress?.service_identity !== expectedServiceIdentity ||
    ingress.worker_version_id !== expectedVersion
  ) {
    throw new BrokerError("CLOUDFLARE_OBSERVER_V2_INGRESS_PIN_INVALID", 409, false);
  }
}

function authorityPin(
  inventory: CloudflareDeploymentObservationRpcRequest["inventory"],
  role: "worm_mirror" | "worm_version_observer",
): PrivateServicePin {
  const authority = inventory.find((row) => row.authority_role === role);
  if (authority === undefined) {
    throw new BrokerError("CLOUDFLARE_OBSERVER_AUTHORITY_PIN_MISSING", 503, false);
  }
  return {
    serviceIdentity: authority.service_identity,
    serviceName: authority.service,
    versionId: authority.worker_version_id,
  };
}

function assertNetworkScope(
  network: { readonly hostname: string; readonly zone_id: string },
  config: CloudflareDeploymentObserverConfig,
): void {
  if (
    network.hostname !== config.approvedIngressHostname ||
    network.zone_id !== config.approvedIngressZoneId
  ) {
    throw new BrokerError("CLOUDFLARE_NETWORK_SCOPE_MISMATCH", 409, false);
  }
}
