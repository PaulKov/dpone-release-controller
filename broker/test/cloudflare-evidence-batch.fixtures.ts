import {
  CloudflareDeploymentObserver,
  type CloudflareDeploymentObservationResult,
} from "../src/cloudflare-deployment-observation";
import {
  sanitizeCloudflareNetworkEvidence,
  sanitizeCloudflareServiceEvidence,
} from "../src/cloudflare-deployment-observation";
import {
  cloudflareEvidenceBatchBinding,
  type CloudflareEvidenceBatchBinding,
  type CloudflareEvidenceBatchExecution,
  type CloudflareEvidenceBatchSlot,
  type CloudflareEvidenceBatchSlotInput,
} from "../src/cloudflare-evidence-batch-contract";
import { CloudflareWorkersDeploymentReader } from "../src/private/cloudflare-provider";
import type {
  DeploymentObservationPhase,
  ExpectedServiceDeployment,
} from "../src/service-authority";
import type { ActivationWorm, JsonObject } from "../src/types";
import {
  ACCOUNT_ID,
  NETWORK_SURFACE,
  NOW,
  OBSERVER_IDENTITY,
  OBSERVER_VERSION,
  REQUEST_ID,
  digest,
  providerFixture,
} from "./cloudflare-deployment-observer-provider.fixtures";

export const BATCH_OBSERVED_AT = new Date(NOW).toISOString();
export const BATCH_COMMITTED_AT = new Date(NOW + 1_000).toISOString();

export async function cloudflareEvidenceBatchFixture(
  phase: DeploymentObservationPhase = "A1_PRECOMMIT",
  observedAtMs = NOW,
): Promise<{
  readonly binding: CloudflareEvidenceBatchBinding;
  readonly expectedDeployments: readonly ExpectedServiceDeployment[];
  readonly observation: JsonObject;
  readonly slots: readonly CloudflareEvidenceBatchSlotInput[];
  readonly transientResult: CloudflareDeploymentObservationResult;
}> {
  const fixture = await providerFixture(phase);
  const result = await new CloudflareDeploymentObserver(
    new CloudflareWorkersDeploymentReader(
      ACCOUNT_ID,
      "token_abcdefghijklmnopqrstuvwxyz",
      fixture.fetch,
    ),
    ACCOUNT_ID,
    OBSERVER_IDENTITY,
    OBSERVER_VERSION,
    () => observedAtMs,
  ).observe({
    expectedDeployments: fixture.expectedDeployments,
    expectationSha256: digest(996),
    expectedNetworkSurface: NETWORK_SURFACE,
    phase,
    requestId: REQUEST_ID,
  });
  const services = await Promise.all(
    result.evidenceEntries.map(async (transient, slotIndex) => ({
      authorityRole: fixture.expectedDeployments[slotIndex]?.authority_role ?? null,
      kind: "cloudflare_service_deployments" as const,
      sanitized: await sanitizeCloudflareServiceEvidence(transient),
      slotIndex,
    })),
  );
  return {
    binding: await cloudflareEvidenceBatchBinding(digest(996), OBSERVER_VERSION, phase),
    expectedDeployments: fixture.expectedDeployments,
    observation: result.observation,
    slots: Object.freeze([
      ...services,
      {
        authorityRole: null,
        kind: "cloudflare_network_surface",
        sanitized: await sanitizeCloudflareNetworkEvidence(result.networkEvidenceEntry),
        slotIndex: services.length,
      },
    ]),
    transientResult: result,
  };
}

export function cloudflareEvidenceBatchExecution(): CloudflareEvidenceBatchExecution {
  const wormWorkerVersionId = "33333333-3333-3333-3333-333333333333";
  return {
    b2ObserverServiceIdentity:
      `cloudflare-worker:${ACCOUNT_ID}/dpone-release-worm-version-observer@` +
      "22222222-2222-2222-2222-222222222222",
    b2ObserverWorkerVersionId: "22222222-2222-2222-2222-222222222222",
    wormServiceIdentity: `cloudflare-worker:${ACCOUNT_ID}/dpone-release-worm-mirror@${wormWorkerVersionId}`,
    wormWorkerVersionId,
  };
}

export function cloudflareEvidenceBatchWorm(
  slot: CloudflareEvidenceBatchSlot,
  versionId = `b2-cloudflare-evidence-${String(slot.slotIndex).padStart(4, "0")}`,
): ActivationWorm {
  return {
    digest: slot.sanitized.recordSha256,
    key:
      `receipts/v1/cloudflare-observations/${OBSERVER_VERSION}/${slot.kind}/` +
      `${slot.sanitized.recordId.slice(7)}.json`,
    retentionUntil: "2034-08-20T12:00:00.000Z",
    versionId,
  };
}
