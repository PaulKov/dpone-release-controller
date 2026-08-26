import { canonicalBytes } from "./canonical";
import { CloudflareDeploymentObserverClient } from "./cloudflare-deployment-observer-client";
import { requireLiveConfig } from "./config";
import {
  buildServiceAuthorityObservation,
  type ServiceAuthorityExpectation,
} from "./service-authority-activation";
import type { MirroredProviderEvidence } from "./activation-schema";
import type { RawProviderEvidenceKind } from "./provider-evidence";
import type { JsonObject, LiveConfigEnv, PrivateServicePin } from "./types";
import type { WormMirrorClient } from "./worm-client";
import {
  canonicalTimestamp,
  digestBytes,
  requirePrivateFetcher,
} from "./activation-registry-codec";

/** Provider-evidence helpers kept outside the registry state-machine facade. */
export class ActivationRegistryEvidence {
  public constructor(private readonly env: LiveConfigEnv) {}

  public async observeServiceAuthorities(
    expectation: ServiceAuthorityExpectation,
    phase: "A0_PRE" | "A1_PRECOMMIT",
    requestId: string,
    observerPin: PrivateServicePin,
  ): Promise<JsonObject> {
    const config = requireLiveConfig(this.env);
    const service = requirePrivateFetcher(
      this.env.CLOUDFLARE_DEPLOYMENT_OBSERVER,
      "CLOUDFLARE_DEPLOYMENT_OBSERVER_UNAVAILABLE",
    );
    const accepted = await new CloudflareDeploymentObserverClient(
      service,
      observerPin,
      config.cloudflareAccountId,
      {
        key: config.cloudflareObserverRpcAuthKey,
        serviceIdentity: config.workerServiceIdentity,
        versionId: config.workerVersionId,
      },
    ).observe({
      expectedDeployments:
        phase === "A0_PRE" ? expectation.a0PreDeployments : expectation.a1PrecommitDeployments,
      expectationSha256: expectation.expectationSha256,
      expectedNetworkSurface: expectation.networkSurface,
      inventory: expectation.authorities,
      phase,
      requestId,
    });
    return buildServiceAuthorityObservation(accepted, expectation.expectationSha256);
  }

  public async mirrorProviderEvidence(
    client: WormMirrorClient,
    evidence: JsonObject,
    evidenceKind: RawProviderEvidenceKind,
    ingressWorkerVersion: string,
  ): Promise<MirroredProviderEvidence> {
    const bytes = canonicalBytes(evidence);
    const canonicalSha256 = await digestBytes(bytes);
    const worm = await client.mirrorEvidence({
      bytes,
      committedAt: canonicalTimestamp(Date.now()),
      digest: canonicalSha256,
      evidenceKind,
      ingressWorkerVersion,
    });
    return { canonicalSha256, evidence, worm };
  }
}
