import type { ActivationOperationCloudflareRequest } from "./activation-operation-cloudflare-request";
import type {
  ActivationOperationPort,
  ActivationOperationProviderRead,
} from "./activation-operation-port";
import {
  provisionReadPlan,
  requireProvisionReadPlan,
  type ActivationOperationReadPlan,
} from "./activation-operation-read-plan";
import { parseProvisionRequest, type ProvisionRequest } from "./activation-schema";
import {
  canonicalTimestamp,
  decodeCanonicalObject,
  requireObjectField,
  requirePrivateFetcher,
  requireStringField,
} from "./activation-registry-codec";
import { canonicalBytes } from "./canonical";
import { CloudflareDeploymentObserverV2Client } from "./cloudflare-deployment-observer-v2-client";
import {
  ControllerActionBundleClient,
  controllerActionBundleAppPin,
} from "./controller-action-bundle-client";
import { BrokerError } from "./errors";
import { GitHubOidcEvidenceClient } from "./github-oidc-evidence-client";
import { TRUST } from "./config";
import { TargetRulesetClient } from "./target-ruleset-client";
import type { LiveConfigEnv, PrivateServicePin, TrustedRuntimeConfig } from "./types";
import type { PreparedWormExactObjectEffect } from "./worm-exact-object-effect-contract";
import { WormExactObjectEffectClient } from "./worm-exact-object-effect-client";

/** Production adapter for every remote call authorized by the operation journal. */
export class ActivationOperationRuntimePort implements ActivationOperationPort {
  public constructor(
    private readonly env: LiveConfigEnv,
    private readonly config: TrustedRuntimeConfig,
    private readonly now: () => number = Date.now,
  ) {}

  public async observeCloudflare(
    delegation: ActivationOperationCloudflareRequest,
    observerPin: PrivateServicePin,
  ): Promise<Uint8Array> {
    const service = requirePrivateFetcher(
      this.env.CLOUDFLARE_DEPLOYMENT_OBSERVER,
      "CLOUDFLARE_DEPLOYMENT_OBSERVER_UNAVAILABLE",
    );
    const response = await new CloudflareDeploymentObserverV2Client(service, observerPin, {
      key: this.config.cloudflareObserverRpcAuthKey,
      serviceIdentity: this.config.workerServiceIdentity,
      versionId: this.config.workerVersionId,
    }).observe(delegation);
    return response.canonicalResultBytes;
  }

  public async readProvisionEvidence(
    plan: ActivationOperationReadPlan,
    request: ProvisionRequest,
  ): Promise<ActivationOperationProviderRead> {
    const ownedRequest = parseProvisionRequest(
      decodeCanonicalObject(canonicalBytes(request.body)),
      this.config,
    );
    const ownedPlan = snapshotReadPlan(plan);
    const expectedPlan = requireProvisionReadPlan(
      provisionReadPlan(ownedRequest, ownedRequest.requestId),
      ownedPlan.slotId,
    );
    assertSameReadPlan(ownedPlan, expectedPlan);
    if (ownedPlan.slotId === "CONTROLLER_ACTION") {
      return this.controllerAction(ownedRequest, ownedPlan);
    }
    if (ownedPlan.slotId === "CONTROLLER_OIDC") {
      return this.oidc(ownedRequest, ownedPlan, true);
    }
    if (ownedPlan.slotId === "TARGET_OIDC") {
      return this.oidc(ownedRequest, ownedPlan, false);
    }
    return this.targetRuleset(ownedRequest, ownedPlan);
  }

  public async executeWorm(
    effect: PreparedWormExactObjectEffect,
    executorPin: PrivateServicePin,
    observerPin: PrivateServicePin,
    internalRequestId: string,
  ): Promise<Uint8Array> {
    const service = requirePrivateFetcher(this.env.WORM_MIRROR, "WORM_MIRROR_UNAVAILABLE");
    const response = await new WormExactObjectEffectClient(service, executorPin, observerPin, {
      key: this.config.wormRpcAuthKey,
      serviceIdentity: this.config.workerServiceIdentity,
      versionId: this.config.workerVersionId,
    }).execute(effect, internalRequestId);
    return response.canonicalResultBytes;
  }

  private async controllerAction(
    request: ProvisionRequest,
    plan: ActivationOperationReadPlan,
  ): Promise<ActivationOperationProviderRead> {
    const service = requirePrivateFetcher(
      this.env.CONTROLLER_RUN_READER,
      "CONTROLLER_RUN_READER_UNAVAILABLE",
    );
    const apps = requireObjectField(request.evidence, "github_apps");
    const observation = await new ControllerActionBundleClient(
      service,
      plan.providerPin,
      controllerActionBundleAppPin(requireObjectField(apps, "controller_run_reader")),
    ).observe(
      requireStringField(request.controller, "controller_action_commit_sha"),
      request.requestId,
    );
    return {
      canonicalPayloadBytes: canonicalBytes(observation.observation),
      observedAt: canonicalTimestamp(this.now()),
    };
  }

  private async oidc(
    request: ProvisionRequest,
    plan: ActivationOperationReadPlan,
    controller: boolean,
  ): Promise<ActivationOperationProviderRead> {
    const service = requirePrivateFetcher(
      controller ? this.env.CONTROLLER_RUN_READER : this.env.GOVERNANCE_READER,
      controller ? "CONTROLLER_RUN_READER_UNAVAILABLE" : "GOVERNANCE_READER_UNAVAILABLE",
    );
    const evidence = await new GitHubOidcEvidenceClient(
      service,
      plan.providerPin,
      controller
        ? {
            observerRole: "controller_run_reader",
            repository: TRUST.controllerRepository,
            repositoryId: TRUST.controllerRepositoryId,
          }
        : {
            observerRole: "governance_reader",
            repository: TRUST.targetRepository,
            repositoryId: TRUST.targetRepositoryId,
          },
      this.now,
    ).observe(request.requestId);
    return {
      canonicalPayloadBytes: canonicalBytes(evidence),
      observedAt: normalizedProviderTimestamp(requireStringField(evidence, "observed_at")),
    };
  }

  private async targetRuleset(
    request: ProvisionRequest,
    plan: ActivationOperationReadPlan,
  ): Promise<ActivationOperationProviderRead> {
    const service = requirePrivateFetcher(
      this.env.GOVERNANCE_READER,
      "GOVERNANCE_READER_UNAVAILABLE",
    );
    const governance = requireObjectField(request.evidence, "target_governance");
    const observation = await new TargetRulesetClient(service, plan.providerPin, this.now).observe(
      requireStringField(governance, "branch_ruleset_id"),
      requireObjectField(governance, "branch_ruleset_projection"),
      requireStringField(governance, "branch_ruleset_projection_sha256"),
      request.requestId,
    );
    return {
      canonicalPayloadBytes: canonicalBytes(observation.evidence),
      observedAt: normalizedProviderTimestamp(
        requireStringField(observation.evidence, "observed_at"),
      ),
    };
  }
}

function snapshotReadPlan(plan: ActivationOperationReadPlan): ActivationOperationReadPlan {
  if (plan.canonicalRequestBytes.byteLength < 1 || plan.canonicalRequestBytes.byteLength > 65_536) {
    throw new BrokerError("ACTIVATION_OPERATION_EFFECT_REQUEST_SIZE_INVALID", 413, false);
  }
  return {
    canonicalRequestBytes: Uint8Array.from(plan.canonicalRequestBytes),
    providerPin: { ...plan.providerPin },
    slotId: plan.slotId,
  };
}

function assertSameReadPlan(
  actual: ActivationOperationReadPlan,
  expected: ActivationOperationReadPlan,
): void {
  if (
    actual.providerPin.serviceIdentity !== expected.providerPin.serviceIdentity ||
    actual.providerPin.serviceName !== expected.providerPin.serviceName ||
    actual.providerPin.versionId !== expected.providerPin.versionId ||
    !sameBytes(actual.canonicalRequestBytes, expected.canonicalRequestBytes)
  ) {
    throw new BrokerError("ACTIVATION_OPERATION_PROVIDER_REQUEST_CONFLICT", 409, false);
  }
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function normalizedProviderTimestamp(value: string): string {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) {
    throw new BrokerError("ACTIVATION_OPERATION_PROVIDER_TIME_INVALID", 503, false);
  }
  return canonicalTimestamp(milliseconds);
}
