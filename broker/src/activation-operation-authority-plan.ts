import type { ActivationOperationIssuance } from "./activation-operation-contract";
import type { ActivationCloudflareBatchPins } from "./activation-operation-pins";
import {
  provisionedRecordServicePin,
  provisionRequestServicePin,
  type FinalizeRequest,
  type ProvisionRequest,
} from "./activation-schema";
import { requireObjectField, requireStringField } from "./activation-registry-codec";
import { CLOUDFLARE_DEPLOYMENT_REQUEST_SCHEMA } from "./cloudflare-deployment-observation";
import { BrokerError } from "./errors";
import {
  assertServiceAuthorityExpectationMatchesBroker,
  materializeA1PrecommitDeployments,
  parseServiceAuthorityExpectation,
  type ServiceAuthorityExpectation,
} from "./service-authority-activation";
import type { ExpectedServiceDeployment } from "./service-authority";
import type { JsonObject, PrivateServicePin, TrustedRuntimeConfig } from "./types";

export interface ActivationOperationAuthorityPlan {
  readonly cloudflareObserverPin: PrivateServicePin;
  readonly expectedDeployments: readonly ExpectedServiceDeployment[];
  readonly expectation: ServiceAuthorityExpectation;
  readonly pins: ActivationCloudflareBatchPins;
  readonly wormObserverPin: PrivateServicePin;
  readonly wormPin: PrivateServicePin;
}

/** Derive every A0 authority/pin from the exact durable semantic request. */
export async function provisionAuthorityPlan(
  request: ProvisionRequest,
  config: TrustedRuntimeConfig,
): Promise<ActivationOperationAuthorityPlan> {
  const expectation = await parseServiceAuthorityExpectation(
    request.serviceAuthorities.expectation,
    request.serviceAuthorities.expectation_sha256,
    config.cloudflareAccountId,
    requireStringField(request.broker, "source_commit_sha"),
  );
  assertServiceAuthorityExpectationMatchesBroker(expectation, request.broker);
  return authorityPlan(
    expectation,
    expectation.a0PreDeployments,
    provisionRequestServicePin(request, "cloudflare_deployment_observer"),
    provisionRequestServicePin(request, "worm_mirror"),
    provisionRequestServicePin(request, "worm_version_observer"),
  );
}

/** Derive every A1 authority/pin from confirmed A0 plus the durable promotion. */
export async function finalizeAuthorityPlan(
  request: FinalizeRequest,
  provisionedEnvelope: JsonObject,
  config: TrustedRuntimeConfig,
): Promise<ActivationOperationAuthorityPlan> {
  const evidence = requireObjectField(provisionedEnvelope, "evidence");
  const broker = requireObjectField(evidence, "broker");
  const authorities = requireObjectField(evidence, "service_authorities");
  const expectation = await parseServiceAuthorityExpectation(
    authorities.expectation,
    authorities.expectation_sha256,
    config.cloudflareAccountId,
    requireStringField(broker, "source_commit_sha"),
  );
  assertServiceAuthorityExpectationMatchesBroker(expectation, broker);
  const expectedDeployments = materializeA1PrecommitDeployments(
    expectation.a1PrecommitDeployments,
    requireStringField(request.promotion, "deployment_id"),
  );
  const ingress = expectedDeployments.find(
    (deployment) => deployment.authority_role === "release_authority_ingress",
  );
  const promotedVersion = requireStringField(request.promotion, "worker_version_id");
  if (
    ingress === undefined ||
    ingress.deployment_id !== request.promotion.deployment_id ||
    ingress.deployment_versions[0]?.worker_version_id !== promotedVersion ||
    promotedVersion !== config.workerVersionId
  ) {
    throw new BrokerError("ACTIVATION_PROMOTION_BINDING_MISMATCH", 409, false);
  }
  return authorityPlan(
    expectation,
    expectedDeployments,
    provisionedRecordServicePin(provisionedEnvelope, "cloudflare_deployment_observer"),
    provisionedRecordServicePin(provisionedEnvelope, "worm_mirror"),
    provisionedRecordServicePin(provisionedEnvelope, "worm_version_observer"),
  );
}

/** Build the exact v1 provider request nested in the durable v2 delegation. */
export function authorityObserverRequest(
  plan: ActivationOperationAuthorityPlan,
  issuance: ActivationOperationIssuance,
  requestedAt: string,
): JsonObject {
  return {
    expected_deployments: plan.expectedDeployments.map((deployment) => ({
      authority_role: deployment.authority_role,
      deployment_id: deployment.deployment_id,
      deployment_versions: deployment.deployment_versions.map((version) => ({ ...version })),
      service: deployment.service,
    })),
    expectation_sha256: plan.expectation.expectationSha256,
    expected_network_surface: { ...plan.expectation.networkSurface },
    phase: issuance.sequence === 0 ? "A0_PRE" : "A1_PRECOMMIT",
    request_id: issuance.internalRequestId,
    requested_at: requestedAt,
    schema: CLOUDFLARE_DEPLOYMENT_REQUEST_SCHEMA,
    schema_version: 1,
    service_authority_inventory: plan.expectation.authorities.map((row) => ({ ...row })),
  };
}

function authorityPlan(
  expectation: ServiceAuthorityExpectation,
  expectedDeployments: readonly ExpectedServiceDeployment[],
  cloudflareObserverPin: PrivateServicePin,
  wormPin: PrivateServicePin,
  wormObserverPin: PrivateServicePin,
): ActivationOperationAuthorityPlan {
  return {
    cloudflareObserverPin,
    expectedDeployments,
    expectation,
    pins: {
      b2ObserverServiceIdentity: wormObserverPin.serviceIdentity,
      b2ObserverWorkerVersionId: wormObserverPin.versionId,
      cloudflareObserverServiceIdentity: cloudflareObserverPin.serviceIdentity,
      cloudflareObserverWorkerVersionId: cloudflareObserverPin.versionId,
      wormServiceIdentity: wormPin.serviceIdentity,
      wormWorkerVersionId: wormPin.versionId,
    },
    wormObserverPin,
    wormPin,
  };
}
