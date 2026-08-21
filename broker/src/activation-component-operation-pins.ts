import type {
  ActivationProvisionPinProjection,
  ActivationProvisionSemanticCommitments,
} from "./activation-component-operation-authority-contract";
import { validateCloudflareBatchPins, validateOperationPins } from "./activation-operation-pins";
import { BrokerError } from "./errors";
import { SERVICE_AUTHORITY_DEFINITIONS, type ServiceAuthorityRole } from "./service-authority";
import type { JsonObject, PrivateServicePin } from "./types";

const INVALID = "ACTIVATION_COMPONENT_OPERATION_AUTHORITY_INVALID";
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const UUID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;

export interface ActivationProvisionOperationProjection {
  readonly historicalWorker: PrivateServicePin;
  readonly pins: ActivationProvisionPinProjection;
  readonly semanticCommitments: ActivationProvisionSemanticCommitments;
}

/**
 * Pure, non-authorizing derivation from an already parsed resolver runtime projection.
 * Only the private operation-authority binder may turn this structural result into capability.
 */
export function deriveActivationProvisionOperationProjection(
  runtime: JsonObject,
  workerVersionId: string,
): ActivationProvisionOperationProjection {
  const cloudflareAccountId = string(runtime, "cloudflare_account_id", /^[0-9a-f]{32}$/u);
  return Object.freeze({
    historicalWorker: ingressPin(cloudflareAccountId, workerVersionId),
    pins: pinProjection(runtime, cloudflareAccountId),
    semanticCommitments: semanticProjection(runtime, cloudflareAccountId),
  });
}

function pinProjection(runtime: JsonObject, accountId: string): ActivationProvisionPinProjection {
  const services = object(runtime.private_services);
  const controller = servicePin(services, "controller_run_reader", accountId);
  const governance = servicePin(services, "governance_reader", accountId);
  const cloudflare = servicePin(services, "cloudflare_deployment_observer", accountId);
  const worm = servicePin(services, "worm_mirror", accountId);
  const observer = servicePin(services, "worm_version_observer", accountId);
  const directEvidenceWorm = Object.freeze({
    executorServiceIdentity: worm.serviceIdentity,
    executorWorkerVersionId: worm.versionId,
    observerServiceIdentity: observer.serviceIdentity,
    observerWorkerVersionId: observer.versionId,
  });
  const cloudflareBatch = Object.freeze({
    b2ObserverServiceIdentity: observer.serviceIdentity,
    b2ObserverWorkerVersionId: observer.versionId,
    cloudflareObserverServiceIdentity: cloudflare.serviceIdentity,
    cloudflareObserverWorkerVersionId: cloudflare.versionId,
    wormServiceIdentity: worm.serviceIdentity,
    wormWorkerVersionId: worm.versionId,
  });
  validateOperationPins(directEvidenceWorm);
  validateCloudflareBatchPins(cloudflareBatch);
  return Object.freeze({
    cloudflareBatch,
    directEvidenceWorm,
    providerReads: Object.freeze({
      controllerAction: controller,
      controllerOidc: controller,
      targetOidc: governance,
      targetRuleset: governance,
    }),
  });
}

function servicePin(
  services: JsonObject,
  role: ServiceAuthorityRole,
  accountId: string,
): PrivateServicePin {
  const value = object(services[role]);
  const serviceName = string(value, "service_name", /^[a-z0-9][a-z0-9-]{1,127}$/u);
  const versionId = string(value, "version_id", UUID);
  const serviceIdentity = string(
    value,
    "service_identity",
    /^cloudflare-worker:[A-Za-z0-9:@._/-]{1,500}$/u,
  );
  if (
    serviceName !== SERVICE_AUTHORITY_DEFINITIONS[role].service ||
    serviceIdentity !== `cloudflare-worker:${accountId}/${serviceName}@${versionId}`
  ) {
    fail();
  }
  return Object.freeze({ serviceIdentity, serviceName, versionId });
}

function ingressPin(accountId: string, workerVersionId: string): PrivateServicePin {
  const serviceName = SERVICE_AUTHORITY_DEFINITIONS.release_authority_ingress.service;
  if (!UUID.test(workerVersionId)) fail();
  return Object.freeze({
    serviceIdentity: `cloudflare-worker:${accountId}/${serviceName}@${workerVersionId}`,
    serviceName,
    versionId: workerVersionId,
  });
}

function semanticProjection(
  runtime: JsonObject,
  cloudflareAccountId: string,
): ActivationProvisionSemanticCommitments {
  return Object.freeze({
    cloudflareAccountId,
    controllerActionBundleSha256: string(runtime, "controller_action_bundle_sha256", DIGEST),
    serviceAuthorityExpectationSha256: string(
      runtime,
      "service_authority_expectation_sha256",
      DIGEST,
    ),
    targetBranchRulesetEvidenceSha256: string(
      runtime,
      "target_branch_ruleset_evidence_sha256",
      DIGEST,
    ),
    targetBranchRulesetProjectionSha256: string(
      runtime,
      "target_branch_ruleset_projection_sha256",
      DIGEST,
    ),
  });
}

function object(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  return value as JsonObject;
}

function string(value: JsonObject, key: string, pattern: RegExp): string {
  const candidate = value[key];
  if (typeof candidate !== "string" || !pattern.test(candidate)) fail();
  return candidate;
}

function fail(): never {
  throw new BrokerError(INVALID, 409, false);
}
