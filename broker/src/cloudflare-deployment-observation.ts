import { canonicalJson } from "./canonical";
import {
  CLOUDFLARE_DEPLOYMENT_REQUEST_SCHEMA,
  DIGEST,
  REQUEST_ID,
  TIMESTAMP,
  type CloudflareDeploymentObservationRpcRequest,
} from "./cloudflare-deployment-observation-contract";
import {
  isJsonObject,
  requireExactInteger,
  requireJsonArray,
  requireJsonObject,
  requireLiteral,
  validateRequest,
} from "./cloudflare-deployment-observation-common";
import { assertExpectedNetworkSurface } from "./cloudflare-deployment-observation-provider";
import { projectCloudflareWorkerRoutes } from "./cloudflare-worker-topology";
import { BrokerError } from "./errors";
import {
  parseExpectedCloudflareNetworkSurface,
  parseExpectedServiceDeployments,
  parseServiceAuthorityInventory,
  type DeploymentObservationPhase,
  type ExpectedCloudflareNetworkSurface,
  type ExpectedServiceDeployment,
  type ServiceAuthorityInventoryRow,
} from "./service-authority";
import type { JsonObject } from "./types";
import { exactObject, requireString } from "./validation";

export {
  CLOUDFLARE_DEPLOYMENT_EVIDENCE_KIND,
  CLOUDFLARE_DEPLOYMENT_EVIDENCE_SCHEMA,
  CLOUDFLARE_DEPLOYMENT_OBSERVATION_RPC_PATH,
  CLOUDFLARE_DEPLOYMENT_OBSERVATION_SCHEMA,
  CLOUDFLARE_DEPLOYMENT_REQUEST_SCHEMA,
  CLOUDFLARE_DEPLOYMENT_RESULT_SCHEMA,
  CLOUDFLARE_NETWORK_EVIDENCE_KIND,
  CLOUDFLARE_NETWORK_EVIDENCE_SCHEMA,
  CLOUDFLARE_SANITIZED_NETWORK_EVIDENCE_SCHEMA,
  CLOUDFLARE_SANITIZED_SERVICE_EVIDENCE_SCHEMA,
} from "./cloudflare-deployment-observation-contract";
export type {
  CloudflareDeploymentObservationRequest,
  CloudflareDeploymentObservationResult,
  CloudflareDeploymentObservationRpcRequest,
  SanitizedCloudflareEvidence,
} from "./cloudflare-deployment-observation-contract";
export { CloudflareDeploymentObserver } from "./cloudflare-deployment-observer";
export {
  assertCloudflareDeploymentEvidenceSet,
  assertSanitizedCloudflareEvidenceRecord,
  assertTransientCloudflareNetworkEvidence,
  assertTransientCloudflareServiceEvidence,
} from "./cloudflare-deployment-observation-evidence";
export {
  sanitizeCloudflareNetworkEvidence,
  sanitizeCloudflareServiceEvidence,
} from "./cloudflare-deployment-observation-sanitizer";

export function parseCloudflareDeploymentObservationRequest(
  value: unknown,
  cloudflareAccountId: string,
): CloudflareDeploymentObservationRpcRequest {
  const body = exactObject(value, [
    "expected_deployments",
    "expectation_sha256",
    "expected_network_surface",
    "phase",
    "request_id",
    "requested_at",
    "schema",
    "schema_version",
    "service_authority_inventory",
  ]);
  requireLiteral(body, "schema", CLOUDFLARE_DEPLOYMENT_REQUEST_SCHEMA);
  requireExactInteger(body, "schema_version", 1);
  const phaseValue = requireString(body, "phase", 12);
  if (phaseValue !== "A0_PRE" && phaseValue !== "A1_PRECOMMIT") {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_REQUEST_INVALID", 400, false);
  }
  const phase: DeploymentObservationPhase = phaseValue;
  const request = {
    expectedDeployments: parseExpectedServiceDeployments(body.expected_deployments, phase),
    expectationSha256: requireString(body, "expectation_sha256", 71, DIGEST),
    expectedNetworkSurface: parseExpectedCloudflareNetworkSurface(body.expected_network_surface),
    inventory: parseServiceAuthorityInventory(
      body.service_authority_inventory,
      cloudflareAccountId,
    ),
    phase,
    requestId: requireString(body, "request_id", 128, REQUEST_ID),
    requestedAt: requireString(body, "requested_at", 32, TIMESTAMP),
  };
  validateRequest(request);
  return request;
}

/** Reject a captured ingress request before any Cloudflare or WORM call. */
export function assertCloudflareObserverRequestFreshness(
  requestedAt: string,
  admittedAtMs: number,
): void {
  const requestedAtMs = Date.parse(requestedAt);
  if (
    !Number.isSafeInteger(admittedAtMs) ||
    !Number.isFinite(requestedAtMs) ||
    requestedAtMs > admittedAtMs + 10_000 ||
    admittedAtMs - requestedAtMs > 60_000
  ) {
    throw new BrokerError("CLOUDFLARE_OBSERVER_RPC_STALE", 409, false);
  }
}

/**
 * Cross-check a sanitized provider observation against the static authority
 * inventory and the caller's exact pre/post deployment expectation.
 */
export function assertCloudflareObservationMatchesInventory(
  observation: JsonObject,
  inventory: readonly ServiceAuthorityInventoryRow[],
  expectedDeployments: readonly ExpectedServiceDeployment[],
  expectedNetworkSurface: ExpectedCloudflareNetworkSurface,
): void {
  const services = observation.services;
  if (!Array.isArray(services) || services.length !== inventory.length) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_OBSERVATION_INVALID", 503, false);
  }
  inventory.forEach((authority, index) => {
    const expected = expectedDeployments[index];
    const observed = exactObject(services[index], [
      "authority_role",
      "current_deployment_id",
      "deployment_created_on",
      "deployment_source",
      "deployment_strategy",
      "deployment_versions",
      "get_deployment_provider_response_sha256",
      "list_deployments_provider_response_sha256",
      "script_settings",
      "script_settings_provider_response_sha256",
      "service",
      "subdomain",
      "subdomain_provider_response_sha256",
      "versions",
    ]);
    if (expected === undefined) {
      throw new BrokerError("CLOUDFLARE_DEPLOYMENT_INVENTORY_MISMATCH", 503, false);
    }
    if (
      authority.authority_role !== expected.authority_role ||
      authority.authority_role !== observed.authority_role ||
      authority.service !== expected.service ||
      authority.service !== observed.service ||
      canonicalJson({ members: observed.deployment_versions }) !==
        canonicalJson({
          members: expected.deployment_versions.map(({ percentage, worker_version_id }) => ({
            percentage,
            worker_version_id,
          })),
        })
    ) {
      throw new BrokerError("CLOUDFLARE_DEPLOYMENT_INVENTORY_MISMATCH", 503, false);
    }
    const observedVersions = requireJsonArray(observed.versions);
    const finalVersionCandidate = observedVersions.find(
      (candidate) =>
        isJsonObject(candidate) && candidate.worker_version_id === authority.worker_version_id,
    );
    const expectedFinal = expected.deployment_versions.find(
      (candidate) => candidate.artifact_kind === "FINAL_AUTHORITY",
    );
    if (finalVersionCandidate === undefined || expectedFinal === undefined) {
      throw new BrokerError("CLOUDFLARE_VERSION_RESOURCE_DRIFT", 503, false);
    }
    const finalVersion = requireJsonObject(finalVersionCandidate);
    if (
      expectedFinal.worker_version_id !== authority.worker_version_id ||
      expectedFinal.configuration_sha256 !== authority.configuration_sha256 ||
      expectedFinal.source_sha256 !== authority.source_sha256 ||
      expectedFinal.version_resource_projection_sha256 !==
        authority.version_resource_projection_sha256 ||
      requireJsonObject(finalVersion.version_resource_projection).script_etag !==
        expectedFinal.script_etag ||
      finalVersion.version_resource_projection_sha256 !==
        expectedFinal.version_resource_projection_sha256
    ) {
      throw new BrokerError("CLOUDFLARE_VERSION_RESOURCE_DRIFT", 503, false);
    }
    const bootstrapVersion = expected.deployment_versions.find(
      (candidate) => candidate.artifact_kind === "BOOTSTRAP_DENY",
    );
    if (bootstrapVersion !== undefined) {
      const observedBootstrapCandidate = observedVersions.find(
        (candidate) =>
          isJsonObject(candidate) &&
          candidate.worker_version_id === bootstrapVersion.worker_version_id,
      );
      if (observedBootstrapCandidate === undefined) {
        throw new BrokerError("CLOUDFLARE_BOOTSTRAP_VERSION_DRIFT", 503, false);
      }
      const observedBootstrap = requireJsonObject(observedBootstrapCandidate);
      if (
        requireJsonObject(observedBootstrap.version_resource_projection).script_etag !==
          bootstrapVersion.script_etag ||
        observedBootstrap.version_resource_projection_sha256 !==
          bootstrapVersion.version_resource_projection_sha256
      ) {
        throw new BrokerError("CLOUDFLARE_BOOTSTRAP_VERSION_DRIFT", 503, false);
      }
    }
  });
  const network = exactObject(observation.network_surface, [
    "domain",
    "get_domain_provider_response_sha256",
    "list_domains_provider_response_sha256",
    "list_routes_provider_response_sha256",
    "routes",
  ]);
  assertExpectedNetworkSurface(requireJsonObject(network.domain), expectedNetworkSurface);
  const routes = exactObject(network.routes, ["routes", "schema"]);
  requireLiteral(routes, "schema", "dpone.cloudflare-workers-routes-projection.v1");
  projectCloudflareWorkerRoutes(routes.routes);
}
