import { digestObject } from "./canonical";
import type { AcceptedCloudflareDeploymentObservation } from "./cloudflare-deployment-observer-client";
import { assert, BrokerError } from "./errors";
import { SERVICE_AUTHORITY_ROLES } from "./service-authority";
import type { JsonObject } from "./types";
import { exactObject, requireString } from "./validation";

export const SERVICE_AUTHORITY_OBSERVATION_SCHEMA =
  "dpone.release-broker-service-authority-observation.v1";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;

/** Compact and bind the independently WORM-confirmed 14+1 evidence set. */
export async function buildServiceAuthorityObservation(
  accepted: AcceptedCloudflareDeploymentObservation,
  expectationSha256: string,
): Promise<JsonObject> {
  const provider = accepted.observation;
  assert(
    provider.expectation_sha256 === expectationSha256,
    "SERVICE_AUTHORITY_OBSERVATION_TRANSPLANT",
  );
  const providerServices = provider.services;
  if (
    !Array.isArray(providerServices) ||
    providerServices.length !== SERVICE_AUTHORITY_ROLES.length
  ) {
    throw new BrokerError("SERVICE_AUTHORITY_OBSERVATION_INVALID", 503, false);
  }
  const services = await Promise.all(
    accepted.serviceEvidenceEntries.map(async (candidate, index) => {
      const entry = exactObject(candidate, [
        "authority_role",
        "deployment_observation_record",
        "deployment_observation_record_id",
        "deployment_observation_record_sha256",
        "deployment_observation_sha256",
        "worm",
      ]);
      const expectedRole = SERVICE_AUTHORITY_ROLES[index];
      if (expectedRole === undefined) {
        throw new BrokerError("SERVICE_AUTHORITY_OBSERVATION_INVALID", 503, false);
      }
      literal(entry, "authority_role", expectedRole);
      const deploymentProjection = compactDeploymentProjection(providerServices[index]);
      return {
        authority_role: entry.authority_role ?? null,
        deployment_observation_record_id: requireString(
          entry,
          "deployment_observation_record_id",
          71,
          DIGEST,
        ),
        deployment_observation_record_sha256: requireString(
          entry,
          "deployment_observation_record_sha256",
          71,
          DIGEST,
        ),
        deployment_observation_sha256: requireString(
          entry,
          "deployment_observation_sha256",
          71,
          DIGEST,
        ),
        deployment_projection: deploymentProjection,
        deployment_projection_sha256: await digestObject(deploymentProjection),
        worm: wormPointer(entry.worm),
      };
    }),
  );
  const networkEntry = exactObject(accepted.networkSurfaceEvidenceEntry, [
    "network_surface_observation_record",
    "network_surface_observation_record_id",
    "network_surface_observation_record_sha256",
    "network_surface_observation_sha256",
    "worm",
  ]);
  const networkProjection = compactNetworkProjection(provider.network_surface);
  const networkSurface = {
    network_projection: networkProjection,
    network_projection_sha256: await digestObject(networkProjection),
    network_surface_observation_record_id: requireString(
      networkEntry,
      "network_surface_observation_record_id",
      71,
      DIGEST,
    ),
    network_surface_observation_record_sha256: requireString(
      networkEntry,
      "network_surface_observation_record_sha256",
      71,
      DIGEST,
    ),
    network_surface_observation_sha256: requireString(
      networkEntry,
      "network_surface_observation_sha256",
      71,
      DIGEST,
    ),
    worm: wormPointer(networkEntry.worm),
  };
  assertUniqueAnchors(services, networkSurface);
  const aggregate = {
    b2_observer_service_identity: accepted.b2ObserverServiceIdentity,
    expectation_sha256: expectationSha256,
    network_surface: anchorProjection(networkSurface, true),
    phase: requireString(provider, "phase", 12),
    services: services.map((row) => anchorProjection(row, false)),
    worm_service_identity: accepted.wormServiceIdentity,
  };
  const providerObservationSha256 = await digestObject(aggregate);
  return {
    b2_observer_service_identity: accepted.b2ObserverServiceIdentity,
    broker_accepted_at: accepted.brokerAcceptedAt,
    cloudflare_provider_observation_sha256: requireString(
      provider,
      "provider_observation_sha256",
      71,
      DIGEST,
    ),
    expectation_sha256: expectationSha256,
    network_surface: networkSurface,
    observed_at: requireString(provider, "observed_at", 32, TIMESTAMP),
    observer_service_identity: requireString(provider, "observer_service_identity", 512),
    observer_worker_version_id: requireString(provider, "observer_worker_version_id", 36),
    phase: aggregate.phase,
    provider_observation_sha256: providerObservationSha256,
    schema: SERVICE_AUTHORITY_OBSERVATION_SCHEMA,
    schema_version: 1,
    services,
    worm_service_identity: accepted.wormServiceIdentity,
  };
}

function wormPointer(value: unknown): JsonObject {
  const pointer = exactObject(value, ["digest", "key", "retention_until", "version_id"]);
  return {
    digest: requireString(pointer, "digest", 71, DIGEST),
    key: requireString(pointer, "key", 512),
    retention_until: requireString(pointer, "retention_until", 32, TIMESTAMP),
    version_id: requireString(pointer, "version_id", 512),
  };
}

function anchorProjection(value: JsonObject, network: boolean): JsonObject {
  const prefix = network ? "network_surface" : "deployment";
  const projection = network ? "network" : "deployment";
  return {
    [`${prefix}_observation_record_id`]: value[`${prefix}_observation_record_id`] ?? null,
    [`${prefix}_observation_record_sha256`]: value[`${prefix}_observation_record_sha256`] ?? null,
    [`${prefix}_observation_sha256`]: value[`${prefix}_observation_sha256`] ?? null,
    [`${projection}_projection`]: value[`${projection}_projection`] ?? null,
    [`${projection}_projection_sha256`]: value[`${projection}_projection_sha256`] ?? null,
    ...(network ? {} : { authority_role: value.authority_role ?? null }),
    worm: value.worm ?? null,
  };
}

function compactDeploymentProjection(value: unknown): JsonObject {
  const service = exactObject(value, [
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
  if (!Array.isArray(service.versions)) {
    throw new BrokerError("SERVICE_AUTHORITY_DEPLOYMENT_PROJECTION_INVALID", 503, false);
  }
  return {
    authority_role: service.authority_role ?? null,
    current_deployment_id: service.current_deployment_id ?? null,
    deployment_created_on: service.deployment_created_on ?? null,
    deployment_source: service.deployment_source ?? null,
    deployment_strategy: service.deployment_strategy ?? null,
    deployment_versions: service.deployment_versions ?? null,
    script_settings: service.script_settings ?? null,
    service: service.service ?? null,
    subdomain: service.subdomain ?? null,
    versions: service.versions.map((candidate) => {
      const version = exactObject(candidate, [
        "created_on",
        "get_version_provider_response_sha256",
        "has_preview",
        "modified_on",
        "source",
        "version_number",
        "version_resource_projection",
        "version_resource_projection_sha256",
        "worker_version_id",
      ]);
      return {
        version_resource_projection: version.version_resource_projection ?? null,
        version_resource_projection_sha256: version.version_resource_projection_sha256 ?? null,
        worker_version_id: version.worker_version_id ?? null,
      };
    }),
  };
}

function compactNetworkProjection(value: unknown): JsonObject {
  const network = exactObject(value, [
    "domain",
    "get_domain_provider_response_sha256",
    "list_domains_provider_response_sha256",
    "list_routes_provider_response_sha256",
    "routes",
  ]);
  return { domain: network.domain ?? null, routes: network.routes ?? null };
}

function assertUniqueAnchors(services: readonly JsonObject[], network: JsonObject): void {
  const ids = services.map((row) =>
    requireString(row, "deployment_observation_record_id", 71, DIGEST),
  );
  const digests = services.map((row) =>
    requireString(row, "deployment_observation_record_sha256", 71, DIGEST),
  );
  ids.push(requireString(network, "network_surface_observation_record_id", 71, DIGEST));
  digests.push(requireString(network, "network_surface_observation_record_sha256", 71, DIGEST));
  assert(new Set(ids).size === ids.length, "SERVICE_AUTHORITY_OBSERVATION_RECORD_ALIAS");
  assert(new Set(digests).size === digests.length, "SERVICE_AUTHORITY_OBSERVATION_DIGEST_ALIAS");
}

function literal(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, Math.max(1, expected.length)) === expected,
    "SERVICE_AUTHORITY_LITERAL_MISMATCH",
  );
}
