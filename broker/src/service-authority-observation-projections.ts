import { canonicalJson, digestObject } from "./canonical";
import { parseCloudflareWorkerResourceProjection } from "./cloudflare-worker-resource-projection";
import { assert, BrokerError } from "./errors";
import type { ServiceAuthorityExpectation } from "./service-authority-activation";
import { literal, tagged, timestamp } from "./service-authority-observation-fields";
import type { ExpectedServiceDeployment } from "./service-authority";
import type { JsonObject, JsonValue } from "./types";
import { exactObject, requireString } from "./validation";

export async function parseServiceObservationEntry(
  value: unknown,
  expected: ExpectedServiceDeployment,
  observerVersion: string,
  observedAt: string,
): Promise<JsonObject> {
  const entry = exactObject(value, [
    "authority_role",
    "deployment_observation_record_id",
    "deployment_observation_record_sha256",
    "deployment_observation_sha256",
    "deployment_projection",
    "deployment_projection_sha256",
    "worm",
  ]);
  literal(entry, "authority_role", expected.authority_role);
  const projection = exactObject(entry.deployment_projection, [
    "authority_role",
    "current_deployment_id",
    "deployment_created_on",
    "deployment_source",
    "deployment_strategy",
    "deployment_versions",
    "script_settings",
    "service",
    "subdomain",
    "versions",
  ]);
  literal(projection, "authority_role", expected.authority_role);
  literal(projection, "service", expected.service);
  literal(projection, "current_deployment_id", requireDeploymentId(expected));
  timestamp(projection, "deployment_created_on");
  requireString(projection, "deployment_source", 64, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u);
  literal(projection, "deployment_strategy", "percentage");
  const expectedMembership = expected.deployment_versions.map(
    ({ percentage, worker_version_id }) => ({ percentage, version_id: worker_version_id }),
  );
  assert(
    canonicalJson(projection.deployment_versions) === canonicalJson(expectedMembership),
    "SERVICE_AUTHORITY_DEPLOYMENT_MEMBERSHIP_MISMATCH",
    503,
  );
  assertScriptSettings(projection.script_settings);
  assertSubdomain(projection.subdomain);
  await parseVersions(projection.versions, expected);
  const projectionSha256 = await digestObject(projection);
  assert(
    tagged(entry, "deployment_projection_sha256") === projectionSha256,
    "SERVICE_AUTHORITY_DEPLOYMENT_PROJECTION_DIGEST_INVALID",
    503,
  );
  const recordId = tagged(entry, "deployment_observation_record_id");
  const recordSha256 = tagged(entry, "deployment_observation_record_sha256");
  const worm = parseWorm(
    entry.worm,
    recordId,
    recordSha256,
    observerVersion,
    "cloudflare_service_deployments",
    observedAt,
  );
  return {
    authority_role: expected.authority_role,
    deployment_observation_record_id: recordId,
    deployment_observation_record_sha256: recordSha256,
    deployment_observation_sha256: tagged(entry, "deployment_observation_sha256"),
    deployment_projection: projection,
    deployment_projection_sha256: projectionSha256,
    worm,
  };
}

export async function parseNetworkObservationEntry(
  value: JsonValue | undefined,
  expectation: ServiceAuthorityExpectation,
  observerVersion: string,
  observedAt: string,
): Promise<JsonObject> {
  const entry = exactObject(value, [
    "network_projection",
    "network_projection_sha256",
    "network_surface_observation_record_id",
    "network_surface_observation_record_sha256",
    "network_surface_observation_sha256",
    "worm",
  ]);
  const projection = exactObject(entry.network_projection, ["domain", "routes"]);
  const domain = exactObject(projection.domain, [
    "cert_id",
    "environment",
    "hostname",
    "id",
    "service",
    "zone_id",
    "zone_name",
  ]);
  const expected = expectation.networkSurface;
  assert(
    canonicalJson(domain) ===
      canonicalJson({
        cert_id: expected.cert_id,
        environment: expected.environment,
        hostname: expected.hostname,
        id: expected.domain_id,
        service: expected.service,
        zone_id: expected.zone_id,
        zone_name: expected.zone_name,
      }) &&
      canonicalJson(projection.routes) ===
        canonicalJson({ routes: [], schema: "dpone.cloudflare-workers-routes-projection.v1" }),
    "SERVICE_AUTHORITY_NETWORK_PROJECTION_MISMATCH",
    503,
  );
  const projectionSha256 = await digestObject(projection);
  assert(
    tagged(entry, "network_projection_sha256") === projectionSha256,
    "SERVICE_AUTHORITY_NETWORK_PROJECTION_DIGEST_INVALID",
    503,
  );
  const recordId = tagged(entry, "network_surface_observation_record_id");
  const recordSha256 = tagged(entry, "network_surface_observation_record_sha256");
  return {
    network_projection: projection,
    network_projection_sha256: projectionSha256,
    network_surface_observation_record_id: recordId,
    network_surface_observation_record_sha256: recordSha256,
    network_surface_observation_sha256: tagged(entry, "network_surface_observation_sha256"),
    worm: parseWorm(
      entry.worm,
      recordId,
      recordSha256,
      observerVersion,
      "cloudflare_network_surface",
      observedAt,
    ),
  };
}

export function assertUniqueObservationAnchors(
  services: readonly JsonObject[],
  network: JsonObject,
): void {
  const ids = services.map((entry) => tagged(entry, "deployment_observation_record_id"));
  const digests = services.map((entry) => tagged(entry, "deployment_observation_record_sha256"));
  const keys = services.map((entry) => wormString(entry.worm, "key"));
  const versions = services.map((entry) => wormString(entry.worm, "version_id"));
  ids.push(tagged(network, "network_surface_observation_record_id"));
  digests.push(tagged(network, "network_surface_observation_record_sha256"));
  keys.push(wormString(network.worm, "key"));
  versions.push(wormString(network.worm, "version_id"));
  assert(
    new Set(ids).size === ids.length &&
      new Set(digests).size === digests.length &&
      new Set(keys).size === keys.length &&
      new Set(versions).size === versions.length,
    "SERVICE_AUTHORITY_OBSERVATION_ANCHOR_ALIAS",
    503,
  );
  assertCoherentWormKeyFamily(keys);
}

async function parseVersions(
  value: JsonValue | undefined,
  expected: ExpectedServiceDeployment,
): Promise<void> {
  if (!Array.isArray(value) || value.length !== expected.deployment_versions.length) {
    throw new BrokerError("SERVICE_AUTHORITY_VERSION_PROJECTION_INVALID", 503, false);
  }
  for (const [index, candidate] of value.entries()) {
    const member = expected.deployment_versions[index];
    if (member === undefined) {
      throw new BrokerError("SERVICE_AUTHORITY_VERSION_PROJECTION_INVALID", 503, false);
    }
    const version = exactObject(candidate, [
      "version_resource_projection",
      "version_resource_projection_sha256",
      "worker_version_id",
    ]);
    literal(version, "worker_version_id", member.worker_version_id);
    const projection = parseCloudflareWorkerResourceProjection(version.version_resource_projection);
    const digest = await digestObject(projection);
    assert(
      tagged(version, "version_resource_projection_sha256") === digest &&
        digest === member.version_resource_projection_sha256 &&
        projection.script_etag === member.script_etag,
      "SERVICE_AUTHORITY_VERSION_PROJECTION_MISMATCH",
      503,
    );
  }
}

function parseWorm(
  value: JsonValue | undefined,
  recordId: string,
  recordSha256: string,
  observerVersion: string,
  kind: "cloudflare_network_surface" | "cloudflare_service_deployments",
  observedAt: string,
): JsonObject {
  const worm = exactObject(value, ["digest", "key", "retention_until", "version_id"]);
  literal(worm, "digest", recordSha256);
  const key = requireString(worm, "key", 512);
  const recordHex = recordId.slice("sha256:".length);
  const legacyKey = `receipts/v1/cloudflare-observations/${observerVersion}/${kind}/${recordHex}.json`;
  const v2Prefix = `receipts/v1/cloudflare-observations-v2/${observerVersion}/`;
  const v2Suffix = `/${kind}/${recordHex}.json`;
  const v2BatchId =
    key.startsWith(v2Prefix) && key.endsWith(v2Suffix)
      ? key.slice(v2Prefix.length, key.length - v2Suffix.length)
      : "";
  assert(
    key === legacyKey || /^[0-9a-f]{64}$/u.test(v2BatchId),
    "SERVICE_AUTHORITY_WORM_KEY_INVALID",
    503,
  );
  const retentionUntil = timestamp(worm, "retention_until");
  assert(
    Date.parse(retentionUntil) >= Date.parse(observedAt) + 2557 * 86_400_000,
    "SERVICE_AUTHORITY_WORM_RETENTION_INVALID",
    503,
  );
  requireString(worm, "version_id", 512, /^[A-Za-z0-9._=-]{1,512}$/u);
  return worm;
}

function assertCoherentWormKeyFamily(keys: readonly string[]): void {
  const bindings = keys.map((key) => {
    if (key.startsWith("receipts/v1/cloudflare-observations/")) {
      return { batchId: null, family: "legacy" } as const;
    }
    const match =
      /^receipts\/v1\/cloudflare-observations-v2\/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\/([0-9a-f]{64})\/(?:cloudflare_network_surface|cloudflare_service_deployments)\/[0-9a-f]{64}\.json$/u.exec(
        key,
      );
    assert(match !== null, "SERVICE_AUTHORITY_WORM_KEY_INVALID", 503);
    return { batchId: match[1] ?? null, family: "v2" } as const;
  });
  const families = new Set(bindings.map(({ family }) => family));
  assert(families.size === 1, "SERVICE_AUTHORITY_WORM_KEY_FAMILY_MISMATCH", 503);
  if (bindings[0]?.family === "v2") {
    const batchIds = new Set(bindings.map(({ batchId }) => batchId));
    assert(batchIds.size === 1, "SERVICE_AUTHORITY_WORM_BATCH_MISMATCH", 503);
  }
}

function assertScriptSettings(value: JsonValue | undefined): void {
  assert(
    canonicalJson(value) ===
      canonicalJson({
        logpush: false,
        observability: {
          enabled: false,
          head_sampling_rate: 0,
          logs: {
            destinations: [],
            enabled: false,
            head_sampling_rate: 0,
            invocation_logs: false,
            persist: false,
          },
          traces: {
            destinations: [],
            enabled: false,
            head_sampling_rate: 0,
            persist: false,
            propagation_policy: "authenticated",
          },
        },
        schema: "dpone.cloudflare-worker-script-settings-projection.v1",
        tags: [],
        tail_consumers: [],
      }),
    "SERVICE_AUTHORITY_SCRIPT_SETTINGS_INVALID",
    503,
  );
}

function assertSubdomain(value: JsonValue | undefined): void {
  assert(
    canonicalJson(value) ===
      canonicalJson({
        enabled: false,
        previews_enabled: false,
        schema: "dpone.cloudflare-worker-subdomain-projection.v1",
      }),
    "SERVICE_AUTHORITY_SUBDOMAIN_INVALID",
    503,
  );
}

function requireDeploymentId(value: ExpectedServiceDeployment): string {
  if (value.deployment_id === null) {
    throw new BrokerError("SERVICE_AUTHORITY_DEPLOYMENT_ID_UNRESOLVED", 503, false);
  }
  return value.deployment_id;
}

function wormString(value: JsonValue | undefined, key: "key" | "version_id"): string {
  return requireString(
    exactObject(value, ["digest", "key", "retention_until", "version_id"]),
    key,
    512,
    key === "version_id" ? /^[A-Za-z0-9._=-]{1,512}$/u : undefined,
  );
}
