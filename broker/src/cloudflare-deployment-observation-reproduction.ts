import { canonicalJson, sha256Hex } from "./canonical";
import {
  ACCOUNT_ID,
  DIGEST,
  PROVIDER_REQUEST_ID,
  VERSION,
} from "./cloudflare-deployment-observation-contract";
import {
  compareWorkerVersion,
  decodeBase64,
  deploymentJson,
  requireExactInteger,
  requireJsonObject,
  requireLiteral,
} from "./cloudflare-deployment-observation-common";
import {
  parseDeployment,
  parseDeploymentList,
  parseVersionObservation,
} from "./cloudflare-deployment-observation-provider";
import {
  projectCloudflareScriptSettings,
  projectCloudflareWorkerDomain,
  projectCloudflareWorkerRoutes,
  projectCloudflareWorkerSubdomain,
  projectCloudflareWorkersDomains,
} from "./cloudflare-worker-topology";
import { BrokerError } from "./errors";
import { SERVICE_AUTHORITY_ROLES } from "./service-authority";
import type { JsonObject } from "./types";
import { exactObject, requireString } from "./validation";
import {
  decodeCloudflareProviderEnvelope,
  decodeCloudflareProviderReadEnvelope,
} from "./private/cloudflare-provider";

export function parseEvidenceSetBinding(
  evidence: JsonObject,
  index: number,
  observation: JsonObject,
): void {
  const role = SERVICE_AUTHORITY_ROLES[index];
  if (
    role === undefined ||
    evidence.authority_role !== role ||
    evidence.cloudflare_account_id !== observation.cloudflare_account_id ||
    evidence.expectation_sha256 !== observation.expectation_sha256 ||
    evidence.observed_at !== observation.observed_at ||
    evidence.observer_service_identity !== observation.observer_service_identity ||
    evidence.observer_worker_version_id !== observation.observer_worker_version_id ||
    evidence.phase !== observation.phase ||
    evidence.provider_observation_sha256 !== observation.provider_observation_sha256
  ) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_BINDING_INVALID", 500, false);
  }
  const suppliedServiceObservation = requireJsonObject(evidence.service_observation);
  const observedService = requireJsonObject(
    Array.isArray(observation.services) ? observation.services[index] : undefined,
  );
  if (canonicalJson(suppliedServiceObservation) !== canonicalJson(observedService)) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_BINDING_INVALID", 500, false);
  }
}

export function parseNetworkEvidenceBinding(evidence: JsonObject, observation: JsonObject): void {
  if (
    evidence.cloudflare_account_id !== observation.cloudflare_account_id ||
    evidence.expectation_sha256 !== observation.expectation_sha256 ||
    evidence.observed_at !== observation.observed_at ||
    evidence.observer_service_identity !== observation.observer_service_identity ||
    evidence.observer_worker_version_id !== observation.observer_worker_version_id ||
    evidence.phase !== observation.phase ||
    evidence.provider_observation_sha256 !== observation.provider_observation_sha256 ||
    canonicalJson(requireJsonObject(evidence.network_surface_observation)) !==
      canonicalJson(requireJsonObject(observation.network_surface))
  ) {
    throw new BrokerError("CLOUDFLARE_NETWORK_EVIDENCE_BINDING_INVALID", 500, false);
  }
}

export async function reproduceNetworkSurfaceObservation(
  evidence: JsonObject,
): Promise<JsonObject> {
  if (!Array.isArray(evidence.raw_responses) || evidence.raw_responses.length !== 3) {
    throw new BrokerError("CLOUDFLARE_NETWORK_EVIDENCE_COUNT_INVALID", 500, false);
  }
  const rows = await Promise.all(evidence.raw_responses.map(parseRawNetworkEvidenceRow));
  const list = rows[0];
  const get = rows[1];
  const routes = rows[2];
  if (
    list?.operation !== "list_domains" ||
    get?.operation !== "get_domain" ||
    routes?.operation !== "list_routes"
  ) {
    throw new BrokerError("CLOUDFLARE_NETWORK_EVIDENCE_ORDER_INVALID", 500, false);
  }
  const accountId = requireString(evidence, "cloudflare_account_id", 32, ACCOUNT_ID);
  const listed = decodeCloudflareProviderReadEnvelope(list.raw, "list_domains");
  const listedProjection = projectCloudflareWorkersDomains(listed.result, listed.resultInfo);
  const domain = requireJsonObject(listedProjection.domain);
  const domainId = requireString(domain, "id", 32, /^[0-9a-f]{32}$/u);
  const zoneId = requireString(domain, "zone_id", 32, /^[0-9a-f]{32}$/u);
  if (
    list.requestPath !== `/client/v4/accounts/${accountId}/workers/domains` ||
    get.requestPath !== `/client/v4/accounts/${accountId}/workers/domains/${domainId}` ||
    routes.requestPath !== `/client/v4/zones/${zoneId}/workers/routes`
  ) {
    throw new BrokerError("CLOUDFLARE_NETWORK_EVIDENCE_PATH_INVALID", 500, false);
  }
  const fetched = projectCloudflareWorkerDomain(
    decodeCloudflareProviderReadEnvelope(get.raw, "get_domain").result,
  );
  if (canonicalJson(domain) !== canonicalJson(fetched)) {
    throw new BrokerError("CLOUDFLARE_WORKERS_DOMAIN_REQUERY_MISMATCH", 500, false);
  }
  const routesProjection = projectCloudflareWorkerRoutes(
    decodeCloudflareProviderReadEnvelope(routes.raw, "list_routes").result,
  );
  return {
    domain,
    get_domain_provider_response_sha256: get.rawResponseSha256,
    list_domains_provider_response_sha256: list.rawResponseSha256,
    list_routes_provider_response_sha256: routes.rawResponseSha256,
    routes: routesProjection,
  };
}

export async function reproduceServiceObservation(evidence: JsonObject): Promise<JsonObject> {
  if (!Array.isArray(evidence.raw_responses)) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_INVALID", 500, false);
  }
  const rows = await Promise.all(
    evidence.raw_responses.map((row) =>
      parseRawEvidenceRow(
        row,
        requireString(evidence, "authority_role", 64),
        requireString(evidence, "service", 128),
      ),
    ),
  );
  const list = rows[0];
  const getDeployment = rows[1];
  if (list?.operation !== "list_deployments" || getDeployment?.operation !== "get_deployment") {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_ORDER_INVALID", 500, false);
  }
  const deployments = parseDeploymentList(decodeCloudflareProviderEnvelope(list.raw));
  const current = deployments[0];
  if (current === undefined) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_INVALID", 500, false);
  }
  const fetched = parseDeployment(decodeCloudflareProviderEnvelope(getDeployment.raw));
  const prefix = `/client/v4/accounts/${requireString(
    evidence,
    "cloudflare_account_id",
    32,
    /^[0-9a-f]{32}$/u,
  )}/workers/scripts/${requireString(evidence, "service", 128)}`;
  if (
    list.requestPath !== `${prefix}/deployments` ||
    getDeployment.requestPath !== `${prefix}/deployments/${current.id}`
  ) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_PATH_INVALID", 500, false);
  }
  if (canonicalJson(deploymentJson(current)) !== canonicalJson(deploymentJson(fetched))) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_MISMATCH", 500, false);
  }
  const versionRows = rows.slice(2, 2 + current.versions.length);
  if (versionRows.length !== current.versions.length) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_COUNT_INVALID", 500, false);
  }
  const versions: JsonObject[] = [];
  for (let index = 0; index < versionRows.length; index += 1) {
    const row = versionRows[index];
    const member = current.versions[index];
    if (row?.operation !== "get_version" || member === undefined) {
      throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_ORDER_INVALID", 500, false);
    }
    const memberVersionId = requireString(member, "worker_version_id", 36, VERSION);
    if (row.requestPath !== `${prefix}/versions/${memberVersionId}`) {
      throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_PATH_INVALID", 500, false);
    }
    const version = await parseVersionObservation(
      decodeCloudflareProviderEnvelope(row.raw),
      memberVersionId,
    );
    version.get_version_provider_response_sha256 = row.rawResponseSha256;
    versions.push(version);
  }
  versions.sort(compareWorkerVersion);
  const settingsRow = rows[2 + current.versions.length];
  const subdomainRow = rows[3 + current.versions.length];
  if (
    rows.length !== 4 + current.versions.length ||
    settingsRow?.operation !== "get_script_settings" ||
    subdomainRow?.operation !== "get_subdomain" ||
    settingsRow.requestPath !== `${prefix}/script-settings` ||
    subdomainRow.requestPath !== `${prefix}/subdomain`
  ) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_ORDER_INVALID", 500, false);
  }
  const settings = projectCloudflareScriptSettings(
    decodeCloudflareProviderReadEnvelope(settingsRow.raw, "get_script_settings").result,
  );
  const subdomain = projectCloudflareWorkerSubdomain(
    decodeCloudflareProviderReadEnvelope(subdomainRow.raw, "get_subdomain").result,
  );
  return {
    authority_role: requireString(evidence, "authority_role", 64),
    current_deployment_id: current.id,
    deployment_created_on: current.created_on,
    deployment_source: current.source,
    deployment_strategy: "percentage",
    deployment_versions: current.versions.map((member) => ({ ...member })),
    get_deployment_provider_response_sha256: getDeployment.rawResponseSha256,
    list_deployments_provider_response_sha256: list.rawResponseSha256,
    script_settings: settings,
    script_settings_provider_response_sha256: settingsRow.rawResponseSha256,
    service: requireString(evidence, "service", 128),
    subdomain,
    subdomain_provider_response_sha256: subdomainRow.rawResponseSha256,
    versions,
  };
}

async function parseRawEvidenceRow(
  value: unknown,
  expectedRole: string,
  expectedService: string,
): Promise<{
  readonly operation: string;
  readonly raw: Uint8Array;
  readonly rawResponseSha256: string;
  readonly requestPath: string;
}> {
  const row = exactObject(value, [
    "authority_role",
    "content_type",
    "operation",
    "provider_request_id",
    "raw_body_base64",
    "raw_response_sha256",
    "request_path",
    "service",
    "status",
  ]);
  requireLiteral(row, "content_type", "application/json");
  requireExactInteger(row, "status", 200);
  if (row.authority_role !== expectedRole || row.service !== expectedService) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_BINDING_INVALID", 500, false);
  }
  if (row.provider_request_id !== null) {
    requireString(row, "provider_request_id", 128, PROVIDER_REQUEST_ID);
  }
  const raw = decodeBase64(
    requireString(row, "raw_body_base64", 16_384, /^[A-Za-z0-9+/]+={0,2}$/u),
  );
  const rawResponseSha256 = requireString(row, "raw_response_sha256", 71, DIGEST);
  if (rawResponseSha256 !== `sha256:${await sha256Hex(raw)}`) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_DIGEST_INVALID", 500, false);
  }
  return {
    operation: requireString(row, "operation", 32),
    raw,
    rawResponseSha256,
    requestPath: requireString(row, "request_path", 512, /^\/client\/v4\/[A-Za-z0-9/._-]+$/u),
  };
}

async function parseRawNetworkEvidenceRow(value: unknown): Promise<{
  readonly operation: string;
  readonly raw: Uint8Array;
  readonly rawResponseSha256: string;
  readonly requestPath: string;
}> {
  const row = exactObject(value, [
    "content_type",
    "operation",
    "provider_request_id",
    "raw_body_base64",
    "raw_response_sha256",
    "request_path",
    "status",
  ]);
  requireLiteral(row, "content_type", "application/json");
  requireExactInteger(row, "status", 200);
  if (row.provider_request_id !== null) {
    requireString(row, "provider_request_id", 128, PROVIDER_REQUEST_ID);
  }
  const raw = decodeBase64(
    requireString(row, "raw_body_base64", 65_536, /^[A-Za-z0-9+/]+={0,2}$/u),
  );
  const rawResponseSha256 = requireString(row, "raw_response_sha256", 71, DIGEST);
  if (rawResponseSha256 !== `sha256:${await sha256Hex(raw)}`) {
    throw new BrokerError("CLOUDFLARE_NETWORK_EVIDENCE_DIGEST_INVALID", 500, false);
  }
  return {
    operation: requireString(row, "operation", 32),
    raw,
    rawResponseSha256,
    requestPath: requireString(
      row,
      "request_path",
      512,
      /^\/client\/v4\/(?:accounts|zones)\/[A-Za-z0-9/._-]+$/u,
    ),
  };
}
