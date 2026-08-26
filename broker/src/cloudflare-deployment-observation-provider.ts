import { canonicalJson, digestObject } from "./canonical";
import {
  MAX_DEPLOYMENTS,
  SOURCE,
  UUID,
  VERSION,
  VERSION_SOURCES,
  type DeploymentProjection,
} from "./cloudflare-deployment-observation-contract";
import {
  assertUnique,
  compareWorkerVersion,
  encodeBase64,
  optionalAsciiString,
  parseAnnotations,
  requireAllowedObject,
  requireLiteral,
  requireTimestamp,
} from "./cloudflare-deployment-observation-common";
import { projectCloudflareWorkerVersionResources } from "./cloudflare-worker-resources";
import { assert, BrokerError } from "./errors";
import type {
  ExpectedCloudflareNetworkSurface,
  ExpectedServiceDeployment,
} from "./service-authority";
import type { JsonObject, JsonValue } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";
import type { CloudflareProviderRead } from "./private/cloudflare-provider";

export function parseDeploymentList(result: unknown): readonly DeploymentProjection[] {
  const wrapper = exactObject(result, ["deployments"]);
  if (!Array.isArray(wrapper.deployments) || wrapper.deployments.length > MAX_DEPLOYMENTS) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_LIST_INVALID", 503, false);
  }
  const deployments = wrapper.deployments.map(parseDeployment);
  assertUnique(
    deployments.map((deployment) => deployment.id),
    "CLOUDFLARE_DEPLOYMENT_ID_ALIAS_FORBIDDEN",
  );
  return deployments;
}

export function parseDeployment(value: unknown): DeploymentProjection {
  const object = requireAllowedObject(
    value,
    ["annotations", "author_email", "created_on", "id", "source", "strategy", "versions"],
    ["created_on", "id", "source", "strategy", "versions"],
    "CLOUDFLARE_DEPLOYMENT_INVALID",
  );
  requireLiteral(object, "strategy", "percentage");
  if (!Array.isArray(object.versions) || object.versions.length < 1 || object.versions.length > 2) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_MEMBERSHIP_INVALID", 503, false);
  }
  const versions = object.versions.map((candidate) => {
    const member = exactObject(candidate, ["percentage", "version_id"]);
    return {
      percentage: requireInteger(member, "percentage", 0, 100),
      worker_version_id: requireString(member, "version_id", 36, VERSION),
    };
  });
  versions.sort(compareWorkerVersion);
  assertUnique(
    versions.map((member) => requireString(member, "worker_version_id", 36, VERSION)),
    "CLOUDFLARE_DEPLOYMENT_VERSION_ALIAS_FORBIDDEN",
  );
  const total = versions.reduce(
    (sum, member) => sum + requireInteger(member, "percentage", 0, 100),
    0,
  );
  assert(total === 100, "CLOUDFLARE_DEPLOYMENT_PERCENTAGE_INVALID", 503);
  return {
    annotations: parseAnnotations(object.annotations),
    author_email: optionalAsciiString(object, "author_email", 320),
    created_on: requireTimestamp(object, "created_on"),
    id: requireString(object, "id", 36, UUID),
    source: requireString(object, "source", 64, SOURCE),
    strategy: "percentage",
    versions,
  };
}

export async function parseVersionObservation(
  result: unknown,
  expectedVersionId: string,
): Promise<JsonObject> {
  const version = exactObject(result, ["id", "metadata", "number", "resources"]);
  assert(
    requireString(version, "id", 36, VERSION) === expectedVersionId,
    "CLOUDFLARE_VERSION_ID_MISMATCH",
    503,
  );
  const versionNumber = requireInteger(version, "number", 1);
  const metadata = exactObject(version.metadata, [
    "author_email",
    "author_id",
    "created_on",
    "hasPreview",
    "modified_on",
    "source",
  ]);
  requireString(metadata, "author_email", 320, /^[\x20-\x7e]+$/u);
  requireString(metadata, "author_id", 128, /^[A-Za-z0-9._:-]+$/u);
  if (typeof metadata.hasPreview !== "boolean") {
    throw new BrokerError("CLOUDFLARE_VERSION_METADATA_INVALID", 503, false);
  }
  const source = requireString(metadata, "source", 32);
  assert(VERSION_SOURCES.has(source), "CLOUDFLARE_VERSION_SOURCE_INVALID", 503);
  const projection = projectCloudflareWorkerVersionResources(version.resources);
  return {
    created_on: requireTimestamp(metadata, "created_on"),
    get_version_provider_response_sha256: "PENDING",
    has_preview: metadata.hasPreview,
    modified_on: requireTimestamp(metadata, "modified_on"),
    source,
    version_number: versionNumber,
    version_resource_projection: projection,
    version_resource_projection_sha256: await digestObject(projection),
    worker_version_id: expectedVersionId,
  };
}

export function assertDeploymentMatchesExpected(
  deployment: DeploymentProjection,
  expected: ExpectedServiceDeployment,
): void {
  if (
    expected.deployment_id === null ||
    deployment.id !== expected.deployment_id ||
    canonicalJson({ members: deployment.versions as unknown as JsonValue }) !==
      canonicalJson({
        members: expected.deployment_versions.map(({ percentage, worker_version_id }) => ({
          percentage,
          worker_version_id,
        })),
      })
  ) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_MEMBERSHIP_MISMATCH", 503, false);
  }
}

export function rawEvidenceRow(
  expected: ExpectedServiceDeployment,
  read: CloudflareProviderRead,
): JsonObject {
  return {
    authority_role: expected.authority_role,
    content_type: read.contentType,
    operation: read.operation,
    provider_request_id: read.providerRequestId,
    raw_body_base64: encodeBase64(read.rawBytes),
    raw_response_sha256: read.rawResponseSha256,
    request_path: read.path,
    service: expected.service,
    status: read.status,
  };
}

export function rawNetworkEvidenceRow(read: CloudflareProviderRead): JsonObject {
  return {
    content_type: read.contentType,
    operation: read.operation,
    provider_request_id: read.providerRequestId,
    raw_body_base64: encodeBase64(read.rawBytes),
    raw_response_sha256: read.rawResponseSha256,
    request_path: read.path,
    status: read.status,
  };
}

export function assertExpectedNetworkSurface(
  observed: JsonObject,
  expected: ExpectedCloudflareNetworkSurface,
): void {
  const normalized: JsonObject = {
    cert_id: expected.cert_id,
    environment: expected.environment,
    hostname: expected.hostname,
    id: expected.domain_id,
    service: expected.service,
    zone_id: expected.zone_id,
    zone_name: expected.zone_name,
  };
  if (canonicalJson(observed) !== canonicalJson(normalized)) {
    throw new BrokerError("CLOUDFLARE_WORKERS_DOMAIN_EXPECTATION_MISMATCH", 503, false);
  }
}
