import { CLOUDFLARE_UUID } from "./cloudflare-ids";
import type {
  DeploymentObservationPhase,
  ExpectedCloudflareNetworkSurface,
  ExpectedServiceDeployment,
  ServiceAuthorityInventoryRow,
} from "./service-authority";
import type { JsonObject } from "./types";
import type { CloudflareProviderRead } from "./private/cloudflare-provider";

export const CLOUDFLARE_DEPLOYMENT_OBSERVATION_RPC_PATH = "/rpc/v1/cloudflare/deployments/observe";
export const CLOUDFLARE_DEPLOYMENT_REQUEST_SCHEMA =
  "dpone.cloudflare-deployment-observation-request.v1";
export const CLOUDFLARE_DEPLOYMENT_OBSERVATION_SCHEMA =
  "dpone.cloudflare-deployment-observation.v1";
export const CLOUDFLARE_DEPLOYMENT_RESULT_SCHEMA =
  "dpone.cloudflare-deployment-observation-result.v1";
export const CLOUDFLARE_DEPLOYMENT_EVIDENCE_SCHEMA =
  "dpone.release-broker-cloudflare-deployment-evidence-entry.v1";
export const CLOUDFLARE_DEPLOYMENT_EVIDENCE_KIND = "cloudflare_service_deployments" as const;
export const CLOUDFLARE_NETWORK_EVIDENCE_SCHEMA =
  "dpone.release-broker-cloudflare-network-surface-evidence-entry.v1";
export const CLOUDFLARE_NETWORK_EVIDENCE_KIND = "cloudflare_network_surface" as const;
export const CLOUDFLARE_SANITIZED_SERVICE_EVIDENCE_SCHEMA =
  "dpone.release-broker-cloudflare-deployment-observation-record.v1";
export const CLOUDFLARE_SANITIZED_NETWORK_EVIDENCE_SCHEMA =
  "dpone.release-broker-cloudflare-network-surface-observation-record.v1";

export const DIGEST = /^sha256:[0-9a-f]{64}$/u;
export const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;
export const UUID = CLOUDFLARE_UUID;
export const VERSION = CLOUDFLARE_UUID;
export const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u;
export const SOURCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
export const VERSION_SOURCES = new Set([
  "api",
  "cf_cli",
  "dash",
  "dash_template",
  "integration",
  "playground",
  "quick_editor",
  "terraform",
  "workersci",
  "wrangler",
]);
export const SERVICE_IDENTITY =
  /^cloudflare-worker:[0-9a-f]{32}\/[a-z0-9][a-z0-9-]{1,127}@[0-9a-f-]{36}$/u;
export const PROVIDER_REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/u;
export const MAX_DEPLOYMENTS = 100;
export const MAX_PARALLEL_SERVICES = 4;
export const MAX_EVIDENCE_ENTRY_BYTES = 65_536;
export const ACCOUNT_ID = /^[0-9a-f]{32}$/u;

export interface CloudflareDeploymentObservationRequest {
  readonly expectedDeployments: readonly ExpectedServiceDeployment[];
  readonly expectationSha256: string;
  readonly expectedNetworkSurface: ExpectedCloudflareNetworkSurface;
  readonly phase: DeploymentObservationPhase;
  readonly requestId: string;
}

export interface CloudflareDeploymentObservationRpcRequest
  extends CloudflareDeploymentObservationRequest {
  readonly inventory: readonly ServiceAuthorityInventoryRow[];
  readonly requestedAt: string;
}

export interface CloudflareDeploymentObservationResult {
  readonly evidenceEntries: readonly JsonObject[];
  readonly networkEvidenceEntry: JsonObject;
  readonly observation: JsonObject;
}

export interface SanitizedCloudflareEvidence {
  readonly record: JsonObject;
  readonly recordId: string;
  readonly recordSha256: string;
}

export interface ObservedService {
  readonly evidenceReads: readonly CloudflareProviderRead[];
  readonly observation: JsonObject;
}

export interface ObservedNetworkSurface {
  readonly evidenceReads: readonly CloudflareProviderRead[];
  readonly observation: JsonObject;
}

export interface DeploymentProjection {
  readonly annotations: JsonObject | null;
  readonly author_email: string | null;
  readonly created_on: string;
  readonly id: string;
  readonly source: string;
  readonly strategy: "percentage";
  readonly versions: readonly JsonObject[];
}
