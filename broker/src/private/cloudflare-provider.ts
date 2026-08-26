import { INTERNAL_RESPONSE_READ_POLICY, readBoundedBytes } from "../bounded";
import { sha256Hex } from "../canonical";
import { CLOUDFLARE_UUID } from "../cloudflare-ids";
import { BrokerError } from "../errors";
import { SERVICE_AUTHORITY_DEFINITIONS, type ServiceAuthorityRole } from "../service-authority";
import { parseStrictJsonObject } from "../strict-json";
import type { JsonObject, JsonValue } from "../types";
import { exactObject } from "../validation";
import type { ProviderFetch } from "./github-provider";

export type CloudflareReadOperation =
  | "get_deployment"
  | "get_domain"
  | "get_script_settings"
  | "get_subdomain"
  | "get_version"
  | "list_deployments"
  | "list_domains"
  | "list_routes";

export interface CloudflareProviderRead {
  readonly contentType: "application/json";
  readonly operation: CloudflareReadOperation;
  readonly path: string;
  readonly providerRequestId: string | null;
  readonly rawBytes: Uint8Array;
  readonly rawResponseSha256: string;
  readonly result: JsonObject | readonly JsonValue[];
  readonly resultInfo: JsonObject | null;
  readonly status: 200;
}

const API_ORIGIN = "https://api.cloudflare.com";
// Four retained responses (A0 ingress) plus canonical envelope overhead must
// remain below the existing 64 KiB WORM object boundary.
const MAX_PROVIDER_BYTES = 8_192;
const PROVIDER_TIMEOUT_MS = 15_000;
const ACCOUNT_ID = /^[0-9a-f]{32}$/u;
const UUID = CLOUDFLARE_UUID;
const TOKEN = /^[\x21-\x7e]{20,512}$/u;
const REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/u;

/**
 * Narrow, read-only Cloudflare Workers control-plane adapter.
 *
 * It exposes only the reviewed Workers Scripts Read GETs and cannot construct a mutation request, an
 * arbitrary hostname, account, script or query string.
 */
export class CloudflareWorkersDeploymentReader {
  public constructor(
    private readonly accountId: string,
    private readonly apiToken: string,
    private readonly providerFetch: ProviderFetch = fetch,
  ) {
    if (!ACCOUNT_ID.test(accountId) || !TOKEN.test(apiToken) || /\s/u.test(apiToken)) {
      throw new BrokerError("CLOUDFLARE_PROVIDER_CONFIGURATION_INVALID", 500, false);
    }
  }

  public listDeployments(role: ServiceAuthorityRole): Promise<CloudflareProviderRead> {
    return this.read("list_deployments", `${this.scriptPath(role)}/deployments`);
  }

  public getDeployment(
    role: ServiceAuthorityRole,
    deploymentId: string,
  ): Promise<CloudflareProviderRead> {
    requireUuid(deploymentId);
    return this.read("get_deployment", `${this.scriptPath(role)}/deployments/${deploymentId}`);
  }

  public getVersion(
    role: ServiceAuthorityRole,
    versionId: string,
  ): Promise<CloudflareProviderRead> {
    requireUuid(versionId);
    return this.read("get_version", `${this.scriptPath(role)}/versions/${versionId}`);
  }

  public getScriptSettings(role: ServiceAuthorityRole): Promise<CloudflareProviderRead> {
    return this.read("get_script_settings", `${this.scriptPath(role)}/script-settings`);
  }

  public getSubdomain(role: ServiceAuthorityRole): Promise<CloudflareProviderRead> {
    return this.read("get_subdomain", `${this.scriptPath(role)}/subdomain`);
  }

  /**
   * Read the account-global Custom Domain inventory. V1 deliberately rejects
   * a multi-page result instead of accepting a potentially truncated set.
   */
  public listDomains(): Promise<CloudflareProviderRead> {
    return this.read("list_domains", `/client/v4/accounts/${this.accountId}/workers/domains`);
  }

  public getDomain(domainId: string): Promise<CloudflareProviderRead> {
    if (!/^[0-9a-f]{32}$/u.test(domainId)) {
      throw new BrokerError("CLOUDFLARE_PROVIDER_ID_INVALID", 503, false);
    }
    return this.read(
      "get_domain",
      `/client/v4/accounts/${this.accountId}/workers/domains/${domainId}`,
    );
  }

  public listRoutes(zoneId: string): Promise<CloudflareProviderRead> {
    if (!/^[0-9a-f]{32}$/u.test(zoneId)) {
      throw new BrokerError("CLOUDFLARE_PROVIDER_ID_INVALID", 503, false);
    }
    return this.read("list_routes", `/client/v4/zones/${zoneId}/workers/routes`);
  }

  private scriptPath(role: ServiceAuthorityRole): string {
    const service = SERVICE_AUTHORITY_DEFINITIONS[role].service;
    return `/client/v4/accounts/${this.accountId}/workers/scripts/${service}`;
  }

  private async read(
    operation: CloudflareReadOperation,
    path: string,
  ): Promise<CloudflareProviderRead> {
    assertClosedProviderPath(path, this.accountId);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), PROVIDER_TIMEOUT_MS);
    let response: Response;
    try {
      response = await this.providerFetch(`${API_ORIGIN}${path}`, {
        headers: {
          accept: "application/json",
          authorization: `Bearer ${this.apiToken}`,
          "user-agent": "dpone-release-cloudflare-deployment-observer/1",
        },
        method: "GET",
        redirect: "error",
        signal: controller.signal,
      });
    } catch {
      throw new BrokerError("CLOUDFLARE_PROVIDER_UNAVAILABLE", 503, true);
    } finally {
      clearTimeout(timeout);
    }
    await requireExactCloudflareJsonResponse(response);
    const rawBytes = await readBoundedBytes(
      response,
      MAX_PROVIDER_BYTES,
      "CLOUDFLARE_PROVIDER_BODY_INVALID",
      INTERNAL_RESPONSE_READ_POLICY,
    );
    const decoded = decodeCloudflareProviderReadEnvelope(rawBytes, operation);
    const requestId = response.headers.get("cf-ray");
    if (requestId !== null && !REQUEST_ID.test(requestId)) {
      throw new BrokerError("CLOUDFLARE_PROVIDER_REQUEST_ID_INVALID", 503, false);
    }
    return {
      contentType: "application/json",
      operation,
      path,
      providerRequestId: requestId,
      rawBytes,
      rawResponseSha256: `sha256:${await sha256Hex(rawBytes)}`,
      result: decoded.result,
      resultInfo: decoded.resultInfo,
      status: 200,
    };
  }
}

/** Reparse retained raw bytes under the same closed provider envelope. */
export function decodeCloudflareProviderEnvelope(rawBytes: Uint8Array): JsonObject {
  const decoded = decodeCloudflareProviderReadEnvelope(rawBytes, "get_version");
  if (Array.isArray(decoded.result)) {
    throw new BrokerError("CLOUDFLARE_PROVIDER_ENVELOPE_INVALID", 503, false);
  }
  return decoded.result as JsonObject;
}

/** Reparse one exact retained response using its operation-specific envelope. */
export function decodeCloudflareProviderReadEnvelope(
  rawBytes: Uint8Array,
  operation: CloudflareReadOperation,
): { readonly result: JsonObject | readonly JsonValue[]; readonly resultInfo: JsonObject | null } {
  const parsed = parseStrictJsonObject(rawBytes, "CLOUDFLARE_PROVIDER_JSON_INVALID");
  const envelope = exactObject(
    parsed,
    operation === "list_domains"
      ? ["errors", "messages", "result", "result_info", "success"]
      : ["errors", "messages", "result", "success"],
  );
  const expectsArray = operation === "list_domains" || operation === "list_routes";
  if (
    envelope.success !== true ||
    !Array.isArray(envelope.errors) ||
    envelope.errors.length !== 0 ||
    !Array.isArray(envelope.messages) ||
    envelope.messages.length !== 0 ||
    envelope.result === null ||
    typeof envelope.result !== "object" ||
    Array.isArray(envelope.result) !== expectsArray
  ) {
    throw new BrokerError("CLOUDFLARE_PROVIDER_ENVELOPE_INVALID", 503, false);
  }
  return {
    result: envelope.result,
    resultInfo:
      operation === "list_domains"
        ? exactObject(envelope.result_info, [
            "count",
            "page",
            "per_page",
            "total_count",
            "total_pages",
          ])
        : null,
  };
}

/** Reject authority-bearing transport transformations before reading bytes. */
export async function requireExactCloudflareJsonResponse(response: Response): Promise<void> {
  const mediaType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (
    response.status !== 200 ||
    mediaType !== "application/json" ||
    response.headers.has("content-encoding") ||
    response.headers.has("content-range") ||
    response.headers.has("location") ||
    response.headers.has("set-cookie") ||
    response.headers.has("transfer-encoding")
  ) {
    await response.body?.cancel("CLOUDFLARE_PROVIDER_RESPONSE_INVALID").catch(() => undefined);
    throw new BrokerError(
      "CLOUDFLARE_PROVIDER_RESPONSE_INVALID",
      503,
      response.status === 429 || response.status >= 500,
    );
  }
}

function assertClosedProviderPath(path: string, accountId: string): void {
  if (path.includes("?") || path.includes("#") || path.includes("\\")) {
    throw new BrokerError("CLOUDFLARE_PROVIDER_PATH_INVALID", 500, false);
  }
  const accountPrefix = `/client/v4/accounts/${accountId}/workers/`;
  if (/^\/client\/v4\/zones\/[0-9a-f]{32}\/workers\/routes$/u.test(path)) {
    return;
  }
  const domainPrefix = `${accountPrefix}domains/`;
  if (
    path === `${accountPrefix}domains` ||
    (path.startsWith(domainPrefix) && /^[0-9a-f]{32}$/u.test(path.slice(domainPrefix.length)))
  ) {
    return;
  }
  const prefix = `/client/v4/accounts/${accountId}/workers/scripts/`;
  const suffix = path.slice(prefix.length);
  const parts = suffix.split("/");
  const service = parts[0];
  const allowedServices: ReadonlySet<string> = new Set(
    Object.values(SERVICE_AUTHORITY_DEFINITIONS).map((definition) => definition.service),
  );
  const validTail =
    (parts.length === 2 && parts[1] === "deployments") ||
    (parts.length === 3 &&
      parts[1] === "deployments" &&
      parts[2] !== undefined &&
      UUID.test(parts[2])) ||
    (parts.length === 3 &&
      parts[1] === "versions" &&
      parts[2] !== undefined &&
      UUID.test(parts[2])) ||
    (parts.length === 2 && (parts[1] === "script-settings" || parts[1] === "subdomain"));
  if (
    !path.startsWith(prefix) ||
    service === undefined ||
    !allowedServices.has(service) ||
    !validTail
  ) {
    throw new BrokerError("CLOUDFLARE_PROVIDER_PATH_INVALID", 500, false);
  }
}

function requireUuid(value: string): void {
  if (!UUID.test(value)) {
    throw new BrokerError("CLOUDFLARE_PROVIDER_ID_INVALID", 503, false);
  }
}
