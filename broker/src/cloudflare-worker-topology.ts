import { assert, BrokerError } from "./errors";
import { SERVICE_AUTHORITY_DEFINITIONS } from "./service-authority";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

const ACCOUNT_OBJECT_ID = /^[0-9a-f]{32}$/u;
const UUID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u;
const SERVICE = /^[a-z0-9][a-z0-9-]{1,127}$/u;

/**
 * Closed projection of the mutable script settings that are outside an
 * immutable Worker Version. Missing fields stay a hard HOLD until the live
 * installed-token rehearsal freezes the provider's concrete response shape.
 */
export function projectCloudflareScriptSettings(value: unknown): JsonObject {
  const settings = exactObject(value, ["logpush", "observability", "tags", "tail_consumers"]);
  assert(settings.logpush === false, "CLOUDFLARE_SCRIPT_LOGPUSH_FORBIDDEN", 503);
  if (!Array.isArray(settings.tags) || settings.tags.length !== 0) {
    throw new BrokerError("CLOUDFLARE_SCRIPT_TAGS_FORBIDDEN", 503, false);
  }
  if (!Array.isArray(settings.tail_consumers) || settings.tail_consumers.length !== 0) {
    throw new BrokerError("CLOUDFLARE_SCRIPT_TAIL_CONSUMERS_FORBIDDEN", 503, false);
  }
  const observability = exactObject(settings.observability, [
    "enabled",
    "head_sampling_rate",
    "logs",
    "traces",
  ]);
  assert(observability.enabled === false, "CLOUDFLARE_OBSERVABILITY_FORBIDDEN", 503);
  requireExactRate(observability.head_sampling_rate, "CLOUDFLARE_OBSERVABILITY_INVALID");
  const logs = exactObject(observability.logs, [
    "destinations",
    "enabled",
    "head_sampling_rate",
    "invocation_logs",
    "persist",
  ]);
  assert(logs.enabled === false, "CLOUDFLARE_LOGS_FORBIDDEN", 503);
  assert(logs.invocation_logs === false, "CLOUDFLARE_LOGS_FORBIDDEN", 503);
  assert(logs.persist === false, "CLOUDFLARE_LOGS_FORBIDDEN", 503);
  requireEmptyStringArray(logs.destinations, "CLOUDFLARE_LOG_DESTINATIONS_FORBIDDEN");
  requireExactRate(logs.head_sampling_rate, "CLOUDFLARE_LOGS_INVALID");
  const traces = exactObject(observability.traces, [
    "destinations",
    "enabled",
    "head_sampling_rate",
    "persist",
    "propagation_policy",
  ]);
  assert(traces.enabled === false, "CLOUDFLARE_TRACES_FORBIDDEN", 503);
  assert(traces.persist === false, "CLOUDFLARE_TRACES_FORBIDDEN", 503);
  requireEmptyStringArray(traces.destinations, "CLOUDFLARE_TRACE_DESTINATIONS_FORBIDDEN");
  requireExactRate(traces.head_sampling_rate, "CLOUDFLARE_TRACES_INVALID");
  assert(
    traces.propagation_policy === "authenticated",
    "CLOUDFLARE_TRACE_PROPAGATION_INVALID",
    503,
  );
  return {
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
  };
}

/** Require both workers.dev and preview URLs to be unavailable. */
export function projectCloudflareWorkerSubdomain(value: unknown): JsonObject {
  const subdomain = exactObject(value, ["enabled", "previews_enabled"]);
  assert(
    subdomain.enabled === false && subdomain.previews_enabled === false,
    "CLOUDFLARE_WORKER_SUBDOMAIN_FORBIDDEN",
    503,
  );
  return {
    enabled: false,
    previews_enabled: false,
    schema: "dpone.cloudflare-worker-subdomain-projection.v1",
  };
}

/**
 * Parse the complete account Custom Domain page. V1 intentionally supports
 * exactly one page and one ingress domain; a larger account remains HOLD
 * until bounded pagination is reviewed and versioned.
 */
export function projectCloudflareWorkersDomains(
  result: unknown,
  resultInfo: JsonObject | null,
): JsonObject {
  if (!Array.isArray(result) || result.length !== 1 || resultInfo === null) {
    throw new BrokerError("CLOUDFLARE_WORKERS_DOMAINS_INVALID", 503, false);
  }
  const count = requireInteger(resultInfo, "count", 0);
  const page = requireInteger(resultInfo, "page", 1);
  const perPage = requireInteger(resultInfo, "per_page", 1, 1000);
  const totalCount = requireInteger(resultInfo, "total_count", 0);
  const totalPages = requireInteger(resultInfo, "total_pages", 0);
  assert(
    count === 1 && page === 1 && perPage >= 1 && totalCount === 1 && totalPages === 1,
    "CLOUDFLARE_WORKERS_DOMAINS_PAGINATION_INVALID",
    503,
  );
  const domain = projectCloudflareWorkerDomain(result[0]);
  assert(
    domain.service === SERVICE_AUTHORITY_DEFINITIONS.release_authority_ingress.service,
    "CLOUDFLARE_WORKERS_DOMAIN_SERVICE_INVALID",
    503,
  );
  return {
    domain,
    schema: "dpone.cloudflare-workers-domains-projection.v1",
  };
}

/** Closed projection shared by list and exact get-domain requery. */
export function projectCloudflareWorkerDomain(value: unknown): JsonObject {
  const domain = requireAllowedDomain(value);
  if (
    Object.hasOwn(domain, "environment") &&
    domain.environment !== null &&
    domain.environment !== "production"
  ) {
    throw new BrokerError("CLOUDFLARE_WORKERS_DOMAIN_ENVIRONMENT_FORBIDDEN", 503, false);
  }
  return {
    cert_id: requireString(domain, "cert_id", 36, UUID),
    environment: domain.environment ?? null,
    hostname: requireString(domain, "hostname", 253, HOSTNAME),
    id: requireString(domain, "id", 32, ACCOUNT_OBJECT_ID),
    service: requireString(domain, "service", 128, SERVICE),
    zone_id: requireString(domain, "zone_id", 32, ACCOUNT_OBJECT_ID),
    zone_name: requireString(domain, "zone_name", 253, HOSTNAME),
  };
}

/** Dedicated authority zone must have no ordinary Workers Routes. */
export function projectCloudflareWorkerRoutes(result: unknown): JsonObject {
  if (!Array.isArray(result) || result.length !== 0) {
    throw new BrokerError("CLOUDFLARE_WORKERS_ROUTES_FORBIDDEN", 503, false);
  }
  return {
    routes: [],
    schema: "dpone.cloudflare-workers-routes-projection.v1",
  };
}

function requireAllowedDomain(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("CLOUDFLARE_WORKERS_DOMAIN_INVALID", 503, false);
  }
  const domain = value as JsonObject;
  const keys = Object.keys(domain);
  const allowed = new Set([
    "cert_id",
    "environment",
    "hostname",
    "id",
    "service",
    "zone_id",
    "zone_name",
  ]);
  const required = ["cert_id", "hostname", "id", "service", "zone_id", "zone_name"];
  if (
    keys.some((key) => !allowed.has(key)) ||
    required.some((key) => !Object.hasOwn(domain, key))
  ) {
    throw new BrokerError("CLOUDFLARE_WORKERS_DOMAIN_INVALID", 503, false);
  }
  return domain;
}

function requireExactRate(value: unknown, code: string): void {
  if (typeof value !== "number" || !Number.isFinite(value) || value !== 0) {
    throw new BrokerError(code, 503, false);
  }
}

function requireEmptyStringArray(value: unknown, code: string): void {
  if (!Array.isArray(value) || value.length !== 0) {
    throw new BrokerError(code, 503, false);
  }
}
