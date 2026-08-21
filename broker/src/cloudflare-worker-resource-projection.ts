import { canonicalJson } from "./canonical";
import { SAFE_CLOUDFLARE_MIGRATION_TAG } from "./cloudflare-migration-tag";
import { assert, BrokerError } from "./errors";
import type { JsonObject, JsonValue } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

const DATE = /^\d{4}-\d{2}-\d{2}$/u;
const NAME = /^[A-Za-z0-9_$][A-Za-z0-9_$.-]{0,127}$/u;
const BINDING = /^[A-Z][A-Z0-9_]{0,127}$/u;
const SAFE = /^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/u;

/** Parse the closed, sanitized Get Version Detail resource projection. */
export function parseCloudflareWorkerResourceProjection(value: unknown): JsonObject {
  const projection = exactObject(value, [
    "compatibility_date",
    "compatibility_flags",
    "cpu_ms",
    "durable_objects",
    "exports",
    "last_deployed_from",
    "migration_tag",
    "named_handlers",
    "plain_text",
    "schema",
    "script_etag",
    "script_handlers",
    "secret_names",
    "services",
    "usage_model",
    "version_metadata",
  ]);
  literal(projection, "schema", "dpone.cloudflare-worker-version-binding-projection.v1");
  requireString(projection, "compatibility_date", 10, DATE);
  requireString(projection, "script_etag", 512, /^[\x21-\x7e]{8,512}$/u);
  requireInteger(projection, "cpu_ms", 1, 300_000);
  const migrationTag = projection.migration_tag;
  assert(
    migrationTag === null ||
      (typeof migrationTag === "string" && SAFE_CLOUDFLARE_MIGRATION_TAG.test(migrationTag)),
    "CLOUDFLARE_RESOURCE_PROJECTION_INVALID",
    503,
  );
  const usageModel = requireString(projection, "usage_model", 16);
  assert(
    usageModel === "bundled" || usageModel === "standard" || usageModel === "unbound",
    "CLOUDFLARE_RESOURCE_PROJECTION_INVALID",
    503,
  );
  sortedStrings(projection.compatibility_flags, /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/u, 64);
  const handlers = sortedStrings(projection.script_handlers, /^[a-z][a-z0-9_-]{0,63}$/u, 8);
  assert(canonicalJson(handlers) === '["fetch"]', "CLOUDFLARE_RESOURCE_PROJECTION_INVALID", 503);
  sortedStrings(projection.secret_names, BINDING, 128);
  sortedStrings(projection.version_metadata, BINDING, 8);
  parseNamed(projection.named_handlers, parseNamedHandler);
  parseNamed(projection.durable_objects, parseDurableObject);
  parseNamed(projection.exports, parseExport);
  parseNamed(projection.plain_text, parsePlainText);
  parseNamed(projection.services, parseService);
  requireString(projection, "last_deployed_from", 64, SAFE);
  return projection;
}

function parseNamed(value: JsonValue | undefined, parse: (candidate: unknown) => string): void {
  if (!Array.isArray(value) || value.length > 128) {
    throw new BrokerError("CLOUDFLARE_RESOURCE_PROJECTION_INVALID", 503, false);
  }
  const names = value.map(parse);
  assertUniqueSorted(names);
}

function parseNamedHandler(value: unknown): string {
  const handler = exactObject(value, ["handlers", "name"]);
  sortedStrings(handler.handlers, /^[a-z][a-z0-9_-]{0,63}$/u, 16);
  return requireString(handler, "name", 128, NAME);
}

function parseDurableObject(value: unknown): string {
  const binding = exactObject(value, [
    "class_name",
    "dispatch_namespace",
    "environment",
    "name",
    "namespace_id",
    "script_name",
  ]);
  nullableString(binding, "dispatch_namespace", SAFE);
  nullableString(binding, "environment", SAFE);
  nullableString(binding, "namespace_id", /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/u);
  nullableString(binding, "script_name", SAFE);
  requireString(binding, "class_name", 128, SAFE);
  return requireString(binding, "name", 128, BINDING);
}

function parseExport(value: unknown): string {
  const candidate = record(value);
  const type = requireString(candidate, "type", 32);
  if (type === "worker") {
    const item = exactObject(candidate, ["cache_enabled", "name", "state", "type"]);
    assert(
      item.cache_enabled === null || typeof item.cache_enabled === "boolean",
      "CLOUDFLARE_RESOURCE_PROJECTION_INVALID",
      503,
    );
    literal(item, "state", "created");
    return requireString(item, "name", 128, NAME);
  }
  if (type === "durable-object") {
    const item = exactObject(candidate, ["container", "name", "state", "storage", "type"]);
    nullableString(item, "container", SAFE);
    literal(item, "state", "created");
    literal(item, "storage", "sqlite");
    return requireString(item, "name", 128, NAME);
  }
  throw new BrokerError("CLOUDFLARE_RESOURCE_PROJECTION_INVALID", 503, false);
}

function parsePlainText(value: unknown): string {
  const item = exactObject(value, ["name", "text"]);
  requireString(item, "text", 4096);
  return requireString(item, "name", 128, BINDING);
}

function parseService(value: unknown): string {
  const item = exactObject(value, ["entrypoint", "environment", "name", "service"]);
  nullableString(item, "entrypoint", SAFE);
  nullableString(item, "environment", SAFE);
  requireString(item, "service", 128, SAFE);
  return requireString(item, "name", 128, BINDING);
}

function sortedStrings(value: JsonValue | undefined, pattern: RegExp, maximum: number): string[] {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new BrokerError("CLOUDFLARE_RESOURCE_PROJECTION_INVALID", 503, false);
  }
  const strings = value.map((candidate) => {
    if (typeof candidate !== "string" || !pattern.test(candidate)) {
      throw new BrokerError("CLOUDFLARE_RESOURCE_PROJECTION_INVALID", 503, false);
    }
    return candidate;
  });
  assertUniqueSorted(strings);
  return strings;
}

function assertUniqueSorted(values: readonly string[]): void {
  assert(
    new Set(values).size === values.length &&
      canonicalJson(values) === canonicalJson([...values].sort()),
    "CLOUDFLARE_RESOURCE_PROJECTION_INVALID",
    503,
  );
}

function nullableString(object: JsonObject, key: string, pattern: RegExp): void {
  const value = object[key];
  assert(
    value === null || (typeof value === "string" && value.length <= 128 && pattern.test(value)),
    "CLOUDFLARE_RESOURCE_PROJECTION_INVALID",
    503,
  );
}

function record(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("CLOUDFLARE_RESOURCE_PROJECTION_INVALID", 503, false);
  }
  return value as JsonObject;
}

function literal(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, expected.length) === expected,
    "CLOUDFLARE_RESOURCE_PROJECTION_INVALID",
    503,
  );
}
