import { assert, BrokerError } from "./errors";
import { SAFE_CLOUDFLARE_MIGRATION_TAG } from "./cloudflare-migration-tag";
import type { JsonObject, JsonValue } from "./types";
import { exactObject, requireString } from "./validation";

const BINDING_NAME = /^[A-Z][A-Z0-9_]{0,127}$/u;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/u;
const EXPORT_NAME = /^(?:default|[A-Za-z_$][A-Za-z0-9_$]{0,127})$/u;
const HANDLER = /^[a-z][a-z0-9_-]{0,63}$/u;
const SCRIPT_ETAG = /^[\x21-\x7e]{8,512}$/u;
const DATE = /^\d{4}-\d{2}-\d{2}$/u;
const DEPLOYMENT_CLIENTS = new Set([
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
const USAGE_MODELS = new Set(["bundled", "standard", "unbound"]);

/**
 * Reduce Get Version Detail resources to the exact non-secret authority
 * surface. The provider etag is retained; it is never mislabeled as a local
 * source digest.
 */
export function projectCloudflareWorkerVersionResources(value: unknown): JsonObject {
  const resources = exactObject(value, ["bindings", "script", "script_runtime"]);
  const script = exactObject(resources.script, [
    "etag",
    "handlers",
    "last_deployed_from",
    "named_handlers",
  ]);
  const runtime = requireRecord(resources.script_runtime, "CLOUDFLARE_VERSION_RUNTIME_INVALID");
  requireAllowedKeys(
    runtime,
    [
      "compatibility_date",
      "compatibility_flags",
      "exports",
      "limits",
      "migration_tag",
      "usage_model",
    ],
    ["compatibility_date", "compatibility_flags", "exports", "limits", "usage_model"],
  );
  const handlers = stringArray(
    script.handlers,
    "CLOUDFLARE_VERSION_HANDLERS_INVALID",
    8,
    64,
    HANDLER,
  );
  assert(JSON.stringify(handlers) === '["fetch"]', "CLOUDFLARE_VERSION_HANDLERS_INVALID", 503);
  const namedHandlers = projectNamedHandlers(script.named_handlers);
  const deploymentClient = requireString(script, "last_deployed_from", 64);
  assert(
    DEPLOYMENT_CLIENTS.has(deploymentClient),
    "CLOUDFLARE_VERSION_DEPLOYMENT_CLIENT_INVALID",
    503,
  );
  const compatibilityFlags = stringArray(
    runtime.compatibility_flags,
    "CLOUDFLARE_VERSION_RUNTIME_INVALID",
    64,
    128,
    /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/u,
  ).sort();
  assertUnique(compatibilityFlags, "CLOUDFLARE_VERSION_RUNTIME_INVALID");
  const compatibilityDate = requireString(runtime, "compatibility_date", 10, DATE);
  const scriptEtag = requireString(script, "etag", 512, SCRIPT_ETAG);
  const runtimeExports = projectRuntimeExports(runtime.exports);
  const limits = exactObject(runtime.limits, ["cpu_ms"]);
  const cpuMs = requireIntegerValue(
    limits.cpu_ms,
    "CLOUDFLARE_VERSION_CPU_LIMIT_INVALID",
    1,
    300_000,
  );
  const migrationTag = Object.hasOwn(runtime, "migration_tag")
    ? requireString(runtime, "migration_tag", 128, SAFE_CLOUDFLARE_MIGRATION_TAG)
    : null;
  const usageModel = requireString(runtime, "usage_model", 16);
  assert(USAGE_MODELS.has(usageModel), "CLOUDFLARE_VERSION_USAGE_MODEL_INVALID", 503);
  if (!Array.isArray(resources.bindings)) {
    throw new BrokerError("CLOUDFLARE_VERSION_BINDINGS_INVALID", 503, false);
  }

  const durableObjects: JsonValue[] = [];
  const plainText: JsonValue[] = [];
  const secretNames: JsonValue[] = [];
  const services: JsonValue[] = [];
  const versionMetadata: JsonValue[] = [];
  const bindingNames = new Set<string>();
  for (const candidate of resources.bindings) {
    const binding = requireRecord(candidate, "CLOUDFLARE_VERSION_BINDING_INVALID");
    const name = requireBindingName(binding);
    if (bindingNames.has(name)) {
      throw new BrokerError("CLOUDFLARE_VERSION_BINDING_ALIAS_FORBIDDEN", 503, false);
    }
    bindingNames.add(name);
    const type = requireString(binding, "type", 64);
    if (type === "secret_text") {
      exactObject(binding, ["name", "type"]);
      secretNames.push(name);
    } else if (type === "plain_text") {
      exactObject(binding, ["name", "text", "type"]);
      plainText.push({ name, text: requireString(binding, "text", 4096) });
    } else if (type === "version_metadata") {
      exactObject(binding, ["name", "type"]);
      versionMetadata.push(name);
    } else if (type === "service") {
      requireAllowedKeys(
        binding,
        ["entrypoint", "environment", "name", "service", "type"],
        ["name", "service", "type"],
      );
      services.push({
        entrypoint: optionalString(binding, "entrypoint", SAFE_NAME),
        environment: optionalString(binding, "environment", SAFE_NAME),
        name,
        service: requireString(binding, "service", 128, SAFE_NAME),
      });
    } else if (type === "durable_object_namespace") {
      requireAllowedKeys(
        binding,
        [
          "class_name",
          "dispatch_namespace",
          "environment",
          "name",
          "namespace_id",
          "script_name",
          "type",
        ],
        ["class_name", "name", "type"],
      );
      durableObjects.push({
        class_name: requireString(binding, "class_name", 128, SAFE_NAME),
        dispatch_namespace: optionalString(binding, "dispatch_namespace", SAFE_NAME),
        environment: optionalString(binding, "environment", SAFE_NAME),
        name,
        namespace_id: optionalString(binding, "namespace_id", /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/u),
        script_name: optionalString(binding, "script_name", SAFE_NAME),
      });
    } else {
      throw new BrokerError("CLOUDFLARE_VERSION_BINDING_TYPE_FORBIDDEN", 503, false);
    }
  }

  for (const values of [durableObjects, plainText, secretNames, services, versionMetadata]) {
    values.sort(compareProjected);
  }
  return {
    compatibility_date: compatibilityDate,
    compatibility_flags: compatibilityFlags,
    cpu_ms: cpuMs,
    durable_objects: durableObjects,
    exports: runtimeExports,
    last_deployed_from: deploymentClient,
    migration_tag: migrationTag,
    named_handlers: namedHandlers,
    plain_text: plainText,
    schema: "dpone.cloudflare-worker-version-binding-projection.v1",
    script_etag: scriptEtag,
    script_handlers: handlers,
    secret_names: secretNames,
    services,
    usage_model: usageModel,
    version_metadata: versionMetadata,
  };
}

function projectNamedHandlers(value: unknown): JsonValue[] {
  if (!Array.isArray(value) || value.length > 128) {
    throw new BrokerError("CLOUDFLARE_VERSION_NAMED_HANDLERS_INVALID", 503, false);
  }
  const projected = value.map((candidate) => {
    const entry = exactObject(candidate, ["handlers", "name"]);
    return {
      handlers: stringArray(
        entry.handlers,
        "CLOUDFLARE_VERSION_NAMED_HANDLERS_INVALID",
        16,
        64,
        HANDLER,
      ).sort(),
      name: requireString(entry, "name", 128, EXPORT_NAME),
    };
  });
  projected.sort(compareProjected);
  assertUnique(
    projected.map((entry) => entry.name),
    "CLOUDFLARE_VERSION_NAMED_HANDLERS_INVALID",
  );
  return projected;
}

function projectRuntimeExports(value: unknown): JsonValue[] {
  const source = requireRecord(value, "CLOUDFLARE_VERSION_EXPORTS_INVALID");
  const names = Object.keys(source).sort();
  if (names.length === 0 || names.length > 128 || !names.every((name) => EXPORT_NAME.test(name))) {
    throw new BrokerError("CLOUDFLARE_VERSION_EXPORTS_INVALID", 503, false);
  }
  const projected = names.map((name) => {
    const candidate = requireRecord(source[name], "CLOUDFLARE_VERSION_EXPORT_INVALID");
    const type = requireString(candidate, "type", 32);
    if (type === "worker") {
      requireAllowedKeys(candidate, ["cache", "state", "type"], ["type"]);
      const state = Object.hasOwn(candidate, "state")
        ? requireString(candidate, "state", 16)
        : "created";
      assert(state === "created", "CLOUDFLARE_VERSION_EXPORT_STATE_INVALID", 503);
      let cacheEnabled: boolean | null = null;
      if (Object.hasOwn(candidate, "cache")) {
        const cache = exactObject(candidate.cache, ["enabled"]);
        if (typeof cache.enabled !== "boolean") {
          throw new BrokerError("CLOUDFLARE_VERSION_EXPORT_CACHE_INVALID", 503, false);
        }
        cacheEnabled = cache.enabled;
      }
      return { cache_enabled: cacheEnabled, name, state: "created", type: "worker" };
    }
    if (type === "durable-object") {
      requireAllowedKeys(candidate, ["container", "state", "storage", "type"], ["storage", "type"]);
      const state = Object.hasOwn(candidate, "state")
        ? requireString(candidate, "state", 32)
        : "created";
      assert(state === "created", "CLOUDFLARE_VERSION_EXPORT_STATE_INVALID", 503);
      assert(
        requireString(candidate, "storage", 16) === "sqlite",
        "CLOUDFLARE_VERSION_EXPORT_STORAGE_INVALID",
        503,
      );
      return {
        container: optionalString(candidate, "container", SAFE_NAME),
        name,
        state: "created",
        storage: "sqlite",
        type: "durable-object",
      };
    }
    throw new BrokerError("CLOUDFLARE_VERSION_EXPORT_TYPE_FORBIDDEN", 503, false);
  });
  const defaultExport = projected.find((entry) => entry.name === "default");
  if (defaultExport?.type !== "worker") {
    throw new BrokerError("CLOUDFLARE_VERSION_DEFAULT_EXPORT_INVALID", 503, false);
  }
  return projected;
}

function stringArray(
  value: unknown,
  code: string,
  maximumItems: number,
  maximumLength: number,
  pattern: RegExp,
): string[] {
  if (!Array.isArray(value) || value.length > maximumItems) {
    throw new BrokerError(code, 503, false);
  }
  return value.map((item) => {
    if (
      typeof item !== "string" ||
      item.length === 0 ||
      item.length > maximumLength ||
      !pattern.test(item)
    ) {
      throw new BrokerError(code, 503, false);
    }
    return item;
  });
}

function requireIntegerValue(
  value: unknown,
  code: string,
  minimum: number,
  maximum: number,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new BrokerError(code, 503, false);
  }
  return value as number;
}

function requireBindingName(binding: JsonObject): string {
  return requireString(binding, "name", 128, BINDING_NAME);
}

function optionalString(object: JsonObject, key: string, pattern: RegExp): string | null {
  if (!Object.hasOwn(object, key)) return null;
  return requireString(object, key, 128, pattern);
}

function requireRecord(value: unknown, code: string): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError(code, 503, false);
  }
  return value as JsonObject;
}

function requireAllowedKeys(
  object: JsonObject,
  allowed: readonly string[],
  required: readonly string[],
): void {
  const allowedSet = new Set(allowed);
  if (
    Object.keys(object).some((key) => !allowedSet.has(key)) ||
    required.some((key) => !Object.hasOwn(object, key))
  ) {
    throw new BrokerError("CLOUDFLARE_VERSION_BINDING_INVALID", 503, false);
  }
}

function compareProjected(left: JsonValue, right: JsonValue): number {
  const leftName = projectedName(left);
  const rightName = projectedName(right);
  return leftName < rightName ? -1 : leftName > rightName ? 1 : 0;
}

function projectedName(value: JsonValue): string {
  if (typeof value === "string") return value;
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const name = value.name;
    if (typeof name === "string") return name;
  }
  throw new BrokerError("CLOUDFLARE_VERSION_BINDING_INVALID", 503, false);
}

function assertUnique(values: readonly string[], code: string): void {
  assert(new Set(values).size === values.length, code, 503);
}
