import {
  allowedKeys,
  compareNamed,
  compareProjected,
  exactKeys,
  record,
} from "./worker-version-resource-common.mjs";
import { validateWorkerVersionResourceProjection } from "./worker-version-resource-validation.mjs";

/**
 * Build the closed, secret-value-free projection returned by
 * `wrangler versions view --json` and bind it to one reviewed config.
 */
export function projectWorkerVersionResources(
  resources,
  config,
  expectedSecrets,
  variableOverrides = {},
) {
  const source = record(resources, "immutable version resources");
  exactKeys(source, ["bindings", "script", "script_runtime"], "immutable version resources");
  const script = record(source.script, "immutable version script");
  exactKeys(
    script,
    ["etag", "handlers", "last_deployed_from", "named_handlers"],
    "immutable version script",
  );
  const runtime = record(source.script_runtime, "immutable version runtime");
  allowedKeys(
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
    "immutable version runtime",
  );
  const namedHandlers = projectNamedHandlers(script.named_handlers);
  const runtimeExports = projectRuntimeExports(runtime.exports);
  const limits = record(runtime.limits, "immutable version runtime limits");
  exactKeys(limits, ["cpu_ms"], "immutable version runtime limits");
  const deploymentClients = new Set([
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
  if (
    typeof script.etag !== "string" ||
    !/^[\x21-\x7e]{8,512}$/u.test(script.etag) ||
    JSON.stringify(script.handlers) !== JSON.stringify(["fetch"]) ||
    !deploymentClients.has(script.last_deployed_from) ||
    runtime.compatibility_date !== config.compatibility_date ||
    JSON.stringify(runtime.compatibility_flags) !==
      JSON.stringify(config.compatibility_flags ?? []) ||
    !Number.isSafeInteger(limits.cpu_ms) ||
    limits.cpu_ms < 1 ||
    limits.cpu_ms > 300_000 ||
    (runtime.migration_tag !== undefined &&
      (typeof runtime.migration_tag !== "string" ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(runtime.migration_tag))) ||
    !["bundled", "standard", "unbound"].includes(runtime.usage_model) ||
    !Array.isArray(source.bindings)
  ) {
    throw new Error("immutable version script/runtime projection mismatch");
  }

  const projection = {
    durable_objects: [],
    plain_text: [],
    secret_names: [],
    services: [],
    version_metadata: [],
  };
  const names = new Set();
  for (const candidate of source.bindings) {
    const binding = record(candidate, "immutable version binding");
    if (typeof binding.name !== "string" || binding.name.length === 0 || names.has(binding.name)) {
      throw new Error("immutable version binding identity is ambiguous");
    }
    names.add(binding.name);
    if (binding.type === "secret_text") {
      exactKeys(binding, ["name", "type"], "immutable secret binding");
      projection.secret_names.push(binding.name);
    } else if (binding.type === "plain_text" && typeof binding.text === "string") {
      exactKeys(binding, ["name", "text", "type"], "immutable plain-text binding");
      projection.plain_text.push({ name: binding.name, text: binding.text });
    } else if (binding.type === "version_metadata") {
      exactKeys(binding, ["name", "type"], "immutable version-metadata binding");
      projection.version_metadata.push(binding.name);
    } else if (binding.type === "service" && typeof binding.service === "string") {
      allowedKeys(
        binding,
        ["entrypoint", "environment", "name", "service", "type"],
        ["name", "service", "type"],
        "immutable service binding",
      );
      projection.services.push({
        entrypoint: binding.entrypoint ?? null,
        environment: binding.environment ?? null,
        name: binding.name,
        service: binding.service,
      });
    } else if (
      binding.type === "durable_object_namespace" &&
      typeof binding.class_name === "string"
    ) {
      allowedKeys(
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
        "immutable Durable Object binding",
      );
      for (const optional of ["dispatch_namespace", "environment", "namespace_id", "script_name"]) {
        if (binding[optional] !== undefined && typeof binding[optional] !== "string") {
          throw new Error("immutable Durable Object binding contains malformed authority metadata");
        }
      }
      projection.durable_objects.push({
        class_name: binding.class_name,
        dispatch_namespace: binding.dispatch_namespace ?? null,
        environment: binding.environment ?? null,
        name: binding.name,
        namespace_id: binding.namespace_id ?? null,
        script_name: binding.script_name ?? null,
      });
    } else {
      throw new Error("immutable version contains an unknown or malformed binding");
    }
  }
  for (const values of Object.values(projection)) values.sort(compareProjected);

  return validateWorkerVersionResourceProjection(
    {
      ...projection,
      compatibility_date: runtime.compatibility_date,
      compatibility_flags: [...runtime.compatibility_flags],
      cpu_ms: limits.cpu_ms,
      exports: runtimeExports,
      last_deployed_from: script.last_deployed_from,
      migration_tag: runtime.migration_tag ?? null,
      named_handlers: namedHandlers,
      schema: "dpone.cloudflare-worker-version-binding-projection.v1",
      script_etag: script.etag,
      script_handlers: [...script.handlers],
      usage_model: runtime.usage_model,
    },
    config,
    expectedSecrets,
    variableOverrides,
  );
}

function projectNamedHandlers(value) {
  if (!Array.isArray(value) || value.length > 128) {
    throw new Error("immutable version named handlers are invalid");
  }
  const projected = value.map((candidate) => {
    const entry = record(candidate, "immutable version named handler");
    exactKeys(entry, ["handlers", "name"], "immutable version named handler");
    if (
      typeof entry.name !== "string" ||
      !/^(?:default|[A-Za-z_$][A-Za-z0-9_$]{0,127})$/u.test(entry.name) ||
      !Array.isArray(entry.handlers) ||
      entry.handlers.length > 16 ||
      entry.handlers.some(
        (handler) => typeof handler !== "string" || !/^[a-z][a-z0-9_-]{0,63}$/u.test(handler),
      )
    ) {
      throw new Error("immutable version named handler is invalid");
    }
    return { handlers: [...entry.handlers].sort(), name: entry.name };
  });
  projected.sort(compareNamed);
  if (new Set(projected.map((item) => item.name)).size !== projected.length) {
    throw new Error("immutable version named handler identity is ambiguous");
  }
  return projected;
}

function projectRuntimeExports(value) {
  const source = record(value, "immutable version runtime exports");
  const names = Object.keys(source).sort();
  if (
    names.length === 0 ||
    names.length > 128 ||
    names.some((name) => !/^(?:default|[A-Za-z_$][A-Za-z0-9_$]{0,127})$/u.test(name))
  ) {
    throw new Error("immutable version runtime exports are invalid");
  }
  const projected = names.map((name) => {
    const entry = record(source[name], "immutable version runtime export");
    if (entry.type === "worker") {
      allowedKeys(entry, ["cache", "state", "type"], ["type"], "Worker runtime export");
      if (entry.state !== undefined && entry.state !== "created") {
        throw new Error("immutable version contains a non-live Worker export");
      }
      let cacheEnabled = null;
      if (entry.cache !== undefined) {
        const cache = record(entry.cache, "Worker export cache");
        exactKeys(cache, ["enabled"], "Worker export cache");
        if (typeof cache.enabled !== "boolean") throw new Error("Worker export cache is invalid");
        cacheEnabled = cache.enabled;
      }
      return { cache_enabled: cacheEnabled, name, state: "created", type: "worker" };
    }
    if (entry.type === "durable-object") {
      allowedKeys(
        entry,
        ["container", "state", "storage", "type"],
        ["storage", "type"],
        "Durable Object runtime export",
      );
      if (
        (entry.state !== undefined && entry.state !== "created") ||
        entry.storage !== "sqlite" ||
        (entry.container !== undefined &&
          (typeof entry.container !== "string" ||
            !/^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/u.test(entry.container)))
      ) {
        throw new Error("immutable version contains a non-live Durable Object export");
      }
      return {
        container: entry.container ?? null,
        name,
        state: "created",
        storage: "sqlite",
        type: "durable-object",
      };
    }
    throw new Error("immutable version contains an unknown runtime export");
  });
  if (!projected.some((item) => item.name === "default" && item.type === "worker")) {
    throw new Error("immutable version default Worker export is missing");
  }
  return projected;
}
