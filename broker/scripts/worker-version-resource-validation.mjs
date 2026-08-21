import {
  canonicalJson,
  compareNamed,
  exactKeys,
  record,
} from "./worker-version-resource-common.mjs";

/** Validate a persisted sanitized projection without trusting report fields. */
export function validateWorkerVersionResourceProjection(
  value,
  config,
  expectedSecrets,
  variableOverrides = {},
) {
  const projection = record(value, "immutable version binding projection");
  exactKeys(
    projection,
    [
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
    ],
    "immutable version binding projection",
  );
  const expectedPlainText = Object.entries({ ...config.vars, ...variableOverrides })
    .map(([name, text]) => ({ name, text }))
    .sort(compareNamed);
  const expectedServices = (config.services ?? [])
    .map((item) => ({
      entrypoint: item.entrypoint ?? null,
      environment: item.environment ?? null,
      name: item.binding,
      service: item.service,
    }))
    .sort(compareNamed);
  const expectedDurableObjects = (config.durable_objects?.bindings ?? [])
    .map((item) => ({
      class_name: item.class_name,
      dispatch_namespace: null,
      environment: item.environment ?? null,
      name: item.name,
      namespace_id: null,
      script_name: item.script_name ?? null,
    }))
    .sort(compareNamed);
  const expectedExports = expectedRuntimeExports(config);
  const expectedMigrationTag = expectedRuntimeMigrationTag(config);
  const secrets = [...expectedSecrets].sort();
  if (
    new Set(secrets).size !== secrets.length ||
    projection.schema !== "dpone.cloudflare-worker-version-binding-projection.v1" ||
    projection.compatibility_date !== config.compatibility_date ||
    JSON.stringify(projection.compatibility_flags) !==
      JSON.stringify(config.compatibility_flags ?? []) ||
    !Number.isSafeInteger(projection.cpu_ms) ||
    projection.cpu_ms < 1 ||
    projection.cpu_ms > 300_000 ||
    JSON.stringify(projection.exports) !== JSON.stringify(expectedExports) ||
    ![
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
    ].includes(projection.last_deployed_from) ||
    projection.migration_tag !== expectedMigrationTag ||
    !validNamedHandlersForExpectedExports(projection.named_handlers, expectedExports) ||
    !["bundled", "standard", "unbound"].includes(projection.usage_model) ||
    typeof projection.script_etag !== "string" ||
    !/^[\x21-\x7e]{8,512}$/u.test(projection.script_etag) ||
    JSON.stringify(projection.script_handlers) !== JSON.stringify(["fetch"]) ||
    JSON.stringify(projection.secret_names) !== JSON.stringify(secrets) ||
    JSON.stringify(projection.plain_text) !== JSON.stringify(expectedPlainText) ||
    JSON.stringify(projection.services) !== JSON.stringify(expectedServices) ||
    !durableObjectBindingsMatchConfig(projection.durable_objects, expectedDurableObjects) ||
    JSON.stringify(projection.version_metadata) !==
      JSON.stringify([config.version_metadata?.binding])
  ) {
    throw new Error("immutable version binding projection differs from reviewed config/secrets");
  }
  return projection;
}

/** Canonical no-newline bytes used by reports to bind the sanitized projection. */
export function canonicalWorkerVersionResourceProjectionBytes(value) {
  return Buffer.from(canonicalJson(value), "utf8");
}

function expectedRuntimeExports(config) {
  const exports = [{ cache_enabled: null, name: "default", state: "created", type: "worker" }];
  const classes = new Set();
  for (const migration of config.migrations ?? []) {
    for (const className of migration.new_sqlite_classes ?? []) {
      if (classes.has(className)) {
        throw new Error("reviewed Worker config repeats a Durable Object export");
      }
      classes.add(className);
      exports.push({
        container: null,
        name: className,
        state: "created",
        storage: "sqlite",
        type: "durable-object",
      });
    }
  }
  return exports.sort(compareNamed);
}

function expectedRuntimeMigrationTag(config) {
  const migrations = config.migrations ?? [];
  if (migrations.length === 0) return null;
  const tag = migrations.at(-1)?.tag;
  if (typeof tag !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(tag)) {
    throw new Error("reviewed Worker migration tag is invalid");
  }
  return tag;
}

function validNamedHandlersForExpectedExports(value, expectedExports) {
  if (!Array.isArray(value)) return false;
  const expectedNames = new Set(
    expectedExports.map((item) => item.name).filter((name) => name !== "default"),
  );
  const actualNames = value.map((item) => item?.name);
  return (
    new Set(actualNames).size === actualNames.length &&
    actualNames.length === expectedNames.size &&
    actualNames.every((name) => expectedNames.has(name)) &&
    value.every(
      (item) =>
        item !== null &&
        typeof item === "object" &&
        !Array.isArray(item) &&
        Object.keys(item).sort().join(",") === "handlers,name" &&
        Array.isArray(item.handlers) &&
        item.handlers.every(
          (handler) => typeof handler === "string" && /^[a-z][a-z0-9_-]{0,63}$/u.test(handler),
        ),
    )
  );
}

function durableObjectBindingsMatchConfig(actual, expected) {
  if (!Array.isArray(actual) || actual.length !== expected.length) return false;
  return actual.every((item, index) => {
    const reviewed = expected[index];
    return (
      item !== null &&
      typeof item === "object" &&
      !Array.isArray(item) &&
      item.class_name === reviewed.class_name &&
      item.dispatch_namespace === reviewed.dispatch_namespace &&
      item.environment === reviewed.environment &&
      item.name === reviewed.name &&
      item.script_name === reviewed.script_name &&
      (item.namespace_id === null ||
        (typeof item.namespace_id === "string" &&
          /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/u.test(item.namespace_id)))
    );
  });
}
