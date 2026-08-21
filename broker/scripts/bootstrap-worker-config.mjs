/**
 * Build the credential-free Worker config used by the one-time blank-account
 * lifecycle bootstrap. Service bindings are deliberately absent: Cloudflare
 * requires every binding target to exist before upload, while a blank account
 * has no private authority scripts yet.
 */
export function buildBootstrapWorkerConfig(finalConfig, role, bootstrapMain) {
  requireRecord(finalConfig, "final Worker config");
  if (!["ingress", "private", "worm"].includes(role) || typeof bootstrapMain !== "string") {
    throw new Error("bootstrap Worker role/main is invalid");
  }
  const config = {
    $schema: finalConfig.$schema,
    account_id: finalConfig.account_id,
    compatibility_date: finalConfig.compatibility_date,
    main: bootstrapMain,
    name: finalConfig.name,
    observability: globalThis.structuredClone(finalConfig.observability),
    preview_urls: false,
    vars: { OPERATING_MODE: "provisioning" },
    version_metadata: globalThis.structuredClone(finalConfig.version_metadata),
    workers_dev: false,
  };
  if (role === "ingress" || role === "worm") {
    config.durable_objects = globalThis.structuredClone(finalConfig.durable_objects);
    config.migrations = globalThis.structuredClone(finalConfig.migrations);
  }
  if (role === "ingress") {
    config.routes = globalThis.structuredClone(finalConfig.routes);
  }
  assertBootstrapWorkerConfig(config, role, bootstrapMain);
  return Object.freeze(config);
}

/** Canonical bytes are persisted only in a private temporary directory. */
export function canonicalBootstrapWorkerConfigBytes(config) {
  return Buffer.from(`${JSON.stringify(config)}\n`, "utf8");
}

export function assertBootstrapWorkerConfig(config, role, bootstrapMain) {
  requireRecord(config, "bootstrap Worker config");
  const expectedKeys = [
    "$schema",
    "account_id",
    "compatibility_date",
    "main",
    "name",
    "observability",
    "preview_urls",
    ...(role === "ingress" ? ["durable_objects", "migrations", "routes"] : []),
    ...(role === "worm" ? ["durable_objects", "migrations"] : []),
    "vars",
    "version_metadata",
    "workers_dev",
  ].sort();
  if (
    JSON.stringify(Object.keys(config).sort()) !== JSON.stringify(expectedKeys) ||
    config.main !== bootstrapMain ||
    config.preview_urls !== false ||
    config.workers_dev !== false ||
    JSON.stringify(config.vars) !== JSON.stringify({ OPERATING_MODE: "provisioning" }) ||
    "services" in config ||
    "route" in config ||
    (role === "private" && "routes" in config)
  ) {
    throw new Error("bootstrap Worker config is not binding-free and credential-free");
  }
}

function requireRecord(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}
