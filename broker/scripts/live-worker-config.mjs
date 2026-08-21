import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ACCESS_AUDIENCE,
  ACCESS_ID,
  ACCESS_ISSUER,
  ACCOUNT_ID,
  AUTHORITY_VERSION_CEREMONY_SENTINEL,
  B2_BUCKET_ID,
  COMPATIBILITY_DATE,
  CONFIG_SCHEMA,
  EXPECTED_OBSERVABILITY,
  HOSTNAME,
  INGRESS_SERVICES,
  LIVE_WORKERS,
  POSITIVE_ID,
  SAFE_NAME,
  SECRET_NAME,
  SHA256_HEX,
  WORM_CALLER_IDENTITY_CEREMONY_SENTINEL,
} from "./live-worker-topology.mjs";
import { parseReviewedJsonc } from "./reviewed-jsonc.mjs";

export {
  AUTHORITY_VERSION_CEREMONY_SENTINEL,
  WORM_CALLER_IDENTITY_CEREMONY_SENTINEL,
} from "./live-worker-topology.mjs";

const PROJECT_ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));

/**
 * Load one checked-in publication review template and enforce its topology boundary.
 * Identifier resolution and provider authorization are separate fail-closed gates.
 */
export function loadLiveWorkerConfig(path) {
  const resolved = resolve(path);
  const filename = basename(resolved);
  const definition = LIVE_WORKERS[filename];
  if (resolved !== resolve(PROJECT_ROOT, filename) || definition === undefined) {
    throw new Error("deployment requires one exact reviewed broker live-config path");
  }
  const config = parseReviewedJsonc(readFileSync(resolved, "utf8"), resolved);
  validateLiveWorkerConfig(config, filename, definition.name);
  return { config, expectedName: definition.name, path: resolved };
}

/** Validate parsed config independently from filesystem I/O for closed smoke tests. */
export function validateLiveWorkerConfig(config, filename, expectedName) {
  const definition = LIVE_WORKERS[filename];
  if (definition === undefined || expectedName !== definition.name) {
    throw new Error("live Worker config identity/safety contract mismatch");
  }
  requireRecord(config, "live Worker config");
  const extras =
    definition.kind === "ingress"
      ? ["durable_objects", "migrations", "routes", "services"]
      : definition.kind === "worm"
        ? ["durable_objects", "migrations", "services"]
        : definition.kind === "cloudflare_observer"
          ? ["services"]
          : [];
  requireExactKeys(
    config,
    [
      "$schema",
      "account_id",
      "compatibility_date",
      "main",
      "name",
      "observability",
      "preview_urls",
      ...extras,
      "vars",
      "version_metadata",
      "workers_dev",
    ],
    "live Worker config",
  );
  if (
    config.$schema !== CONFIG_SCHEMA ||
    config.name !== definition.name ||
    config.main !== definition.main ||
    typeof config.account_id !== "string" ||
    !ACCOUNT_ID.test(config.account_id) ||
    config.compatibility_date !== COMPATIBILITY_DATE ||
    config.workers_dev !== false ||
    config.preview_urls !== false ||
    JSON.stringify(config.observability) !== JSON.stringify(EXPECTED_OBSERVABILITY) ||
    JSON.stringify(config.version_metadata) !== JSON.stringify({ binding: "CF_VERSION_METADATA" })
  ) {
    throw new Error("live Worker config identity/safety contract mismatch");
  }

  validateVariables(config.vars, definition, config.account_id);
  if (definition.kind === "ingress") {
    validateIngress(config);
  } else {
    if ("route" in config || "routes" in config) {
      throw new Error("private provider Worker must not have a public route");
    }
    if (definition.kind === "worm") {
      validateServiceBindings(config.services, [
        ["WORM_VERSION_OBSERVER", "dpone-release-worm-version-observer"],
      ]);
      validateWormDurableObjects(config.durable_objects, config.migrations);
    } else if (definition.kind === "cloudflare_observer") {
      validateServiceBindings(config.services, [["WORM_MIRROR", "dpone-release-worm-mirror"]]);
    }
  }
}

function validateWormDurableObjects(value, migrations) {
  const durable = requireRecord(value, "WORM Durable Object config");
  requireExactKeys(durable, ["bindings"], "WORM Durable Object config");
  if (
    JSON.stringify(durable.bindings) !==
      JSON.stringify([
        { class_name: "CloudflareEvidenceBatch", name: "CLOUDFLARE_EVIDENCE_BATCHES" },
        { class_name: "WormExactObjectEffect", name: "WORM_EXACT_OBJECT_EFFECTS" },
      ]) ||
    JSON.stringify(migrations) !==
      JSON.stringify([
        { new_sqlite_classes: ["CloudflareEvidenceBatch"], tag: "v1" },
        { new_sqlite_classes: ["WormExactObjectEffect"], tag: "v2" },
      ])
  ) {
    throw new Error("WORM Durable Object topology mismatch");
  }
}

/** Exact immutable Worker names accepted by upload/deployment tooling. */
export const LIVE_WORKER_IDENTITIES = Object.freeze(
  Object.fromEntries(
    Object.entries(LIVE_WORKERS).map(([filename, definition]) => [filename, definition.name]),
  ),
);

function validateVariables(value, definition, accountId) {
  const vars = requireRecord(value, "live Worker vars");
  const expected = {
    candidate: [
      "CANDIDATE_READER_SERVICE_NAME",
      "CF_ACCOUNT_ID",
      "GITHUB_APP_ID",
      "GITHUB_APP_INSTALLATION_ID",
      "OPERATING_MODE",
    ],
    cloudflare_observer: [
      "APPROVED_INGRESS_HOSTNAME",
      "APPROVED_INGRESS_ZONE_ID",
      "CF_ACCOUNT_ID",
      "EXPECTED_INGRESS_SERVICE_IDENTITY",
      "OPERATING_MODE",
      "SERVICE_NAME",
    ],
    controller: [
      "CF_ACCOUNT_ID",
      "GITHUB_APP_ID",
      "GITHUB_APP_INSTALLATION_ID",
      "GITHUB_APP_SLUG",
      "OPERATING_MODE",
      "SERVICE_NAME",
    ],
    deny: ["OPERATING_MODE", "SERVICE_NAME"],
    governance: [
      "CF_ACCOUNT_ID",
      "GITHUB_APP_ID",
      "GITHUB_APP_INSTALLATION_ID",
      "OPERATING_MODE",
      "SERVICE_NAME",
    ],
    ingress: [
      "ADMIN_ACCESS_APPLICATION_ID",
      "ADMIN_ACCESS_AUDIENCE",
      "ADMIN_ACCESS_ISSUER",
      "ADMIN_ACCESS_POLICY_ID",
      "ADMIN_HOSTNAME",
      "ADMIN_MTLS_CERT_SHA256",
      "BROKER_SERVICE_NAME",
      "CF_ACCOUNT_ID",
      "OPERATING_MODE",
    ],
    observer: ["B2_BUCKET_ID", "B2_BUCKET_NAME", "OPERATING_MODE"],
    worm: [
      "B2_BUCKET_ID",
      "B2_BUCKET_NAME",
      "CF_ACCOUNT_ID",
      "OPERATING_MODE",
      "SERVICE_NAME",
      "WORM_EXPECTED_B2_OBSERVER_SERVICE_IDENTITY",
      "WORM_EXPECTED_CALLER_SERVICE_IDENTITY",
      "WORM_EXPECTED_CLOUDFLARE_OBSERVER_SERVICE_IDENTITY",
    ],
  }[definition.kind];
  requireExactKeys(vars, expected, "live Worker vars");
  for (const key of Object.keys(vars)) {
    if (SECRET_NAME.test(key)) throw new Error("secret-bearing Worker variable must be a secret");
    if (typeof vars[key] !== "string") throw new Error("live Worker variables must be strings");
  }
  requireLiteral(vars, "OPERATING_MODE", "live");
  if ("CF_ACCOUNT_ID" in vars) requireLiteral(vars, "CF_ACCOUNT_ID", accountId);

  if (definition.kind === "ingress") {
    requireLiteral(vars, "BROKER_SERVICE_NAME", definition.name);
    requirePattern(vars, "ADMIN_MTLS_CERT_SHA256", SHA256_HEX);
    requirePattern(vars, "ADMIN_ACCESS_APPLICATION_ID", ACCESS_ID);
    requirePattern(vars, "ADMIN_ACCESS_AUDIENCE", ACCESS_AUDIENCE);
    requirePattern(vars, "ADMIN_ACCESS_ISSUER", ACCESS_ISSUER);
    requirePattern(vars, "ADMIN_ACCESS_POLICY_ID", ACCESS_ID);
    requirePattern(vars, "ADMIN_HOSTNAME", HOSTNAME);
  } else if (definition.kind === "candidate") {
    requireLiteral(vars, "CANDIDATE_READER_SERVICE_NAME", definition.name);
    requireProviderIds(vars);
  } else if (definition.kind === "controller") {
    requireLiteral(vars, "SERVICE_NAME", definition.name);
    requireProviderIds(vars);
    requirePattern(vars, "GITHUB_APP_SLUG", SAFE_NAME);
  } else if (definition.kind === "governance") {
    requireLiteral(vars, "SERVICE_NAME", definition.name);
    requireProviderIds(vars);
  } else if (definition.kind === "cloudflare_observer") {
    requireLiteral(vars, "SERVICE_NAME", definition.name);
    requirePattern(vars, "APPROVED_INGRESS_HOSTNAME", HOSTNAME);
    requirePattern(vars, "APPROVED_INGRESS_ZONE_ID", ACCOUNT_ID);
    requireLiteral(vars, "EXPECTED_INGRESS_SERVICE_IDENTITY", AUTHORITY_VERSION_CEREMONY_SENTINEL);
  } else if (definition.kind === "deny") {
    requireLiteral(vars, "SERVICE_NAME", definition.name);
  } else if (definition.kind === "worm") {
    requireLiteral(vars, "SERVICE_NAME", definition.name);
    requireB2Bucket(vars);
    requireLiteral(
      vars,
      "WORM_EXPECTED_B2_OBSERVER_SERVICE_IDENTITY",
      AUTHORITY_VERSION_CEREMONY_SENTINEL,
    );
    requireLiteral(
      vars,
      "WORM_EXPECTED_CALLER_SERVICE_IDENTITY",
      WORM_CALLER_IDENTITY_CEREMONY_SENTINEL,
    );
    requireLiteral(
      vars,
      "WORM_EXPECTED_CLOUDFLARE_OBSERVER_SERVICE_IDENTITY",
      AUTHORITY_VERSION_CEREMONY_SENTINEL,
    );
  } else {
    requireB2Bucket(vars);
  }
}

function validateIngress(config) {
  const vars = config.vars;
  if (
    !Array.isArray(config.routes) ||
    config.routes.length !== 1 ||
    config.routes[0]?.custom_domain !== true
  ) {
    throw new Error("live ingress requires one exact custom hostname");
  }
  requireExactKeys(config.routes[0], ["custom_domain", "pattern"], "live ingress route");
  requirePattern(config.routes[0], "pattern", HOSTNAME);
  requireLiteral(vars, "ADMIN_HOSTNAME", config.routes[0].pattern);
  validateServiceBindings(config.services, INGRESS_SERVICES);
  validateDurableObjects(config.durable_objects, config.migrations);
}

function validateServiceBindings(value, expected) {
  if (!Array.isArray(value) || value.length !== expected.length) {
    throw new Error("live Worker service binding topology mismatch");
  }
  value.forEach((raw, index) => {
    const item = requireRecord(raw, "live Worker service binding");
    requireExactKeys(item, ["binding", "service"], "live Worker service binding");
    requireLiteral(item, "binding", expected[index][0]);
    requireLiteral(item, "service", expected[index][1]);
  });
}

function validateDurableObjects(value, migrations) {
  const durable = requireRecord(value, "live Durable Object config");
  requireExactKeys(durable, ["bindings"], "live Durable Object config");
  const bindings = durable.bindings;
  const expectedBindings = [
    ["ACTIVATION_REGISTRY", "ActivationRegistry"],
    ["AUTH_REPLAY_LEDGER", "AuthReplayLedger"],
    ["GLOBAL_ACTIVATED_AUTHORITY_HEAD", "GlobalActivatedAuthorityHead"],
    ["RELEASE_LEDGERS", "ReleaseLedger"],
  ];
  if (!Array.isArray(bindings) || bindings.length !== expectedBindings.length) {
    throw new Error("live Durable Object topology mismatch");
  }
  bindings.forEach((raw, index) => {
    const item = requireRecord(raw, "live Durable Object binding");
    requireExactKeys(item, ["class_name", "name"], "live Durable Object binding");
    requireLiteral(item, "name", expectedBindings[index][0]);
    requireLiteral(item, "class_name", expectedBindings[index][1]);
  });

  const expectedMigrations = [
    { new_sqlite_classes: ["AuthReplayLedger", "ReleaseLedger"], tag: "v1" },
    { new_sqlite_classes: ["ActivationRegistry"], tag: "v2" },
    { new_sqlite_classes: ["GlobalActivatedAuthorityHead"], tag: "v3" },
  ];
  if (JSON.stringify(migrations) !== JSON.stringify(expectedMigrations)) {
    throw new Error("live Durable Object migration history mismatch");
  }
}

function requireB2Bucket(vars) {
  requirePattern(vars, "B2_BUCKET_ID", B2_BUCKET_ID);
  requirePattern(vars, "B2_BUCKET_NAME", SAFE_NAME);
}

function requireProviderIds(vars) {
  requirePattern(vars, "GITHUB_APP_ID", POSITIVE_ID);
  requirePattern(vars, "GITHUB_APP_INSTALLATION_ID", POSITIVE_ID);
  if (
    !Number.isSafeInteger(Number(vars.GITHUB_APP_ID)) ||
    !Number.isSafeInteger(Number(vars.GITHUB_APP_INSTALLATION_ID))
  ) {
    throw new Error("GitHub App identifiers must be JavaScript-safe");
  }
}

function requireExactKeys(value, expected, name) {
  requireRecord(value, name);
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(sortedExpected)) {
    throw new Error(`${name} keys mismatch`);
  }
}

function requireRecord(value, name) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new Error(`${name} must be a plain object`);
  }
  return value;
}

function requireLiteral(object, key, expected) {
  if (object[key] !== expected) throw new Error(`live Worker ${key} mismatch`);
}

function requirePattern(object, key, pattern) {
  const value = object[key];
  pattern.lastIndex = 0;
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new Error(`live Worker ${key} invalid`);
  }
}
