import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";

import { INGRESS_CONFIG, PRIVATE_CONFIGS, PROJECT_ROOT } from "./bootstrap-live-workers-common.mjs";
import {
  buildBootstrapWorkerConfig,
  canonicalBootstrapWorkerConfigBytes,
} from "./bootstrap-worker-config.mjs";
import { loadLiveWorkerConfig } from "./live-worker-config.mjs";
import {
  canonicalWorkerVersionResourceProjectionBytes,
  projectWorkerVersionResources,
} from "./worker-version-resources.mjs";
import {
  ACCOUNT_ID,
  BOOTSTRAP_BYTES,
  BOOTSTRAP_IDS,
  BUCKET_ID,
  BUCKET_NAME,
  CLOUDFLARE_TOKEN_FINGERPRINT,
  CONFIG_BYTES,
  MAIN_BYTES,
  VERSION_IDS,
  ZONE_ID,
  configs,
  dependencies,
  taggedSha256,
} from "./test-worm-rpc-key-fixtures.mjs";

/** Build an exact full-topology bootstrap report for ceremony provenance tests. */
export function canonicalBootstrapReport() {
  const workers = [...PRIVATE_CONFIGS, INGRESS_CONFIG].map((filename) => {
    const selectedRole = roleForFilename(filename);
    const inspected =
      selectedRole === null
        ? loadLiveWorkerConfig(resolve(PROJECT_ROOT, filename))
        : dependencies().loadLiveWorkerConfig(configs[selectedRole].live.pathname);
    const finalConfig = inspected.config;
    const bootstrapRole = bootstrapRoleForFilename(filename);
    const bootstrapMain = bootstrapMainForRole(bootstrapRole);
    const bootstrapConfig = buildBootstrapWorkerConfig(finalConfig, bootstrapRole, bootstrapMain);
    return {
      bootstrap_config: bootstrapConfig,
      bootstrap_config_sha256: taggedSha256(canonicalBootstrapWorkerConfigBytes(bootstrapConfig)),
      bootstrap_main: bootstrapMain,
      bootstrap_main_sha256: taggedSha256(readFileSync(resolve(PROJECT_ROOT, bootstrapMain))),
      config: inspected.path,
      config_sha256: taggedSha256(
        selectedRole === null ? readFileSync(inspected.path) : CONFIG_BYTES[selectedRole],
      ),
      final_main: finalConfig.main,
      final_main_sha256: taggedSha256(
        selectedRole === null
          ? readFileSync(resolve(PROJECT_ROOT, finalConfig.main))
          : MAIN_BYTES[selectedRole],
      ),
      name: finalConfig.name,
      role: bootstrapRole,
      ...(bootstrapRole === "ingress" ? { ingress_hostname: "release.example.test" } : {}),
    };
  });
  return {
    applied: true,
    bootstrap_secret_absent: true,
    plan: {
      bootstrap_ingress_source_sha256: taggedSha256(BOOTSTRAP_BYTES.ingress),
      bootstrap_private_source_sha256: taggedSha256(BOOTSTRAP_BYTES.observer),
      bootstrap_worm_source_sha256: taggedSha256(BOOTSTRAP_BYTES.worm),
      ingress_hostname: "release.example.test",
      lifecycle_migrations: workers
        .filter(({ role }) => role === "ingress" || role === "worm")
        .map((worker) => ({
          bootstrap_config_sha256: worker.bootstrap_config_sha256,
          durable_objects: worker.bootstrap_config.durable_objects.bindings.map((binding) => ({
            binding: binding.name,
            class_name: binding.class_name,
          })),
          migrations: worker.bootstrap_config.migrations.map((migration) => ({
            new_sqlite_classes: [...migration.new_sqlite_classes],
            tag: migration.tag,
          })),
          name: worker.name,
          role: worker.role,
        })),
      workers,
    },
    provider_observations: workers.map((worker, index) => {
      const bootstrapConfig = worker.bootstrap_config;
      const projection = projectWorkerVersionResources(
        bootstrapVersionResources(bootstrapConfig, index),
        bootstrapConfig,
        [],
      );
      const selectedRole = roleForFilename(basename(worker.config));
      return {
        binding_projection: projection,
        binding_projection_sha256: taggedSha256(
          canonicalWorkerVersionResourceProjectionBytes(projection),
        ),
        bootstrap_main: worker.bootstrap_main,
        bootstrap_main_sha256: worker.bootstrap_main_sha256,
        name: worker.name,
        version_id:
          selectedRole === null
            ? `00000000-0000-4000-8000-${String(index + 100).padStart(12, "0")}`
            : BOOTSTRAP_IDS[selectedRole],
      };
    }),
    schema: "dpone.release-broker-bootstrap-report.v2",
    schema_version: 2,
    smoke: { hostname: "release.example.test", liveness_version_id: BOOTSTRAP_IDS.ingress },
    version_message: "reviewed one-use lifecycle bootstrap",
    version_tag: "bootstrap-deny-v1",
  };
}

export function restrictionEvidence(role, keyId) {
  const capabilities =
    role === "writer"
      ? ["writeFiles"]
      : [
          "listBuckets",
          "listFiles",
          "readBucketEncryption",
          "readBucketReplications",
          "readBucketRetentions",
          "readFileRetentions",
          "readFiles",
        ];
  return {
    application_key_expiration_timestamp: null,
    bucket_id: BUCKET_ID,
    bucket_name: BUCKET_NAME,
    capabilities,
    key_id_sha256: taggedSha256(Buffer.from(keyId, "utf8")),
    name_prefix: "receipts/v1/",
    role,
    schema: "dpone.release-b2-key-restriction-evidence.v1",
    schema_version: 1,
  };
}

export function cloudflareRestrictionEvidence() {
  return {
    account_id: ACCOUNT_ID,
    grants: [
      { permission: "Workers Scripts Read", resource_scope: `account:${ACCOUNT_ID}` },
      { permission: "Workers Routes Read", resource_scope: `zone:${ZONE_ID}` },
    ],
    schema: "dpone.cloudflare-deployment-observer-token-restriction-evidence.v1",
    schema_version: 1,
    token_fingerprint_sha256: CLOUDFLARE_TOKEN_FINGERPRINT,
    zone_id: ZONE_ID,
  };
}

export function cloudflarePolicyEvidence() {
  return {
    account_id: ACCOUNT_ID,
    grants: cloudflareRestrictionEvidence().grants,
    observed_at: "2026-08-19T12:00:00.000Z",
    provider_observation_sha256: taggedSha256(Buffer.from("provider-policy", "utf8")),
    schema: "dpone.cloudflare-api-token-policy-observation.v1",
    schema_version: 1,
    token_fingerprint_sha256: CLOUDFLARE_TOKEN_FINGERPRINT,
    zone_id: ZONE_ID,
  };
}

/** Build the provider resource shape returned by exact final-version requery. */
export function versionResources(role, secretOverride, bootstrap = false) {
  const finalConfig = dependencies().loadLiveWorkerConfig(configs[role].live.pathname).config;
  const config = bootstrap
    ? buildBootstrapWorkerConfig(
        finalConfig,
        bootstrapRoleForRole(role),
        bootstrapMainForRole(bootstrapRoleForRole(role)),
      )
    : finalConfig;
  const callerIdentity = `cloudflare-worker:${ACCOUNT_ID}/dpone-release-authority-broker@${VERSION_IDS.ingress}`;
  const vars = {
    ...config.vars,
    ...(role === "cloudflareObserver" && secretOverride === undefined
      ? {
          EXPECTED_INGRESS_SERVICE_IDENTITY: `cloudflare-worker:${ACCOUNT_ID}/${configs.ingress.name}@${VERSION_IDS.ingress}`,
        }
      : {}),
    ...(role === "worm" && secretOverride === undefined
      ? {
          WORM_EXPECTED_B2_OBSERVER_SERVICE_IDENTITY: `cloudflare-worker:${ACCOUNT_ID}/${configs.observer.name}@${VERSION_IDS.observer}`,
          WORM_EXPECTED_CALLER_SERVICE_IDENTITY: callerIdentity,
          WORM_EXPECTED_CLOUDFLARE_OBSERVER_SERVICE_IDENTITY:
            `cloudflare-worker:${ACCOUNT_ID}/${configs.cloudflareObserver.name}@` +
            VERSION_IDS.cloudflareObserver,
        }
      : {}),
  };
  const secrets = bootstrap
    ? []
    : (secretOverride ??
      {
        cloudflareObserver: [
          "CLOUDFLARE_API_TOKEN",
          "CLOUDFLARE_EVIDENCE_RPC_AUTH_KEY",
          "CLOUDFLARE_OBSERVER_RPC_AUTH_KEY",
        ],
        ingress: [
          "ADMIN_ACCESS_GROUP",
          "ADMIN_ACCESS_IDENTITY",
          "ADMIN_ACCESS_SUBJECT_ID",
          "CLOUDFLARE_OBSERVER_RPC_AUTH_KEY",
          "WORM_RPC_AUTH_KEY",
        ],
        observer: ["B2_APPLICATION_KEY", "B2_KEY_ID"],
        worm: [
          "B2_APPLICATION_KEY",
          "B2_KEY_ID",
          "CLOUDFLARE_EVIDENCE_RPC_AUTH_KEY",
          "WORM_RPC_AUTH_KEY",
        ],
      }[role]);
  const durableClasses = (config.migrations ?? []).flatMap(
    (migration) => migration.new_sqlite_classes ?? [],
  );
  return {
    bindings: [
      ...Object.entries(vars).map(([name, text]) => ({ name, text, type: "plain_text" })),
      ...(config.services ?? []).map((item) => ({
        name: item.binding,
        service: item.service,
        type: "service",
      })),
      ...(config.durable_objects?.bindings ?? []).map((item) => ({
        class_name: item.class_name,
        name: item.name,
        namespace_id: `namespace-${item.name}`.slice(0, 32),
        type: "durable_object_namespace",
      })),
      { name: "CF_VERSION_METADATA", type: "version_metadata" },
      ...secrets.map((name) => ({ name, type: "secret_text" })),
    ],
    script: {
      etag: `provider-etag-${role}-0001`,
      handlers: ["fetch"],
      last_deployed_from: "wrangler",
      named_handlers: durableClasses.map((name) => ({ handlers: [], name })),
    },
    script_runtime: {
      compatibility_date: "2026-08-15",
      compatibility_flags: [],
      exports: Object.fromEntries([
        ["default", { state: "created", type: "worker" }],
        ...durableClasses.map((name) => [
          name,
          { state: "created", storage: "sqlite", type: "durable-object" },
        ]),
      ]),
      limits: { cpu_ms: 30_000 },
      ...(durableClasses.length === 0 ? {} : { migration_tag: config.migrations.at(-1).tag }),
      usage_model: "standard",
    },
  };
}

function bootstrapVersionResources(config, index) {
  const durableClasses = (config.migrations ?? []).flatMap(
    (migration) => migration.new_sqlite_classes ?? [],
  );
  return {
    bindings: [
      ...Object.entries(config.vars).map(([name, text]) => ({ name, text, type: "plain_text" })),
      ...(config.durable_objects?.bindings ?? []).map((binding) => ({
        class_name: binding.class_name,
        name: binding.name,
        namespace_id: `namespace-${binding.name}`.slice(0, 32),
        type: "durable_object_namespace",
      })),
      { name: "CF_VERSION_METADATA", type: "version_metadata" },
    ],
    script: {
      etag: `provider-bootstrap-etag-${String(index).padStart(2, "0")}`,
      handlers: ["fetch"],
      last_deployed_from: "wrangler",
      named_handlers: durableClasses.map((name) => ({ handlers: [], name })),
    },
    script_runtime: {
      compatibility_date: "2026-08-15",
      compatibility_flags: [],
      exports: Object.fromEntries([
        ["default", { state: "created", type: "worker" }],
        ...durableClasses.map((name) => [
          name,
          { state: "created", storage: "sqlite", type: "durable-object" },
        ]),
      ]),
      limits: { cpu_ms: 30_000 },
      ...(durableClasses.length === 0 ? {} : { migration_tag: config.migrations.at(-1).tag }),
      usage_model: "standard",
    },
  };
}

function roleForFilename(filename) {
  const match = Object.entries(configs).find(
    ([, config]) => basename(config.live.pathname) === filename,
  );
  return match?.[0] ?? null;
}

function bootstrapRoleForFilename(filename) {
  return filename === INGRESS_CONFIG
    ? "ingress"
    : filename === "wrangler.worm-mirror.live.jsonc"
      ? "worm"
      : "private";
}

function bootstrapRoleForRole(role) {
  return role === "ingress" ? "ingress" : role === "worm" ? "worm" : "private";
}

function bootstrapMainForRole(role) {
  return role === "ingress"
    ? "src/bootstrap-ingress.ts"
    : role === "worm"
      ? "src/bootstrap-worm.ts"
      : "src/bootstrap-private.ts";
}
