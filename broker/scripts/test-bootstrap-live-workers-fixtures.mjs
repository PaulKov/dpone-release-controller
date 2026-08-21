import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";
import { basename } from "node:path";

import { buildBootstrapWorkerConfig } from "./bootstrap-worker-config.mjs";

export const NAMES = new Map([
  ["wrangler.attestation-mutator.live.jsonc", "dpone-release-attestation-mutator"],
  ["wrangler.candidate-reader.live.jsonc", "dpone-release-candidate-reader"],
  ["wrangler.closed-projector.live.jsonc", "dpone-release-closed-projector"],
  [
    "wrangler.cloudflare-deployment-observer.live.jsonc",
    "dpone-release-cloudflare-deployment-observer",
  ],
  ["wrangler.controller-run-reader.live.jsonc", "dpone-release-controller-run-reader"],
  ["wrangler.governance-reader.live.jsonc", "dpone-release-governance-reader"],
  ["wrangler.pypi-deployment-gate.live.jsonc", "dpone-release-pypi-deployment-gate"],
  ["wrangler.pypi-reader.live.jsonc", "dpone-release-pypi-reader"],
  ["wrangler.release-mutator.live.jsonc", "dpone-release-mutator"],
  ["wrangler.runtime-deployment-gate.live.jsonc", "dpone-release-runtime-deployment-gate"],
  ["wrangler.tenant-scanner.live.jsonc", "dpone-release-tenant-scanner"],
  ["wrangler.worm-mirror.live.jsonc", "dpone-release-worm-mirror"],
  ["wrangler.worm-version-observer.live.jsonc", "dpone-release-worm-version-observer"],
  ["wrangler.live.jsonc", "dpone-release-authority-broker"],
]);
const MAINS = new Map([
  ["wrangler.attestation-mutator.live.jsonc", "src/private/fail-closed-worker.ts"],
  ["wrangler.candidate-reader.live.jsonc", "src/private/candidate-reader-worker.ts"],
  ["wrangler.closed-projector.live.jsonc", "src/private/fail-closed-worker.ts"],
  [
    "wrangler.cloudflare-deployment-observer.live.jsonc",
    "src/private/cloudflare-deployment-observer-worker.ts",
  ],
  ["wrangler.controller-run-reader.live.jsonc", "src/private/controller-run-reader-worker.ts"],
  ["wrangler.governance-reader.live.jsonc", "src/private/governance-reader-worker.ts"],
  ["wrangler.pypi-deployment-gate.live.jsonc", "src/private/fail-closed-worker.ts"],
  ["wrangler.pypi-reader.live.jsonc", "src/private/fail-closed-worker.ts"],
  ["wrangler.release-mutator.live.jsonc", "src/private/fail-closed-worker.ts"],
  ["wrangler.runtime-deployment-gate.live.jsonc", "src/private/fail-closed-worker.ts"],
  ["wrangler.tenant-scanner.live.jsonc", "src/private/fail-closed-worker.ts"],
  ["wrangler.worm-mirror.live.jsonc", "src/private/worm-mirror-worker.ts"],
  ["wrangler.worm-version-observer.live.jsonc", "src/private/worm-version-observer-worker.ts"],
  ["wrangler.live.jsonc", "src/index.ts"],
]);

export const MESSAGE = "reviewed one-use lifecycle bootstrap";
export const TAG = "bootstrap-deny-v1";

export function assertLifecycleBootstrapConfig(config, filename) {
  const isIngress = filename === "wrangler.live.jsonc";
  const isWorm = filename === "wrangler.worm-mirror.live.jsonc";
  assert.equal("durable_objects" in config, isIngress || isWorm);
  assert.equal("migrations" in config, isIngress || isWorm);
  if (!isWorm) return;
  assert.deepEqual(config.durable_objects.bindings, [
    { class_name: "CloudflareEvidenceBatch", name: "CLOUDFLARE_EVIDENCE_BATCHES" },
    { class_name: "WormExactObjectEffect", name: "WORM_EXACT_OBJECT_EFFECTS" },
  ]);
  assert.deepEqual(config.migrations, [
    { new_sqlite_classes: ["CloudflareEvidenceBatch"], tag: "v1" },
    { new_sqlite_classes: ["WormExactObjectEffect"], tag: "v2" },
  ]);
}

export function canonicalResponse(value, init = {}) {
  return new globalThis.Response(JSON.stringify(value), {
    ...init,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

export function taggedSha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function inspectedConfig(path) {
  const filename = basename(path);
  const name = NAMES.get(filename);
  const main = MAINS.get(filename);
  assert.ok(name !== undefined && main !== undefined);
  return {
    config: {
      account_id: "0123456789abcdef0123456789abcdef",
      compatibility_date: "2026-08-15",
      compatibility_flags: [],
      main,
      name,
      vars:
        filename === "wrangler.cloudflare-deployment-observer.live.jsonc"
          ? {
              APPROVED_INGRESS_HOSTNAME: "release.example.test",
              APPROVED_INGRESS_ZONE_ID: "fedcba9876543210fedcba9876543210",
              OPERATING_MODE: "live",
            }
          : filename === "wrangler.live.jsonc"
            ? { ADMIN_HOSTNAME: "release.example.test", OPERATING_MODE: "live" }
            : { OPERATING_MODE: "live" },
      version_metadata: { binding: "CF_VERSION_METADATA" },
      ...(filename === "wrangler.live.jsonc"
        ? {
            durable_objects: {
              bindings: [
                { class_name: "ActivationRegistry", name: "ACTIVATION_REGISTRY" },
                { class_name: "AuthReplayLedger", name: "AUTH_REPLAY_LEDGER" },
                {
                  class_name: "GlobalActivatedAuthorityHead",
                  name: "GLOBAL_ACTIVATED_AUTHORITY_HEAD",
                },
                { class_name: "ReleaseLedger", name: "RELEASE_LEDGERS" },
              ],
            },
            migrations: [
              { new_sqlite_classes: ["AuthReplayLedger", "ReleaseLedger"], tag: "v1" },
              { new_sqlite_classes: ["ActivationRegistry"], tag: "v2" },
              { new_sqlite_classes: ["GlobalActivatedAuthorityHead"], tag: "v3" },
            ],
            routes: [{ custom_domain: true, pattern: "release.example.test" }],
            services: [
              { binding: "GOVERNANCE_READER", service: "dpone-release-governance-reader" },
            ],
          }
        : filename === "wrangler.worm-mirror.live.jsonc"
          ? {
              durable_objects: {
                bindings: [
                  {
                    class_name: "CloudflareEvidenceBatch",
                    name: "CLOUDFLARE_EVIDENCE_BATCHES",
                  },
                  {
                    class_name: "WormExactObjectEffect",
                    name: "WORM_EXACT_OBJECT_EFFECTS",
                  },
                ],
              },
              migrations: [
                { new_sqlite_classes: ["CloudflareEvidenceBatch"], tag: "v1" },
                { new_sqlite_classes: ["WormExactObjectEffect"], tag: "v2" },
              ],
            }
          : {}),
    },
    expectedName: name,
    path,
  };
}

export function versionResources(filename) {
  const inspected = inspectedConfig(`/reviewed/${filename}`);
  const config = buildBootstrapWorkerConfig(
    inspected.config,
    filename === "wrangler.live.jsonc"
      ? "ingress"
      : filename === "wrangler.worm-mirror.live.jsonc"
        ? "worm"
        : "private",
    filename === "wrangler.live.jsonc"
      ? "src/bootstrap-ingress.ts"
      : filename === "wrangler.worm-mirror.live.jsonc"
        ? "src/bootstrap-worm.ts"
        : "src/bootstrap-private.ts",
  );
  const durableClasses = (config.migrations ?? []).flatMap(
    (migration) => migration.new_sqlite_classes ?? [],
  );
  const exports = { default: { state: "created", type: "worker" } };
  for (const className of durableClasses) {
    exports[className] = { state: "created", storage: "sqlite", type: "durable-object" };
  }
  return {
    bindings: [
      ...Object.entries(config.vars).map(([name, text]) => ({ name, text, type: "plain_text" })),
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
    ],
    script: {
      etag: `provider-bootstrap-etag-${filename}`,
      handlers: ["fetch"],
      last_deployed_from: "wrangler",
      named_handlers: durableClasses.map((name) => ({ handlers: [], name })),
    },
    script_runtime: {
      compatibility_date: "2026-08-15",
      compatibility_flags: [],
      exports,
      limits: { cpu_ms: 30_000 },
      ...(durableClasses.length > 0 ? { migration_tag: config.migrations.at(-1).tag } : {}),
      usage_model: "standard",
    },
  };
}

export function negativeDependencies(resources) {
  const negativeVersions = new Map();
  const bootstrapConfigs = new Map();
  const orderedFilenames = [...NAMES.keys()];
  let deployIndex = 0;
  return {
    fetch: async (url) => {
      const path = new URL(url).pathname;
      return canonicalResponse(
        path === "/livez"
          ? {
              schema: "dpone.release-broker-bootstrap-liveness.v1",
              status: "bootstrap-deny",
              worker_version_id: negativeVersions.get("wrangler.live.jsonc"),
            }
          : {
              error: {
                code: "BROKER_BOOTSTRAP_DENY",
                request_id: "bootstrap-smoke-deny-0001",
                retryable: false,
              },
            },
        path === "/livez" ? {} : { status: 503 },
      );
    },
    loadLiveWorkerConfig: (path) => inspectedConfig(path),
    readFileSync: (path, encoding) => {
      if (String(path).endsWith(".live.jsonc")) return Buffer.from(`reviewed:${path}`);
      return readFileSync(path, encoding);
    },
    spawnSync: (_executable, arguments_, options) => {
      const providerConfig = arguments_.at(-1);
      if (arguments_[1] === "deploy") {
        const filename = orderedFilenames[deployIndex];
        assert.ok(filename !== undefined);
        deployIndex += 1;
        bootstrapConfigs.set(providerConfig, filename);
        const version = `00000000-0000-4000-8000-${String(negativeVersions.size + 100).padStart(
          12,
          "0",
        )}`;
        negativeVersions.set(filename, version);
        appendFileSync(
          options.env.WRANGLER_OUTPUT_FILE_PATH,
          `${JSON.stringify({
            targets:
              filename === "wrangler.live.jsonc" ? ["release.example.test (custom domain)"] : [],
            type: "deploy",
            version: 1,
            version_id: version,
            worker_name: NAMES.get(filename),
            worker_name_overridden: false,
            worker_tag: `worker-tag-negative-${negativeVersions.size}`,
          })}\n`,
        );
        return { status: 0, stderr: "", stdout: "" };
      }
      const filename = bootstrapConfigs.get(providerConfig);
      assert.ok(filename !== undefined);
      if (arguments_[1] === "deployments") {
        return {
          status: 0,
          stderr: "",
          stdout: JSON.stringify({
            versions: [{ percentage: 100, version_id: negativeVersions.get(filename) }],
          }),
        };
      }
      return {
        status: 0,
        stderr: "",
        stdout: JSON.stringify({
          annotations: { "workers/message": MESSAGE, "workers/tag": TAG },
          id: negativeVersions.get(filename),
          metadata: { created_on: "2026-08-18T20:00:00.000Z" },
          resources: resources(filename),
        }),
      };
    },
  };
}
