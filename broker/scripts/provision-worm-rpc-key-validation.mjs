import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { TextDecoder } from "node:util";

import {
  buildBootstrapWorkerConfig,
  canonicalBootstrapWorkerConfigBytes,
} from "./bootstrap-worker-config.mjs";
import {
  canonicalWorkerVersionResourceProjectionBytes,
  validateWorkerVersionResourceProjection,
} from "./worker-version-resources.mjs";
import { INGRESS_CONFIG, PRIVATE_CONFIGS } from "./bootstrap-live-workers-common.mjs";
import { LIVE_WORKERS } from "./live-worker-topology.mjs";
import { MAX_INPUT_BYTES, PROJECT_ROOT, VERSION } from "./provision-worm-rpc-key-constants.mjs";
import { taggedSha256 } from "./provision-worm-rpc-key-crypto.mjs";
import { readPrivateFile } from "./provision-worm-rpc-key-inputs.mjs";
import { assertProviderMutationReleased } from "./provider-mutation-hold.mjs";

export function validateInspectedConfig(inspected, expectedName) {
  assertProviderMutationReleased("worm-authority-apply");
  if (
    inspected === null ||
    typeof inspected !== "object" ||
    inspected.expectedName !== expectedName ||
    typeof inspected.path !== "string" ||
    inspected.config === null ||
    typeof inspected.config !== "object"
  ) {
    throw new Error("reviewed live Worker config inspection failed");
  }
}

export function validateBootstrapProvenance(path, ingress, observer, cloudflareObserver, worm) {
  assertProviderMutationReleased("worm-authority-apply");
  if (path === null) throw new Error("applied authority ceremony requires bootstrap provenance");
  const bytes = readPrivateFile(path, 64, MAX_INPUT_BYTES, "bootstrap report");
  let report;
  try {
    report = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("bootstrap report is not canonical UTF-8 JSON");
  }
  if (
    report === null ||
    typeof report !== "object" ||
    Array.isArray(report) ||
    `${JSON.stringify(report)}\n` !== bytes.toString("utf8") ||
    report.schema !== "dpone.release-broker-bootstrap-report.v2" ||
    report.schema_version !== 2 ||
    report.applied !== true ||
    report.bootstrap_secret_absent !== true ||
    !Array.isArray(report.plan?.workers) ||
    !hasExactLifecycleMigrationProjection(report.plan) ||
    !Array.isArray(report.provider_observations)
  ) {
    throw new Error("bootstrap report authority contract mismatch");
  }
  const plannedNames = report.plan.workers.map((item) => item?.name).sort();
  const observedNames = report.provider_observations.map((item) => item?.name).sort();
  const expectedWorkers = [...PRIVATE_CONFIGS, INGRESS_CONFIG].map((filename) => ({
    name: LIVE_WORKERS[filename].name,
    role:
      filename === INGRESS_CONFIG
        ? "ingress"
        : filename === "wrangler.worm-mirror.live.jsonc"
          ? "worm"
          : "private",
  }));
  const expectedNames = expectedWorkers.map(({ name }) => name).sort();
  if (
    JSON.stringify(report.plan.workers.map((item) => ({ name: item?.name, role: item?.role }))) !==
      JSON.stringify(expectedWorkers) ||
    JSON.stringify(report.provider_observations.map((item) => item?.name)) !==
      JSON.stringify(expectedWorkers.map(({ name }) => name)) ||
    new Set(plannedNames).size !== plannedNames.length ||
    new Set(observedNames).size !== observedNames.length ||
    JSON.stringify(plannedNames) !== JSON.stringify(expectedNames) ||
    JSON.stringify(observedNames) !== JSON.stringify(expectedNames) ||
    JSON.stringify(plannedNames) !== JSON.stringify(observedNames) ||
    report.provider_observations.some(
      (item) =>
        item?.binding_projection?.schema !==
          "dpone.cloudflare-worker-version-binding-projection.v1" ||
        JSON.stringify(item.binding_projection.secret_names) !== "[]" ||
        item.binding_projection_sha256 !==
          taggedSha256(canonicalWorkerVersionResourceProjectionBytes(item.binding_projection)),
    )
  ) {
    throw new Error("bootstrap report does not prove exact credential-free provider versions");
  }
  return {
    bootstrap_report_sha256: taggedSha256(bytes),
    cloudflare_observer: validateBootstrapWorkerProjection(report, cloudflareObserver),
    ingress: validateBootstrapWorkerProjection(report, ingress),
    observer: validateBootstrapWorkerProjection(report, observer),
    worm: validateBootstrapWorkerProjection(report, worm),
  };
}

function hasExactLifecycleMigrationProjection(plan) {
  const lifecycleWorkers = plan.workers.filter(
    (worker) => worker?.role === "ingress" || worker?.role === "worm",
  );
  if (lifecycleWorkers.length !== 2 || !Array.isArray(plan.lifecycle_migrations)) return false;
  const expected = lifecycleWorkers.map((worker) => ({
    bootstrap_config_sha256: worker.bootstrap_config_sha256,
    durable_objects: (worker.bootstrap_config?.durable_objects?.bindings ?? []).map((binding) => ({
      binding: binding.name,
      class_name: binding.class_name,
    })),
    migrations: (worker.bootstrap_config?.migrations ?? []).map((migration) => ({
      new_sqlite_classes: [...(migration.new_sqlite_classes ?? [])],
      tag: migration.tag,
    })),
    name: worker.name,
    role: worker.role,
  }));
  return JSON.stringify(plan.lifecycle_migrations) === JSON.stringify(expected);
}

function validateBootstrapWorkerProjection(report, inspected) {
  const matches = report.plan.workers.filter((item) => item?.name === inspected.expectedName);
  const observations = report.provider_observations.filter(
    (item) => item?.name === inspected.expectedName,
  );
  if (matches.length !== 1 || observations.length !== 1) {
    throw new Error("bootstrap report Worker provenance is ambiguous");
  }
  const projected = matches[0];
  const observation = observations[0];
  const main = inspected.config.main;
  if (typeof main !== "string") throw new Error("reviewed live Worker main is invalid");
  const worm = main === "src/private/worm-mirror-worker.ts";
  const bootstrapMain =
    main === "src/index.ts"
      ? "src/bootstrap-ingress.ts"
      : worm
        ? "src/bootstrap-worm.ts"
        : "src/bootstrap-private.ts";
  const bootstrapConfig = buildBootstrapWorkerConfig(
    inspected.config,
    main === "src/index.ts" ? "ingress" : worm ? "worm" : "private",
    bootstrapMain,
  );
  const configSha256 = taggedSha256(readFileSync(inspected.path));
  const mainSha256 = taggedSha256(readFileSync(resolve(PROJECT_ROOT, main)));
  const bootstrapMainSha256 = taggedSha256(readFileSync(resolve(PROJECT_ROOT, bootstrapMain)));
  const bindingProjection = validateWorkerVersionResourceProjection(
    observation.binding_projection,
    bootstrapConfig,
    [],
  );
  if (
    projected.config !== inspected.path ||
    projected.config_sha256 !== configSha256 ||
    projected.final_main !== main ||
    projected.final_main_sha256 !== mainSha256 ||
    projected.bootstrap_main !== bootstrapMain ||
    projected.bootstrap_main_sha256 !== bootstrapMainSha256 ||
    projected.bootstrap_config_sha256 !==
      taggedSha256(canonicalBootstrapWorkerConfigBytes(bootstrapConfig)) ||
    JSON.stringify(projected.bootstrap_config) !== JSON.stringify(bootstrapConfig) ||
    observation.bootstrap_main !== bootstrapMain ||
    observation.bootstrap_main_sha256 !== bootstrapMainSha256 ||
    observation.binding_projection_sha256 !==
      taggedSha256(canonicalWorkerVersionResourceProjectionBytes(bindingProjection)) ||
    typeof observation.version_id !== "string" ||
    !VERSION.test(observation.version_id)
  ) {
    throw new Error("current final Worker bytes differ from bootstrap provenance");
  }
  return {
    bootstrap_version_id: observation.version_id,
    bootstrap_main: bootstrapMain,
    bootstrap_main_sha256: bootstrapMainSha256,
    bootstrap_version_binding_projection_sha256: observation.binding_projection_sha256,
    config_sha256: configSha256,
    final_main: main,
    final_main_sha256: mainSha256,
    service_name: inspected.expectedName,
  };
}
