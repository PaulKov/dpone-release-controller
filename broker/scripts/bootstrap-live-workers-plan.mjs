import { writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";

import {
  assertBootstrapWorkerConfig,
  buildBootstrapWorkerConfig,
  canonicalBootstrapWorkerConfigBytes,
} from "./bootstrap-worker-config.mjs";
import {
  BOOTSTRAP_INGRESS_SOURCE,
  BOOTSTRAP_PRIVATE_SOURCE,
  BOOTSTRAP_WORM_SOURCE,
  EXPECTED_DURABLE_EXPORTS,
  EXPECTED_WORM_DURABLE_EXPORTS,
  FINAL_INGRESS_SOURCE,
  FINAL_WORM_SOURCE,
  INGRESS_CONFIG,
  PRIVATE_CONFIGS,
  PROJECT_ROOT,
  taggedSha256,
} from "./bootstrap-live-workers-common.mjs";

export function buildPlan(inspectConfig, read) {
  const filenames = [...PRIVATE_CONFIGS, INGRESS_CONFIG];
  const workers = filenames.map((filename) => {
    const path = resolve(PROJECT_ROOT, filename);
    const inspected = inspectConfig(path);
    if (
      inspected === null ||
      typeof inspected !== "object" ||
      inspected.path !== path ||
      inspected.config === null ||
      typeof inspected.config !== "object" ||
      inspected.expectedName !== inspected.config.name ||
      "exports" in inspected.config
    ) {
      throw new Error("bootstrap requires one exact reviewed lifecycle-migration live config");
    }
    const worm = filename === "wrangler.worm-mirror.live.jsonc";
    const bootstrapMain = relative(
      PROJECT_ROOT,
      filename === INGRESS_CONFIG
        ? BOOTSTRAP_INGRESS_SOURCE
        : worm
          ? BOOTSTRAP_WORM_SOURCE
          : BOOTSTRAP_PRIVATE_SOURCE,
    );
    const role = filename === INGRESS_CONFIG ? "ingress" : worm ? "worm" : "private";
    const bootstrapConfig = buildBootstrapWorkerConfig(inspected.config, role, bootstrapMain);
    return {
      bootstrap_config: bootstrapConfig,
      bootstrap_config_sha256: taggedSha256(canonicalBootstrapWorkerConfigBytes(bootstrapConfig)),
      bootstrap_main: bootstrapMain,
      bootstrap_main_sha256: taggedSha256(
        read(
          filename === INGRESS_CONFIG
            ? BOOTSTRAP_INGRESS_SOURCE
            : worm
              ? BOOTSTRAP_WORM_SOURCE
              : BOOTSTRAP_PRIVATE_SOURCE,
        ),
      ),
      config: path,
      config_sha256: taggedSha256(read(path)),
      final_main: inspected.config.main,
      final_main_sha256: taggedSha256(read(resolve(PROJECT_ROOT, inspected.config.main))),
      name: inspected.expectedName,
      role,
    };
  });
  requireDurableExportParity(read);
  const ingress = workers.at(-1);
  const inspectedIngress = inspectConfig(resolve(PROJECT_ROOT, INGRESS_CONFIG));
  const hostname = inspectedIngress.config.routes?.[0]?.pattern;
  if (
    ingress?.role !== "ingress" ||
    typeof hostname !== "string" ||
    inspectedIngress.config.main !== "src/index.ts"
  ) {
    throw new Error("bootstrap ingress topology mismatch");
  }
  ingress.ingress_hostname = hostname;
  return {
    bootstrap_ingress_source_sha256: taggedSha256(read(BOOTSTRAP_INGRESS_SOURCE)),
    bootstrap_private_source_sha256: taggedSha256(read(BOOTSTRAP_PRIVATE_SOURCE)),
    bootstrap_worm_source_sha256: taggedSha256(read(BOOTSTRAP_WORM_SOURCE)),
    ingress_hostname: hostname,
    lifecycle_migrations: lifecycleMigrationProjection(workers),
    workers,
  };
}

export function materializeBootstrapConfig(worker, temporaryDirectory, index) {
  assertBootstrapWorkerConfig(worker.bootstrap_config, worker.role, worker.bootstrap_main);
  const bytes = canonicalBootstrapWorkerConfigBytes(worker.bootstrap_config);
  if (taggedSha256(bytes) !== worker.bootstrap_config_sha256) {
    throw new Error("bootstrap config differs from the reviewed binding-free plan");
  }
  const path = join(temporaryDirectory, `${String(index).padStart(2, "0")}-bootstrap.json`);
  writeFileSync(path, bytes, { flag: "wx", mode: 0o600 });
  return path;
}

export function assertPlanBytesUnchanged(plan, read) {
  for (const worker of plan.workers) {
    if (
      taggedSha256(read(worker.config)) !== worker.config_sha256 ||
      taggedSha256(canonicalBootstrapWorkerConfigBytes(worker.bootstrap_config)) !==
        worker.bootstrap_config_sha256 ||
      taggedSha256(read(resolve(PROJECT_ROOT, worker.final_main))) !== worker.final_main_sha256 ||
      taggedSha256(read(resolve(PROJECT_ROOT, worker.bootstrap_main))) !==
        worker.bootstrap_main_sha256
    ) {
      throw new Error("bootstrap reviewed config/source bytes changed before the first effect");
    }
  }
}

function requireDurableExportParity(read) {
  const finalExports = namedExports(read(FINAL_INGRESS_SOURCE, "utf8"));
  const bootstrapExports = namedExports(read(BOOTSTRAP_INGRESS_SOURCE, "utf8"));
  const finalWormExports = namedExports(read(FINAL_WORM_SOURCE, "utf8"));
  const bootstrapWormExports = namedExports(read(BOOTSTRAP_WORM_SOURCE, "utf8"));
  if (
    JSON.stringify(finalExports) !== JSON.stringify(EXPECTED_DURABLE_EXPORTS) ||
    JSON.stringify(bootstrapExports) !== JSON.stringify(EXPECTED_DURABLE_EXPORTS) ||
    JSON.stringify(finalWormExports) !== JSON.stringify(EXPECTED_WORM_DURABLE_EXPORTS) ||
    JSON.stringify(bootstrapWormExports) !== JSON.stringify(EXPECTED_WORM_DURABLE_EXPORTS)
  ) {
    throw new Error("bootstrap/final Durable Object export parity mismatch");
  }
}

function lifecycleMigrationProjection(workers) {
  return workers
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
    }));
}

/** Collect every explicit value export block before comparing Durable Object parity. */
export function namedExports(source) {
  const text = Buffer.isBuffer(source) ? source.toString("utf8") : source;
  const matches = [...text.matchAll(/export\s*\{([^}]+)\}/gu)];
  return matches
    .flatMap((match) => (match[1] === undefined ? [] : match[1].split(",")))
    .map((value) =>
      value
        .trim()
        .split(/\s+as\s+/u)
        .at(-1),
    )
    .filter((value) => value !== undefined)
    .sort();
}
