import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  MAX_PROVIDER_BYTES,
  PROJECT_ROOT,
  VERSION_ID,
  WRANGLER,
  taggedSha256,
} from "./bootstrap-live-workers-common.mjs";
import {
  canonicalWorkerVersionResourceProjectionBytes,
  projectWorkerVersionResources,
} from "./worker-version-resources.mjs";

export function deployBootstrapWorker(
  worker,
  source,
  bootstrapConfigPath,
  options,
  outputPath,
  execute,
  read,
) {
  if (
    resolve(PROJECT_ROOT, worker.bootstrap_main) !== source ||
    taggedSha256(read(source)) !== worker.bootstrap_main_sha256
  ) {
    throw new Error("bootstrap deploy source differs from the reviewed deny entrypoint");
  }
  const previousEvents = readWranglerEvents(outputPath).length;
  const arguments_ = [
    WRANGLER,
    "deploy",
    source,
    "--strict",
    "--message",
    options.message,
    "--tag",
    options.tag,
  ];
  arguments_.push("--config", bootstrapConfigPath);
  const result = execute(process.execPath, arguments_, {
    encoding: "utf8",
    env: {
      ...process.env,
      CI: "true",
      WRANGLER_LOG_SANITIZE: "true",
      WRANGLER_OUTPUT_FILE_PATH: outputPath,
    },
    maxBuffer: MAX_PROVIDER_BYTES,
  });
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) throw new Error(`bootstrap deployment failed for ${worker.name}`);
  const events = readWranglerEvents(outputPath);
  const fresh = events.slice(previousEvents);
  if (fresh.length !== 1) throw new Error("Wrangler emitted an ambiguous bootstrap event set");
  const event = requireRecord(fresh[0], "Wrangler deploy event");
  requireAllowedKeys(
    event,
    [
      "targets",
      "type",
      "version",
      "version_id",
      "worker_name",
      "worker_name_overridden",
      "worker_tag",
      "wrangler_environment",
    ],
    "Wrangler deploy event",
  );
  if (
    event.type !== "deploy" ||
    event.version !== 1 ||
    event.worker_name !== worker.name ||
    event.worker_name_overridden !== false ||
    !VERSION_ID.test(event.version_id ?? "") ||
    ("wrangler_environment" in event && event.wrangler_environment !== null) ||
    typeof event.worker_tag !== "string" ||
    event.worker_tag.length === 0 ||
    !Array.isArray(event.targets)
  ) {
    throw new Error("Wrangler deploy event identity mismatch");
  }
  const expectedTargets =
    worker.role === "ingress" ? [`${worker.ingress_hostname} (custom domain)`] : [];
  if (JSON.stringify(event.targets) !== JSON.stringify(expectedTargets)) {
    throw new Error("Wrangler deploy targets differ from the reviewed route boundary");
  }
  return {
    bootstrap_main: worker.bootstrap_main,
    bootstrap_main_sha256: worker.bootstrap_main_sha256,
    bootstrap_config: worker.bootstrap_config,
    bootstrap_config_sha256: worker.bootstrap_config_sha256,
    config: worker.config,
    provider_config: bootstrapConfigPath,
    name: worker.name,
    role: worker.role,
    targets: event.targets,
    version_id: event.version_id,
    worker_tag: event.worker_tag,
  };
}

export function requeryDeployment(deployment, options, inspectConfig, execute) {
  const status = executeJson(
    [WRANGLER, "deployments", "status", "--json", "--config", deployment.provider_config],
    execute,
    "deployment status",
  );
  const version = executeJson(
    [
      WRANGLER,
      "versions",
      "view",
      deployment.version_id,
      "--json",
      "--config",
      deployment.provider_config,
    ],
    execute,
    "version view",
  );
  const statusRecord = requireRecord(status.value, "provider deployment status");
  if (
    !Array.isArray(statusRecord.versions) ||
    statusRecord.versions.length !== 1 ||
    statusRecord.versions[0]?.version_id !== deployment.version_id ||
    statusRecord.versions[0]?.percentage !== 100
  ) {
    throw new Error("provider did not deploy exactly one bootstrap version at 100 percent");
  }
  const versionRecord = requireRecord(version.value, "provider version");
  const annotations = requireRecord(versionRecord.annotations, "provider version annotations");
  const metadata = requireRecord(versionRecord.metadata, "provider version metadata");
  if (
    versionRecord.id !== deployment.version_id ||
    annotations["workers/tag"] !== options.tag ||
    annotations["workers/message"] !== options.message ||
    typeof metadata.created_on !== "string"
  ) {
    throw new Error("provider version annotation/identity mismatch");
  }
  const inspected = inspectConfig(deployment.config);
  if (
    inspected === null ||
    typeof inspected !== "object" ||
    inspected.path !== deployment.config ||
    inspected.expectedName !== deployment.name ||
    inspected.config === null ||
    typeof inspected.config !== "object"
  ) {
    throw new Error("bootstrap provider requery config identity mismatch");
  }
  const bindingProjection = projectWorkerVersionResources(
    versionRecord.resources,
    deployment.bootstrap_config,
    [],
  );
  if (bindingProjection.secret_names.length !== 0) {
    throw new Error("bootstrap provider version retained a secret binding");
  }
  return {
    binding_projection: bindingProjection,
    binding_projection_sha256: taggedSha256(
      canonicalWorkerVersionResourceProjectionBytes(bindingProjection),
    ),
    bootstrap_main: deployment.bootstrap_main,
    bootstrap_main_sha256: deployment.bootstrap_main_sha256,
    created_on: metadata.created_on,
    deployment_raw_sha256: status.sha256,
    name: deployment.name,
    targets: deployment.targets,
    version_id: deployment.version_id,
    version_raw_sha256: version.sha256,
    worker_tag: deployment.worker_tag,
  };
}

function executeJson(arguments_, execute, name) {
  const result = execute(process.execPath, arguments_, {
    encoding: "utf8",
    env: { ...process.env, CI: "true", WRANGLER_LOG_SANITIZE: "true" },
    maxBuffer: MAX_PROVIDER_BYTES,
  });
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) throw new Error(`Wrangler ${name} requery failed`);
  const bytes = Buffer.from(result.stdout ?? "", "utf8");
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_PROVIDER_BYTES) {
    throw new Error(`Wrangler ${name} response size invalid`);
  }
  try {
    return { sha256: taggedSha256(bytes), value: JSON.parse(bytes.toString("utf8")) };
  } catch {
    throw new Error(`Wrangler ${name} response is not exact JSON`);
  }
}

function readWranglerEvents(path) {
  const bytes = readFileSync(path);
  if (bytes.byteLength > MAX_PROVIDER_BYTES) throw new Error("Wrangler output file is oversized");
  const source = bytes.toString("utf8");
  if (source === "") return [];
  if (!source.endsWith("\n")) throw new Error("Wrangler output file is not complete JSONL");
  return source
    .slice(0, -1)
    .split("\n")
    .map((line) => JSON.parse(line));
}

function requireAllowedKeys(value, allowed, name) {
  const extras = Object.keys(value).filter((key) => !allowed.includes(key));
  if (extras.length !== 0) throw new Error(`${name} contains unknown fields`);
}

function requireRecord(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value;
}
