import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  BOOTSTRAP_INGRESS_SOURCE,
  BOOTSTRAP_PRIVATE_SOURCE,
  BOOTSTRAP_WORM_SOURCE,
  INGRESS_CONFIG,
  PROJECT_ROOT,
  taggedSha256,
} from "./bootstrap-live-workers-common.mjs";
import { deployBootstrapWorker, requeryDeployment } from "./bootstrap-live-workers-deploy.mjs";
import {
  assertPlanBytesUnchanged,
  buildPlan,
  materializeBootstrapConfig,
} from "./bootstrap-live-workers-plan.mjs";
import { smokeBootstrap } from "./bootstrap-live-workers-smoke.mjs";
import { loadLiveWorkerConfig } from "./live-worker-config.mjs";
import { assertProviderMutationReleased } from "./provider-mutation-hold.mjs";

/**
 * Apply the sole permitted blank-account lifecycle deployment.
 *
 * Every uploaded entrypoint is credential-free and fail-closed; no secret is
 * uploaded or retained in a bootstrap version. This command intentionally
 * cannot activate the broker or create a final shared HMAC authority. Final
 * code and the first shared key are uploaded later by the paired immutable-
 * version ceremony, after this bootstrap version has been re-queried.
 */
export async function main() {
  assertProviderMutationReleased("bootstrap-live-apply");
  const arguments_ = Object.freeze(process.argv.slice(2));
  const options = parseArguments(arguments_);
  if (!options.apply) return runBootstrapDryValidation();
  return runBootstrapEngine(options, {
    fetch,
    loadLiveWorkerConfig,
    readFileSync,
    spawnSync,
    writeFileSync,
    writeOutput: (value) => process.stdout.write(value),
  });
}

/** Explicit effect-port engine; production adapters are bound only by the guarded main function. */
export async function runBootstrapEngine(options, dependencies) {
  assertProviderMutationReleased("bootstrap-live-apply");
  const inspectConfig = requirePort(dependencies, "loadLiveWorkerConfig");
  const execute = requirePort(dependencies, "spawnSync");
  const fetchImpl = requirePort(dependencies, "fetch");
  const read = requirePort(dependencies, "readFileSync");
  const writeOutput = requirePort(dependencies, "writeOutput");
  const writeReport = requirePort(dependencies, "writeFileSync");
  const plan = buildPlan();

  assertReportTarget(options.report);
  assertPlanBytesUnchanged(plan);
  assertResolvedLiveNetworkSurface(
    inspectConfig(resolve(PROJECT_ROOT, INGRESS_CONFIG)),
    inspectConfig(resolve(PROJECT_ROOT, "wrangler.cloudflare-deployment-observer.live.jsonc")),
  );

  const temporaryDirectory = mkdtempSync(join(tmpdir(), "dpone-bootstrap-"));
  const outputPath = join(temporaryDirectory, "wrangler-output.jsonl");
  let completedReport;
  try {
    writeFileSync(outputPath, "", { flag: "wx", mode: 0o600 });
    const deployments = [];
    for (const [index, worker] of plan.workers
      .filter((item) => item.role !== "ingress")
      .entries()) {
      const bootstrapConfigPath = materializeBootstrapConfig(worker, temporaryDirectory, index);
      deployments.push(
        deployBootstrapWorker(
          worker,
          worker.role === "worm" ? BOOTSTRAP_WORM_SOURCE : BOOTSTRAP_PRIVATE_SOURCE,
          bootstrapConfigPath,
          options,
          outputPath,
          execute,
          read,
        ),
      );
    }
    const ingress = plan.workers.find((item) => item.role === "ingress");
    if (ingress === undefined) throw new Error("bootstrap ingress plan is incomplete");
    const ingressBootstrapConfigPath = materializeBootstrapConfig(
      ingress,
      temporaryDirectory,
      plan.workers.length,
    );
    deployments.push(
      deployBootstrapWorker(
        ingress,
        BOOTSTRAP_INGRESS_SOURCE,
        ingressBootstrapConfigPath,
        options,
        outputPath,
        execute,
        read,
      ),
    );

    const providerObservations = deployments.map((deployment) =>
      requeryDeployment(deployment, options, inspectConfig, execute),
    );
    const ingressDeployment = deployments.at(-1);
    if (ingressDeployment === undefined) throw new Error("bootstrap ingress was not deployed");
    const smoke = await smokeBootstrap(
      plan.ingress_hostname,
      ingressDeployment.version_id,
      fetchImpl,
    );
    completedReport = {
      applied: true,
      bootstrap_secret_absent: true,
      plan,
      provider_observations: providerObservations,
      schema: "dpone.release-broker-bootstrap-report.v2",
      schema_version: 2,
      smoke,
      version_message: options.message,
      version_tag: options.tag,
    };
  } finally {
    rmSync(temporaryDirectory, { force: true, recursive: true });
  }
  if (completedReport === undefined) throw new Error("bootstrap did not produce a report");

  const reportBytes = Buffer.from(`${JSON.stringify(completedReport)}\n`, "utf8");
  writeReport(options.report, reportBytes, { flag: "wx", mode: 0o600 });
  const output = `${JSON.stringify({
    applied: true,
    report: options.report,
    report_sha256: taggedSha256(reportBytes),
  })}\n`;
  writeOutput(output);
  return output;
}

/** Perform the provider-free bootstrap plan validation used by the default CLI mode. */
function runBootstrapDryValidation() {
  const output = `${JSON.stringify({
    applied: false,
    plan: buildPlan(),
  })}\n`;
  process.stdout.write(output);
  return output;
}

function requirePort(dependencies, name) {
  const value = dependencies?.[name];
  if (typeof value !== "function") throw new Error(`bootstrap effect port missing: ${name}`);
  return value;
}

export function parseArguments(arguments_) {
  assertProviderMutationReleased("bootstrap-live-apply");
  const values = new Map();
  let apply = false;
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--apply") {
      if (apply) throw new Error(usage());
      apply = true;
      continue;
    }
    if (!["--report", "--version-message", "--version-tag"].includes(argument)) {
      throw new Error(usage());
    }
    const value = arguments_[index + 1];
    if (value === undefined || value.startsWith("--") || values.has(argument)) {
      throw new Error(usage());
    }
    values.set(argument, value);
    index += 1;
  }
  const message = values.get("--version-message");
  const report = values.get("--report");
  const tag = values.get("--version-tag");
  if (
    message === undefined ||
    report === undefined ||
    tag === undefined ||
    !/^[ -~]{8,128}$/u.test(message) ||
    !/^[a-z0-9][a-z0-9._-]{7,63}$/u.test(tag)
  ) {
    throw new Error(usage());
  }
  return { apply, message, report: resolve(report), tag };
}

/** Reject syntactically valid placeholders before the first provider effect. */
export function assertResolvedLiveNetworkSurface(ingress, observer) {
  assertProviderMutationReleased("bootstrap-live-apply");
  const ingressConfig = ingress?.config;
  const observerConfig = observer?.config;
  const routeHostname = ingressConfig?.routes?.[0]?.pattern;
  const adminHostname = ingressConfig?.vars?.ADMIN_HOSTNAME;
  const observerHostname = observerConfig?.vars?.APPROVED_INGRESS_HOSTNAME;
  const zoneId = observerConfig?.vars?.APPROVED_INGRESS_ZONE_ID;
  const accountId = ingressConfig?.account_id;
  if (
    typeof routeHostname !== "string" ||
    routeHostname.endsWith(".invalid") ||
    routeHostname !== adminHostname ||
    routeHostname !== observerHostname ||
    typeof accountId !== "string" ||
    !/^[0-9a-f]{32}$/u.test(accountId) ||
    /^0{32}$/u.test(accountId) ||
    accountId !== observerConfig?.account_id ||
    typeof zoneId !== "string" ||
    !/^[0-9a-f]{32}$/u.test(zoneId) ||
    /^0{32}$/u.test(zoneId)
  ) {
    throw new Error("bootstrap apply requires one resolved reviewed ingress hostname and zone");
  }
}

function assertReportTarget(path) {
  if (existsSync(path))
    throw new Error("bootstrap report path already exists; ceremony is one-use");
  const parent = lstatSync(dirname(path));
  if (!parent.isDirectory() || parent.isSymbolicLink()) {
    throw new Error("bootstrap report parent must be a real directory");
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}

function usage() {
  return (
    "usage: pnpm bootstrap:live -- --report <new-report.json> " +
    "--version-tag <reviewed-tag> --version-message <reviewed-message> [--apply]"
  );
}
