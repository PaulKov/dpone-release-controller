import { strict as assert } from "node:assert";
import { appendFileSync, lstatSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  assertResolvedLiveNetworkSurface,
  boundedJsonResponse,
} from "./bootstrap-live-workers.mjs";
import { namedExports } from "./bootstrap-live-workers-plan.mjs";
import { buildBootstrapWorkerConfig } from "./bootstrap-worker-config.mjs";
import { runBootstrapForTest } from "./test-bootstrap-live-workers-engine.mjs";
import {
  MESSAGE,
  NAMES,
  TAG,
  assertLifecycleBootstrapConfig,
  canonicalResponse,
  inspectedConfig,
  negativeDependencies,
  taggedSha256,
  versionResources,
} from "./test-bootstrap-live-workers-fixtures.mjs";
import { projectWorkerVersionResources } from "./worker-version-resources.mjs";
const temporaryDirectory = mkdtempSync(join(tmpdir(), "dpone-bootstrap-test-"));
const reportPath = join(temporaryDirectory, "bootstrap-report.json");
const calls = [];
const versions = new Map();
const bootstrapConfigs = new Map();
const orderedFilenames = [...NAMES.keys()];
let deployIndex = 0;
let output = "";

try {
  assert.deepEqual(
    namedExports(Buffer.from("export { First }\nexport { Second as Renamed }\n", "utf8")),
    ["First", "Renamed"],
  );

  const unresolvedIngress = inspectedConfig("/reviewed/wrangler.live.jsonc");
  unresolvedIngress.config.routes[0].pattern = "release-authority.invalid";
  unresolvedIngress.config.vars.ADMIN_HOSTNAME = "release-authority.invalid";
  const unresolvedObserver = inspectedConfig(
    "/reviewed/wrangler.cloudflare-deployment-observer.live.jsonc",
  );
  unresolvedObserver.config.vars.APPROVED_INGRESS_HOSTNAME = "release-authority.invalid";
  unresolvedObserver.config.vars.APPROVED_INGRESS_ZONE_ID = "0".repeat(32);
  assert.throws(
    () => assertResolvedLiveNetworkSurface(unresolvedIngress, unresolvedObserver),
    /resolved reviewed ingress hostname and zone/u,
  );

  const zeroAccountIngress = inspectedConfig("/reviewed/wrangler.live.jsonc");
  const zeroAccountObserver = inspectedConfig(
    "/reviewed/wrangler.cloudflare-deployment-observer.live.jsonc",
  );
  zeroAccountIngress.config.account_id = "0".repeat(32);
  zeroAccountObserver.config.account_id = "0".repeat(32);
  assert.throws(
    () => assertResolvedLiveNetworkSurface(zeroAccountIngress, zeroAccountObserver),
    /resolved reviewed ingress hostname and zone/u,
  );

  await runBootstrapForTest(
    ["--report", reportPath, "--version-tag", TAG, "--version-message", MESSAGE, "--apply"],
    {
      fetch: async (url, init = {}) => {
        const path = new URL(url).pathname;
        if (path === "/livez") {
          return canonicalResponse({
            schema: "dpone.release-broker-bootstrap-liveness.v1",
            status: "bootstrap-deny",
            worker_version_id: versions.get("wrangler.live.jsonc"),
          });
        }
        assert.equal(init.redirect, "error");
        return canonicalResponse(
          {
            error: {
              code: "BROKER_BOOTSTRAP_DENY",
              request_id: "bootstrap-smoke-deny-0001",
              retryable: false,
            },
          },
          { status: 503 },
        );
      },
      loadLiveWorkerConfig: (path) => inspectedConfig(path),
      readFileSync: (path, encoding) => {
        if (String(path).endsWith(".live.jsonc")) return Buffer.from(`reviewed:${path}`);
        return readFileSync(path, encoding);
      },
      spawnSync: (executable, arguments_, options) => {
        calls.push({ arguments_, executable, options });
        const providerConfig = arguments_.at(-1);
        if (arguments_[1] === "deploy") {
          const filename = orderedFilenames[deployIndex];
          assert.ok(filename !== undefined);
          deployIndex += 1;
          bootstrapConfigs.set(providerConfig, filename);
          const bootstrapConfig = JSON.parse(readFileSync(providerConfig, "utf8"));
          assert.equal(lstatSync(providerConfig).mode & 0o777, 0o600);
          assert.deepEqual(bootstrapConfig.vars, { OPERATING_MODE: "provisioning" });
          assert.equal("services" in bootstrapConfig, false);
          assert.equal("route" in bootstrapConfig, false);
          assert.equal("routes" in bootstrapConfig, filename === "wrangler.live.jsonc");
          const index = versions.size;
          const version = `00000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`;
          versions.set(filename, version);
          const isIngress = filename === "wrangler.live.jsonc";
          const isWorm = filename === "wrangler.worm-mirror.live.jsonc";
          assertLifecycleBootstrapConfig(bootstrapConfig, filename);
          assert.equal(
            arguments_[2].endsWith(
              isIngress
                ? "src/bootstrap-ingress.ts"
                : isWorm
                  ? "src/bootstrap-worm.ts"
                  : "src/bootstrap-private.ts",
            ),
            true,
          );
          assert.equal(arguments_.includes("--secrets-file"), false);
          appendFileSync(
            options.env.WRANGLER_OUTPUT_FILE_PATH,
            `${JSON.stringify({
              targets: isIngress ? ["release.example.test (custom domain)"] : [],
              type: "deploy",
              version: 1,
              version_id: version,
              worker_name: NAMES.get(filename),
              worker_name_overridden: false,
              worker_tag: `worker-tag-${index}`,
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
              created_on: "2026-08-18T20:00:00.000Z",
              versions: [{ percentage: 100, version_id: versions.get(filename) }],
            }),
          };
        }
        assert.equal(arguments_[1], "versions");
        return {
          status: 0,
          stderr: "",
          stdout: JSON.stringify({
            annotations: { "workers/message": MESSAGE, "workers/tag": TAG },
            id: versions.get(filename),
            metadata: { created_on: "2026-08-18T20:00:00.000Z" },
            resources: versionResources(filename),
          }),
        };
      },
      writeOutput: (value) => {
        output += value;
      },
    },
  );

  assert.equal(calls.filter(({ arguments_ }) => arguments_[1] === "deploy").length, NAMES.size);
  assert.equal(
    calls.filter(({ arguments_ }) => arguments_[1] === "deployments").length,
    NAMES.size,
  );
  assert.equal(calls.filter(({ arguments_ }) => arguments_[1] === "versions").length, NAMES.size);
  assert.equal(lstatSync(reportPath).mode & 0o777, 0o600);
  const reportBytes = readFileSync(reportPath);
  assert.equal(reportBytes.includes(Buffer.from("WORM_RPC_AUTH_KEY")), false);
  const report = JSON.parse(reportBytes.toString("utf8"));
  assert.equal(report.schema, "dpone.release-broker-bootstrap-report.v2");
  assert.equal(report.schema_version, 2);
  assert.equal(report.bootstrap_secret_absent, true);
  assert.deepEqual(
    report.plan.lifecycle_migrations.map(({ name, role }) => ({ name, role })),
    [
      { name: "dpone-release-worm-mirror", role: "worm" },
      { name: "dpone-release-authority-broker", role: "ingress" },
    ],
  );
  assert.equal(
    report.plan.lifecycle_migrations.every(
      (lifecycle) =>
        lifecycle.bootstrap_config_sha256 ===
        report.plan.workers.find(({ name }) => name === lifecycle.name)?.bootstrap_config_sha256,
    ),
    true,
  );
  assert.equal(
    report.plan.workers.every(
      (worker) =>
        !("services" in worker.bootstrap_config) &&
        JSON.stringify(worker.bootstrap_config.vars) ===
          JSON.stringify({ OPERATING_MODE: "provisioning" }),
    ),
    true,
  );
  assert.equal(report.provider_observations.length, NAMES.size);
  for (const observation of report.provider_observations) {
    const filename = [...NAMES.entries()].find(([, name]) => name === observation.name)?.[0];
    assert.ok(filename !== undefined);
    const planWorker = report.plan.workers.find((worker) => worker.name === observation.name);
    assert.ok(planWorker !== undefined);
    const inspected = inspectedConfig(`/reviewed/${filename}`);
    const expectedProjection = projectWorkerVersionResources(
      versionResources(filename),
      buildBootstrapWorkerConfig(
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
      ),
      [],
    );
    assert.deepEqual(observation.binding_projection, expectedProjection);
    assert.deepEqual(observation.binding_projection.secret_names, []);
    assert.deepEqual(observation.binding_projection.script_handlers, ["fetch"]);
    assert.equal(observation.binding_projection.compatibility_date, "2026-08-15");
    assert.deepEqual(observation.binding_projection.compatibility_flags, []);
    assert.equal(
      observation.bootstrap_main,
      observation.name === "dpone-release-authority-broker"
        ? "src/bootstrap-ingress.ts"
        : observation.name === "dpone-release-worm-mirror"
          ? "src/bootstrap-worm.ts"
          : "src/bootstrap-private.ts",
    );
    assert.equal(observation.binding_projection.script_etag, `provider-bootstrap-etag-${filename}`);
    assert.equal(observation.bootstrap_main_sha256, planWorker.bootstrap_main_sha256);
    assert.equal(
      planWorker.bootstrap_main_sha256,
      taggedSha256(readFileSync(new URL(`../${planWorker.bootstrap_main}`, import.meta.url))),
    );
    assert.equal(
      planWorker.config_sha256,
      taggedSha256(Buffer.from(`reviewed:${planWorker.config}`)),
    );
    assert.equal(
      planWorker.final_main_sha256,
      taggedSha256(readFileSync(new URL(`../${planWorker.final_main}`, import.meta.url))),
    );
  }
  assert.equal(report.smoke.liveness_version_id, versions.get("wrangler.live.jsonc"));
  assert.match(JSON.parse(output).report_sha256, /^sha256:[0-9a-f]{64}$/u);

  await assert.rejects(
    () =>
      runBootstrapForTest(
        ["--report", reportPath, "--version-tag", TAG, "--version-message", MESSAGE, "--apply"],
        {
          loadLiveWorkerConfig: (path) => inspectedConfig(path),
          readFileSync: (path, encoding) => {
            if (String(path).endsWith(".live.jsonc")) return Buffer.from(`reviewed:${path}`);
            return readFileSync(path, encoding);
          },
        },
      ),
    /ceremony is one-use/u,
  );

  let overflowCanceled = false;
  const overflow = new globalThis.Response(
    new globalThis.ReadableStream({
      cancel() {
        overflowCanceled = true;
      },
      start(controller) {
        controller.enqueue(new Uint8Array(65));
      },
    }),
    { headers: { "content-type": "application/json; charset=utf-8" } },
  );
  await assert.rejects(() => boundedJsonResponse(overflow, 64), /response size invalid/u);
  assert.equal(overflowCanceled, true);

  let stalledCanceled = false;
  const stalled = new globalThis.Response(
    new globalThis.ReadableStream({
      cancel() {
        stalledCanceled = true;
      },
    }),
    { headers: { "content-type": "application/json; charset=utf-8" } },
  );
  await assert.rejects(
    () => boundedJsonResponse(stalled, 64, { idleTimeoutMs: 1, totalTimeoutMs: 10 }),
    /stalled/u,
  );
  assert.equal(stalledCanceled, true);

  const retainedSecret = versionResources("wrangler.live.jsonc");
  retainedSecret.bindings.push({ name: "WORM_RPC_AUTH_KEY", type: "secret_text" });
  await assert.rejects(
    () =>
      runBootstrapForTest(
        [
          "--report",
          join(temporaryDirectory, "retained-secret-report.json"),
          "--version-tag",
          TAG,
          "--version-message",
          MESSAGE,
          "--apply",
        ],
        negativeDependencies(() => retainedSecret),
      ),
    /projection differs from reviewed config\/secrets/u,
  );

  let ingressBootstrapReads = 0;
  let driftEffects = 0;
  await assert.rejects(
    () =>
      runBootstrapForTest(
        [
          "--report",
          join(temporaryDirectory, "source-drift-report.json"),
          "--version-tag",
          TAG,
          "--version-message",
          MESSAGE,
          "--apply",
        ],
        {
          loadLiveWorkerConfig: (path) => inspectedConfig(path),
          readFileSync: (path, encoding) => {
            if (String(path).endsWith(".live.jsonc")) return Buffer.from(`reviewed:${path}`);
            if (String(path).endsWith("src/bootstrap-ingress.ts")) {
              ingressBootstrapReads += 1;
              if (ingressBootstrapReads >= 4) {
                return readFileSync(new URL("../src/index.ts", import.meta.url), encoding);
              }
            }
            return readFileSync(path, encoding);
          },
          spawnSync: () => {
            driftEffects += 1;
            throw new Error("provider effect must not start after source drift");
          },
        },
      ),
    /reviewed config\/source bytes changed before the first effect/u,
  );
  assert.equal(driftEffects, 0);
} finally {
  rmSync(temporaryDirectory, { force: true, recursive: true });
}
