import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { main as deployVersion } from "./deploy-version.mjs";
import { LIVE_WORKER_IDENTITIES, validateLiveWorkerConfig } from "./live-worker-config.mjs";
import { PROVIDER_MUTATION_HOLD_CODE } from "./provider-mutation-hold.mjs";
import {
  CANDIDATE,
  LIVE_CONFIG,
  PAIRED_AUTHORITY_CONFIGS,
  STABLE,
  liveConfig,
  privateConfig,
} from "./test-deployment-tooling-fixtures.mjs";
import {
  simulateVersionDeployment,
  simulateVersionUpload,
} from "./test-provider-trace-simulation.mjs";
import { main as uploadVersion } from "./upload-version.mjs";

for (const filename of ["deploy-version.mjs", "upload-version.mjs"]) {
  const source = readFileSync(fileURLToPath(new URL(filename, import.meta.url)), "utf8");
  const holdOffset = source.indexOf("assertProviderMutationReleased(");
  const optionOffset = source.indexOf("process.argv.slice(2)");
  assert.ok(
    holdOffset >= 0 && optionOffset > holdOffset,
    `${filename} must snapshot its native CLI options only after the unconditional HOLD`,
  );
}

let callerArgumentReads = 0;
const callerArguments = new Proxy([], {
  get() {
    callerArgumentReads += 1;
    throw new Error("production main inspected caller-controlled argv before HOLD");
  },
});
for (const [entrypoint, invoke] of [
  ["version-deploy", deployVersion],
  ["version-upload", uploadVersion],
]) {
  assert.throws(
    () => invoke(callerArguments),
    (error) => error?.code === PROVIDER_MUTATION_HOLD_CODE && error?.entrypoint === entrypoint,
    `${entrypoint} must stop without reading caller-controlled argv`,
  );
}
assert.equal(callerArgumentReads, 0);

for (const [filename, expectedName] of Object.entries(LIVE_WORKER_IDENTITIES)) {
  const config = liveConfig(filename);
  assert.equal(config.name, expectedName);
  validateLiveWorkerConfig(config, filename, expectedName);
}

for (const mutation of [
  (config) => {
    config.observability.enabled = true;
  },
  (config) => {
    config.vars.GITHUB_APP_PRIVATE_KEY = "forbidden";
  },
  (config) => {
    config.routes = [{ custom_domain: true, pattern: "private.example.test" }];
  },
]) {
  const config = privateConfig();
  mutation(config);
  assert.throws(
    () =>
      validateLiveWorkerConfig(
        config,
        "wrangler.controller-run-reader.live.jsonc",
        "dpone-release-controller-run-reader",
      ),
    /live Worker (?:config|vars)|private provider Worker/u,
  );
}

const uploadOptions = {
  apply: true,
  config: LIVE_CONFIG,
  message: "reviewed broker version test",
  tag: "broker-version-test-v1",
};
const upload = simulateVersionUpload(
  JSON.stringify({ ...uploadOptions, workerName: "dpone-release-controller-run-reader" }),
);
for (const [config, workerName] of PAIRED_AUTHORITY_CONFIGS) {
  assert.throws(
    () =>
      simulateVersionUpload(
        JSON.stringify({
          ...uploadOptions,
          config,
          workerName,
        }),
      ),
    /paired authority/u,
  );
}
const deployments = ["--stage", "--promote", "--rollback"].map((operation) => {
  return simulateVersionDeployment(JSON.stringify(deploymentInput(operation)));
});

assert.deepEqual(upload.trace, [
  "versions",
  "upload",
  "--strict",
  "--message",
  "reviewed broker version test",
  "--tag",
  "broker-version-test-v1",
  "--config",
  LIVE_CONFIG,
]);
assert.deepEqual(deployments[0].trace, [
  "versions",
  "deploy",
  `${STABLE}@100%`,
  `${CANDIDATE}@0%`,
  "--yes",
  "--message",
  "reviewed deployment test",
  "--config",
  LIVE_CONFIG,
]);
assert.deepEqual(deployments[1].trace, [
  "versions",
  "deploy",
  `${CANDIDATE}@100%`,
  "--yes",
  "--message",
  "reviewed deployment test",
  "--config",
  LIVE_CONFIG,
]);
assert.deepEqual(deployments[2].trace, [
  "versions",
  "deploy",
  `${STABLE}@100%`,
  "--yes",
  "--message",
  "reviewed deployment test",
  "--config",
  LIVE_CONFIG,
]);

assert.throws(
  () =>
    simulateVersionUpload(
      JSON.stringify({ ...uploadOptions, workerName: "dpone-release-authority-broker" }),
    ),
  /authority/u,
);

assert.throws(
  () =>
    simulateVersionDeployment(JSON.stringify(deploymentInput("--stage", "not-an-immutable-id"))),
  /input invalid/u,
);

function deploymentInput(operation, candidate = CANDIDATE) {
  return {
    apply: true,
    candidate,
    config: LIVE_CONFIG,
    message: "reviewed deployment test",
    operation: operation.slice(2),
    stable: STABLE,
  };
}
