import { strict as assert } from "node:assert";

import { parseArguments as parseDeployArguments, runVersionDeployment } from "./deploy-version.mjs";
import { LIVE_WORKER_IDENTITIES, validateLiveWorkerConfig } from "./live-worker-config.mjs";
import {
  CANDIDATE,
  LIVE_CONFIG,
  PAIRED_AUTHORITY_CONFIGS,
  STABLE,
  liveConfig,
  privateConfig,
} from "./test-deployment-tooling-fixtures.mjs";
import { parseArguments as parseUploadArguments, runVersionUpload } from "./upload-version.mjs";

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

const calls = [];
const dependencies = {
  loadLiveWorkerConfig: (path) => {
    assert.ok(path === LIVE_CONFIG || PAIRED_AUTHORITY_CONFIGS.has(path));
    return {
      config: privateConfig(),
      expectedName: PAIRED_AUTHORITY_CONFIGS.get(path) ?? "dpone-release-controller-run-reader",
      path,
    };
  },
  spawnSync: (executable, arguments_, options) => {
    calls.push({ arguments_, executable, options });
    return { status: 0 };
  },
};

runVersionUpload(
  parseUploadArguments([
    "--apply",
    "--config",
    LIVE_CONFIG,
    "--tag",
    "broker-version-test-v1",
    "--message",
    "reviewed broker version test",
  ]),
  dependencies,
);
for (const config of PAIRED_AUTHORITY_CONFIGS.keys()) {
  assert.throws(
    () =>
      runVersionUpload(
        parseUploadArguments([
          "--apply",
          "--config",
          config,
          "--tag",
          "broker-version-test-v1",
          "--message",
          "reviewed broker version test",
        ]),
        dependencies,
      ),
    /paired authority-key ceremony/u,
  );
}
runVersionDeployment(parseDeployArguments(deployArguments("--stage")), dependencies);
runVersionDeployment(parseDeployArguments(deployArguments("--promote")), dependencies);
runVersionDeployment(parseDeployArguments(deployArguments("--rollback")), dependencies);

assert.equal(calls.length, 4);
assert.deepEqual(calls[0].arguments_.slice(1), [
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
assert.deepEqual(calls[1].arguments_.slice(1), [
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
assert.deepEqual(calls[2].arguments_.slice(1), [
  "versions",
  "deploy",
  `${CANDIDATE}@100%`,
  "--yes",
  "--message",
  "reviewed deployment test",
  "--config",
  LIVE_CONFIG,
]);
assert.deepEqual(calls[3].arguments_.slice(1), [
  "versions",
  "deploy",
  `${STABLE}@100%`,
  "--yes",
  "--message",
  "reviewed deployment test",
  "--config",
  LIVE_CONFIG,
]);
for (const call of calls) {
  assert.equal(call.executable, process.execPath);
  assert.equal(call.arguments_.includes("deploy") && call.arguments_.includes("upload"), false);
  assert.equal(call.options.stdio, "inherit");
}

assert.throws(() => parseDeployArguments(deployArguments("--promote", STABLE)), /usage:/u);
assert.throws(
  () => parseDeployArguments(deployArguments("--stage", "not-an-immutable-id")),
  /usage:/u,
);

function deployArguments(operation, candidate = CANDIDATE) {
  return [
    "--apply",
    "--config",
    LIVE_CONFIG,
    "--stable",
    STABLE,
    "--candidate",
    candidate,
    "--message",
    "reviewed deployment test",
    operation,
  ];
}
