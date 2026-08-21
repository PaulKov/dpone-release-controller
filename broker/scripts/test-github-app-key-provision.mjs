import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";

import {
  PROVIDER_MUTATION_HOLD_CODE,
  PROVIDER_MUTATION_HOLD_MARKER,
} from "./provider-mutation-hold.mjs";
import { simulateGithubAppKeyProvision } from "./test-provider-trace-simulation.mjs";

const project = new URL("..", import.meta.url);
const script = new URL("./provision-github-app-key.mjs", import.meta.url);
const dryConfig = new URL("../wrangler.controller-run-reader.jsonc", import.meta.url);
const liveConfig = new URL("../wrangler.controller-run-reader.live.jsonc", import.meta.url);
const fingerprint = `sha256:${"1".repeat(64)}`;
const versionId = "123e4567-e89b-42d3-a456-426614174000";

const held = spawnSync(
  process.execPath,
  [script.pathname, ...argumentsFor(fingerprint, dryConfig.pathname, false)],
  { cwd: project.pathname, encoding: "utf8", maxBuffer: 65_536 },
);
assert.notEqual(held.status, 0);
assert.equal(held.stdout, "");
assert.match(
  held.stderr,
  new RegExp(`${PROVIDER_MUTATION_HOLD_CODE}.*${PROVIDER_MUTATION_HOLD_MARKER}`, "u"),
);

const simulated = simulateGithubAppKeyProvision(
  JSON.stringify({
    actualFingerprint: fingerprint,
    config: liveConfig.pathname,
    expectedFingerprint: fingerprint,
    versionId,
    workerName: "dpone-release-controller-run-reader",
  }),
);
assert.deepEqual(simulated, {
  applied: true,
  fingerprint,
  operation: "VERSION_SECRET_PUT",
  secretName: "GITHUB_APP_PRIVATE_KEY",
  versionId,
  workerName: "dpone-release-controller-run-reader",
});

function argumentsFor(expectedFingerprint, configPath, apply) {
  return [
    "--input",
    "/unread/github-app.pem",
    "--expected-spki-sha256",
    expectedFingerprint,
    "--config",
    configPath,
    "--version-tag",
    "app-key-test-v1",
    "--version-message",
    "reviewed test key conversion",
    ...(apply ? ["--apply"] : []),
  ];
}
