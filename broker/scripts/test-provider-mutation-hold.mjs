import { strict as assert } from "node:assert";
import { resolve } from "node:path";

import { main as bootstrapMain } from "./bootstrap-live-workers.mjs";
import { main as deployMain } from "./deploy-version.mjs";
import { main as githubKeyMain } from "./provision-github-app-key.mjs";
import { main as wormMain } from "./provision-worm-rpc-key.mjs";
import { runCeremony } from "./provision-worm-rpc-key-ceremony.mjs";
import {
  PROVIDER_MUTATION_ENTRYPOINTS,
  PROVIDER_MUTATION_HOLD_CODE,
  assertProviderMutationReleased,
} from "./provider-mutation-hold.mjs";
import { main as uploadMain } from "./upload-version.mjs";

const projectRoot = resolve(new URL("..", import.meta.url).pathname);
const versionA = "123e4567-e89b-42d3-a456-426614174000";
const versionB = "123e4567-e89b-42d3-a456-426614174001";
let effectPortReads = 0;
const explodingPorts = new Proxy(
  {},
  {
    get() {
      effectPortReads += 1;
      throw new Error("provider/local effect port was read before HOLD");
    },
  },
);

const cases = [
  [
    "bootstrap-live-apply",
    () =>
      bootstrapMain(
        [
          "--report",
          "/unread/bootstrap-report.json",
          "--version-tag",
          "publication-hold-v1",
          "--version-message",
          "publication HOLD regression",
          "--apply",
        ],
        explodingPorts,
      ),
  ],
  [
    "github-app-key-apply",
    () =>
      githubKeyMain(
        [
          "--input",
          "/unread/github-app.pem",
          "--expected-spki-sha256",
          `sha256:${"0".repeat(64)}`,
          "--config",
          resolve(projectRoot, "wrangler.controller-run-reader.live.jsonc"),
          "--version-tag",
          "publication-hold-v1",
          "--version-message",
          "publication HOLD regression",
          "--apply",
        ],
        explodingPorts,
      ),
  ],
  ["version-deploy", () => deployMain(deployArguments(), explodingPorts)],
  ["version-upload", () => uploadMain(uploadArguments(), explodingPorts)],
  ["worm-authority-apply", () => wormMain(wormArguments(), explodingPorts)],
  ["worm-authority-apply", () => runCeremony({ apply: true }, explodingPorts)],
];

assert.deepEqual([...PROVIDER_MUTATION_ENTRYPOINTS].sort(), [
  "bootstrap-live-apply",
  "github-app-key-apply",
  "version-deploy",
  "version-upload",
  "worm-authority-apply",
]);
for (const [entrypoint, invoke] of cases) {
  await assert.rejects(
    async () => invoke(),
    (error) => error?.code === PROVIDER_MUTATION_HOLD_CODE && error?.entrypoint === entrypoint,
    `${entrypoint} must stop at the shared HOLD`,
  );
}
assert.equal(effectPortReads, 0);
assert.throws(
  () => assertProviderMutationReleased("not-in-inventory"),
  (error) =>
    error?.code === PROVIDER_MUTATION_HOLD_CODE &&
    error?.entrypoint === "unclassified-provider-mutation",
);

assert.throws(
  () => deployMain(deployArguments().filter((value) => value !== "--apply")),
  /usage:/u,
);
assert.throws(
  () => uploadMain(uploadArguments().filter((value) => value !== "--apply")),
  /usage:/u,
);

process.stdout.write("provider mutation HOLD zero-effect regressions: PASS\n");

function deployArguments() {
  return [
    "--config",
    resolve(projectRoot, "wrangler.controller-run-reader.live.jsonc"),
    "--stable",
    versionA,
    "--candidate",
    versionB,
    "--message",
    "publication HOLD regression",
    "--stage",
    "--apply",
  ];
}

function uploadArguments() {
  return [
    "--config",
    resolve(projectRoot, "wrangler.controller-run-reader.live.jsonc"),
    "--tag",
    "publication-hold-v1",
    "--message",
    "publication HOLD regression",
    "--apply",
  ];
}

function wormArguments() {
  const unread = (name) => `/unread/${name}`;
  return [
    "--admin-access-principals",
    unread("admin-principals.json"),
    "--bootstrap-report",
    unread("bootstrap.json"),
    "--cloudflare-evidence-rpc-key",
    unread("evidence-rpc.bin"),
    "--cloudflare-observer-config",
    resolve(projectRoot, "wrangler.cloudflare-deployment-observer.live.jsonc"),
    "--cloudflare-observer-provider-policy-evidence",
    unread("provider-policy.json"),
    "--cloudflare-observer-restriction-evidence",
    unread("observer-restriction.json"),
    "--cloudflare-observer-rpc-key",
    unread("observer-rpc.bin"),
    "--cloudflare-observer-token",
    unread("observer-token.json"),
    "--ingress-config",
    resolve(projectRoot, "wrangler.live.jsonc"),
    "--input",
    unread("worm-rpc.bin"),
    "--observer-config",
    resolve(projectRoot, "wrangler.worm-version-observer.live.jsonc"),
    "--observer-restriction-evidence",
    unread("b2-observer-restriction.json"),
    "--observer-secret",
    unread("b2-observer.json"),
    "--result",
    unread("authority-hold.jsonl"),
    "--version-message",
    "publication HOLD regression",
    "--version-tag",
    "publication-hold-v1",
    "--worm-config",
    resolve(projectRoot, "wrangler.worm-mirror.live.jsonc"),
    "--writer-restriction-evidence",
    unread("b2-writer-restriction.json"),
    "--writer-secret",
    unread("b2-writer.json"),
    "--apply",
  ];
}
