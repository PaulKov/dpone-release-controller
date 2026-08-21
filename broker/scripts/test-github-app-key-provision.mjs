import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

import { parseArguments, runGithubAppKeyProvision } from "./provision-github-app-key.mjs";

const project = new URL("..", import.meta.url);
const script = new URL("./provision-github-app-key.mjs", import.meta.url);
const config = new URL("../wrangler.controller-run-reader.jsonc", import.meta.url);
const temporaryDirectory = mkdtempSync(`${tmpdir()}/dpone-github-app-key-test-`);
const sourcePath = `${temporaryDirectory}/github-app.pem`;

try {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const source = privateKey.export({ format: "pem", type: "pkcs1" });
  const publicSpki = publicKey.export({ format: "der", type: "spki" });
  const fingerprint = `sha256:${createHash("sha256").update(publicSpki).digest("hex")}`;
  writeFileSync(sourcePath, source, { mode: 0o600 });

  const success = run(fingerprint);
  if (success.status !== 0) {
    throw new Error("PKCS#1 to PKCS#8 provisioning validation failed");
  }
  const expected =
    JSON.stringify({
      applied: false,
      config: "wrangler.controller-run-reader.jsonc",
      fingerprint,
      runtime_format: "PKCS8",
      version_id: null,
      version_message: "reviewed test key conversion",
      version_tag: "app-key-test-v1",
    }) + "\n";
  if (success.stdout !== expected || success.stdout.includes("PRIVATE KEY")) {
    throw new Error("provisioning validation emitted unexpected or sensitive output");
  }

  const mismatch = run(`sha256:${"0".repeat(64)}`);
  if (mismatch.status === 0 || mismatch.stdout.includes("PRIVATE KEY")) {
    throw new Error("provisioning validation accepted a mismatched public fingerprint");
  }

  const liveConfig = new URL("../wrangler.controller-run-reader.live.jsonc", import.meta.url);
  const versionId = "123e4567-e89b-42d3-a456-426614174000";
  const calls = [];
  const inspectedConfigs = [];
  const output = [];
  runGithubAppKeyProvision(parseArguments(argumentsFor(fingerprint, liveConfig.pathname, true)), {
    loadLiveWorkerConfig: (path) => inspectedConfigs.push(path),
    spawnSync: (executable, arguments_, options) => {
      if (executable === "openssl") return spawnSync(executable, arguments_, options);
      calls.push({ arguments_, executable, inputBytes: options.input.byteLength });
      return {
        status: 0,
        stdout: `Created version ${versionId} with secret GITHUB_APP_PRIVATE_KEY\n`,
      };
    },
    writeOutput: (value) => output.push(value),
  });
  if (
    inspectedConfigs.length !== 1 ||
    inspectedConfigs[0] !== liveConfig.pathname ||
    calls.length !== 1 ||
    JSON.stringify(calls[0].arguments_.slice(1, 5)) !==
      JSON.stringify(["versions", "secret", "put", "GITHUB_APP_PRIVATE_KEY"]) ||
    calls[0].arguments_.includes("deploy") ||
    calls[0].inputBytes < 512 ||
    output.length !== 1 ||
    JSON.parse(output[0]).version_id !== versionId
  ) {
    throw new Error("apply path did not create exactly one undeployed immutable secret version");
  }

  for (const forbidden of [
    "wrangler.live.jsonc",
    "wrangler.worm-mirror.live.jsonc",
    "wrangler.worm-version-observer.live.jsonc",
  ]) {
    let rejected = false;
    try {
      runGithubAppKeyProvision(
        parseArguments(
          argumentsFor(fingerprint, new URL(`../${forbidden}`, import.meta.url).pathname, true),
        ),
        {
          loadLiveWorkerConfig: () => {
            throw new Error("forbidden live config reached loader");
          },
          spawnSync,
          writeOutput: () => undefined,
        },
      );
    } catch {
      rejected = true;
    }
    if (!rejected) throw new Error(`apply path accepted forbidden config ${forbidden}`);
  }
} finally {
  rmSync(temporaryDirectory, { force: true, recursive: true });
}

function run(expectedFingerprint) {
  return spawnSync(
    process.execPath,
    [
      script.pathname,
      "--input",
      sourcePath,
      "--expected-spki-sha256",
      expectedFingerprint,
      "--config",
      config.pathname,
      "--version-tag",
      "app-key-test-v1",
      "--version-message",
      "reviewed test key conversion",
    ],
    { cwd: project.pathname, encoding: "utf8", maxBuffer: 65_536 },
  );
}

function argumentsFor(expectedFingerprint, configPath, apply) {
  return [
    "--input",
    sourcePath,
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
