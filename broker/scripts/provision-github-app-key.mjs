import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { loadLiveWorkerConfig } from "./live-worker-config.mjs";
import { CLOUDFLARE_UUID_SOURCE } from "./cloudflare-ids.mjs";
import { assertProviderMutationReleased } from "./provider-mutation-hold.mjs";

const DRY_RUN_CONFIGS = new Set([
  "wrangler.candidate-reader.jsonc",
  "wrangler.controller-run-reader.jsonc",
  "wrangler.governance-reader.jsonc",
]);
const LIVE_CONFIGS = new Set([
  "wrangler.candidate-reader.live.jsonc",
  "wrangler.controller-run-reader.live.jsonc",
  "wrangler.governance-reader.live.jsonc",
]);
const PROJECT_ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const SOURCE =
  /^-----BEGIN RSA PRIVATE KEY-----\n[+/0-9A-Za-z\n=]+\n-----END RSA PRIVATE KEY-----\n?$/u;
const CONVERTED = /^-----BEGIN PRIVATE KEY-----\n[+/0-9A-Za-z\n=]+\n-----END PRIVATE KEY-----\n?$/u;

/**
 * Validate GitHub's PKCS#1 download, convert it to runtime PKCS#8 and optionally
 * create one undeployed secret-bearing Worker version. Private bytes are never logged.
 */
export function main() {
  assertProviderMutationReleased("github-app-key-apply");
  const arguments_ = Object.freeze(process.argv.slice(2));
  const options = parseArguments(arguments_);
  if (!options.apply) return runGithubAppKeyValidation(options);
  return runGithubAppKeyProvision(options, {
    loadLiveWorkerConfig,
    spawnSync,
    writeOutput: (value) => process.stdout.write(value),
  });
}

/** Quarantined provider mutation boundary; the shared HOLD is always the first operation. */
export function runGithubAppKeyProvision(options, dependencies) {
  assertProviderMutationReleased("github-app-key-apply");
  return executeGithubAppKeyOperation(options, dependencies);
}

/** Validate and convert a key without loading a live config or invoking Wrangler. */
function runGithubAppKeyValidation(options) {
  if (options.apply) throw new Error("GitHub App key validation rejects apply options");
  return executeGithubAppKeyOperation(options, {
    loadLiveWorkerConfig,
    spawnSync,
    writeOutput: (value) => process.stdout.write(value),
  });
}

function executeGithubAppKeyOperation(options, dependencies) {
  const execute = requirePort(dependencies, "spawnSync");
  const inspectLiveConfig = requirePort(dependencies, "loadLiveWorkerConfig");
  const writeOutput = requirePort(dependencies, "writeOutput");
  const sourceBytes = readFileSync(options.input);
  const source = sourceBytes.toString("utf8");
  if (sourceBytes.byteLength < 512 || sourceBytes.byteLength > 32_768 || !SOURCE.test(source)) {
    sourceBytes.fill(0);
    throw new Error("input must be one downloaded PKCS#1 GitHub App RSA private key");
  }

  const temporaryDirectory = mkdtempSync(`${tmpdir()}/dpone-github-app-key-`);
  const convertedPath = resolve(temporaryDirectory, "app.pk8.pem");
  let convertedBytes;
  try {
    runOpenSsl(
      ["pkcs8", "-topk8", "-nocrypt", "-in", options.input, "-out", convertedPath],
      execute,
    );
    chmodSync(convertedPath, 0o600);
    convertedBytes = readFileSync(convertedPath);
    if (
      convertedBytes.byteLength < 512 ||
      convertedBytes.byteLength > 16_384 ||
      !CONVERTED.test(convertedBytes.toString("utf8"))
    ) {
      throw new Error("OpenSSL did not produce the required unencrypted PKCS#8 PEM");
    }
    const publicKey = runOpenSsl(
      ["pkey", "-in", convertedPath, "-pubout", "-outform", "DER"],
      execute,
    );
    const fingerprint = `sha256:${createHash("sha256").update(publicKey).digest("hex")}`;
    if (fingerprint !== options.expectedFingerprint) {
      throw new Error(
        "public SPKI fingerprint does not match the independently reviewed GitHub UI value",
      );
    }

    let createdVersionId = null;
    if (options.apply) {
      inspectLiveConfig(options.config);
      const wrangler = fileURLToPath(
        new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url),
      );
      const result = execute(
        process.execPath,
        [
          wrangler,
          "versions",
          "secret",
          "put",
          "GITHUB_APP_PRIVATE_KEY",
          "--message",
          options.versionMessage,
          "--tag",
          options.versionTag,
          "--config",
          options.config,
        ],
        { encoding: "utf8", input: convertedBytes, maxBuffer: 65_536 },
      );
      if (result.error !== undefined) throw result.error;
      if (result.status !== 0) throw new Error("Wrangler version-only secret upload failed");
      const matches = [
        ...(result.stdout ?? "").matchAll(
          new RegExp(`Created version (${CLOUDFLARE_UUID_SOURCE}) with secret`, "gu"),
        ),
      ];
      if (matches.length !== 1 || matches[0]?.[1] === undefined) {
        throw new Error("Wrangler did not return one exact immutable secret version ID");
      }
      createdVersionId = matches[0][1];
    }
    const output =
      JSON.stringify({
        applied: options.apply,
        config: basename(options.config),
        fingerprint,
        runtime_format: "PKCS8",
        version_id: createdVersionId,
        version_message: options.versionMessage,
        version_tag: options.versionTag,
      }) + "\n";
    writeOutput(output);
    return output;
  } finally {
    sourceBytes.fill(0);
    convertedBytes?.fill(0);
    rmSync(temporaryDirectory, { force: true, recursive: true });
  }
}

function requirePort(dependencies, name) {
  const value = dependencies?.[name];
  if (typeof value !== "function") throw new Error(`GitHub App key effect port missing: ${name}`);
  return value;
}

export function parseArguments(arguments_) {
  assertProviderMutationReleased("github-app-key-apply");
  const values = new Map();
  let apply = false;
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--apply") {
      if (apply) throw new Error("duplicate --apply");
      apply = true;
      continue;
    }
    if (
      argument !== "--input" &&
      argument !== "--expected-spki-sha256" &&
      argument !== "--config" &&
      argument !== "--version-message" &&
      argument !== "--version-tag"
    ) {
      throw new Error(usage());
    }
    const value = arguments_[index + 1];
    if (value === undefined || value.startsWith("--") || values.has(argument)) {
      throw new Error(usage());
    }
    values.set(argument, value);
    index += 1;
  }
  const input = values.get("--input");
  const expectedFingerprint = values.get("--expected-spki-sha256");
  const config = values.get("--config");
  const versionMessage = values.get("--version-message");
  const versionTag = values.get("--version-tag");
  const resolvedConfig = config === undefined ? undefined : resolve(config);
  if (
    input === undefined ||
    expectedFingerprint === undefined ||
    resolvedConfig === undefined ||
    versionMessage === undefined ||
    versionTag === undefined ||
    !/^sha256:[0-9a-f]{64}$/u.test(expectedFingerprint) ||
    !/^[ -~]{8,128}$/u.test(versionMessage) ||
    !/^[a-z0-9][a-z0-9._-]{7,63}$/u.test(versionTag) ||
    !(apply ? LIVE_CONFIGS : DRY_RUN_CONFIGS).has(basename(resolvedConfig)) ||
    resolvedConfig !== resolve(PROJECT_ROOT, basename(resolvedConfig))
  ) {
    throw new Error(usage());
  }
  return {
    apply,
    config: resolvedConfig,
    expectedFingerprint,
    input: resolve(input),
    versionMessage,
    versionTag,
  };
}

function runOpenSsl(arguments_, execute) {
  const result = execute("openssl", arguments_, {
    encoding: arguments_.includes("DER") ? null : "utf8",
    maxBuffer: 65_536,
  });
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) {
    throw new Error("OpenSSL key conversion or fingerprint derivation failed");
  }
  return Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(result.stdout ?? "", "utf8");
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}

function usage() {
  return (
    "usage: pnpm github-app-key:provision -- --input <downloaded-pkcs1.pem> " +
    "--expected-spki-sha256 sha256:<64-lowercase-hex> --config <private-worker.jsonc> " +
    "--version-tag <reviewed-tag> --version-message <reviewed-message> [--apply]"
  );
}
