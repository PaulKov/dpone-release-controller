import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { loadLiveWorkerConfig } from "./live-worker-config.mjs";
import { assertProviderMutationReleased } from "./provider-mutation-hold.mjs";

/** Upload code as an undeployed immutable version. Traffic is changed separately. */
export function main() {
  assertProviderMutationReleased("version-upload");
  const arguments_ = Object.freeze(process.argv.slice(2));
  const options = parseArguments(arguments_);
  return runVersionUpload(options, {
    loadLiveWorkerConfig,
    spawnSync,
  });
}

/** Execute a parsed upload through explicit test/provider ports, with no real defaults. */
export function runVersionUpload(options, dependencies) {
  assertProviderMutationReleased("version-upload");
  const inspectConfig = requirePort(dependencies, "loadLiveWorkerConfig");
  const execute = requirePort(dependencies, "spawnSync");
  const inspected = inspectConfig(options.config);
  if (
    [
      "dpone-release-authority-broker",
      "dpone-release-cloudflare-deployment-observer",
      "dpone-release-worm-mirror",
      "dpone-release-worm-version-observer",
    ].includes(inspected.expectedName)
  ) {
    throw new Error(
      "ingress/WORM/observer versions must be created by the paired authority-key ceremony",
    );
  }
  const wrangler = fileURLToPath(
    new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url),
  );
  const command = [
    wrangler,
    "versions",
    "upload",
    "--strict",
    "--message",
    options.message,
    "--tag",
    options.tag,
    "--config",
    options.config,
  ];
  const result = execute(process.execPath, command, { stdio: "inherit" });
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) throw new Error("immutable Worker version upload failed");
  return { command };
}

function requirePort(dependencies, name) {
  const value = dependencies?.[name];
  if (typeof value !== "function") throw new Error(`version upload effect port missing: ${name}`);
  return value;
}

export function parseArguments(arguments_) {
  assertProviderMutationReleased("version-upload");
  const values = new Map();
  let apply = false;
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--apply") {
      if (apply) throw new Error(usage());
      apply = true;
      continue;
    }
    if (!["--config", "--message", "--tag"].includes(argument)) throw new Error(usage());
    const value = arguments_[index + 1];
    if (value === undefined || value.startsWith("--") || values.has(argument)) {
      throw new Error(usage());
    }
    values.set(argument, value);
    index += 1;
  }
  const config = values.get("--config");
  const message = values.get("--message");
  const tag = values.get("--tag");
  if (
    config === undefined ||
    message === undefined ||
    tag === undefined ||
    !apply ||
    !/^[ -~]{8,128}$/u.test(message) ||
    !/^[a-z0-9][a-z0-9._-]{7,63}$/u.test(tag)
  ) {
    throw new Error(usage());
  }
  return { apply, config: resolve(config), message, tag };
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}

function usage() {
  return (
    "usage: pnpm version:upload -- --config <reviewed-live.jsonc> " +
    "--tag <reviewed-tag> --message <reviewed-message> --apply"
  );
}
