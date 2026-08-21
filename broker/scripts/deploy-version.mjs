import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { loadLiveWorkerConfig } from "./live-worker-config.mjs";
import { CLOUDFLARE_UUID } from "./cloudflare-ids.mjs";
import { assertProviderMutationReleased } from "./provider-mutation-hold.mjs";

const VERSION = CLOUDFLARE_UUID;

/** Build and execute one immutable deployment change through exact production adapters. */
export function main() {
  assertProviderMutationReleased("version-deploy");
  const arguments_ = Object.freeze(process.argv.slice(2));
  const options = parseArguments(arguments_);
  return runVersionDeployment(options, {
    loadLiveWorkerConfig,
    spawnSync,
  });
}

/** Execute a parsed deployment through explicit test/provider ports, with no real defaults. */
export function runVersionDeployment(options, dependencies) {
  assertProviderMutationReleased("version-deploy");
  const inspectConfig = requirePort(dependencies, "loadLiveWorkerConfig");
  const execute = requirePort(dependencies, "spawnSync");
  inspectConfig(options.config);
  const wrangler = fileURLToPath(
    new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url),
  );
  const versions =
    options.operation === "stage"
      ? [`${options.stable}@100%`, `${options.candidate}@0%`]
      : [`${options.operation === "promote" ? options.candidate : options.stable}@100%`];
  const command = [
    wrangler,
    "versions",
    "deploy",
    ...versions,
    "--yes",
    "--message",
    options.message,
    "--config",
    options.config,
  ];
  const result = execute(process.execPath, command, { stdio: "inherit" });
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) throw new Error("immutable Worker deployment update failed");
  return { command, operation: options.operation };
}

function requirePort(dependencies, name) {
  const value = dependencies?.[name];
  if (typeof value !== "function")
    throw new Error(`version deployment effect port missing: ${name}`);
  return value;
}

export function parseArguments(arguments_) {
  assertProviderMutationReleased("version-deploy");
  const values = new Map();
  let operation;
  let apply = false;
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--apply") {
      if (apply) throw new Error(usage());
      apply = true;
      continue;
    }
    if (argument === "--stage" || argument === "--promote" || argument === "--rollback") {
      if (operation !== undefined) throw new Error(usage());
      operation = argument.slice(2);
      continue;
    }
    if (
      argument !== "--config" &&
      argument !== "--candidate" &&
      argument !== "--message" &&
      argument !== "--stable"
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
  const config = values.get("--config");
  const candidate = values.get("--candidate");
  const message = values.get("--message");
  const stable = values.get("--stable");
  if (
    config === undefined ||
    candidate === undefined ||
    message === undefined ||
    stable === undefined ||
    operation === undefined ||
    !apply ||
    !VERSION.test(candidate) ||
    !VERSION.test(stable) ||
    candidate === stable ||
    !/^[ -~]{8,128}$/u.test(message)
  ) {
    throw new Error(usage());
  }
  return { apply, candidate, config: resolve(config), message, operation, stable };
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}

function usage() {
  return (
    "usage: pnpm version:deploy -- --config <reviewed-live.jsonc> " +
    "--candidate <immutable-version> --stable <immutable-version> " +
    "--message <reviewed-message> --apply " +
    "(--stage|--promote|--rollback)"
  );
}
