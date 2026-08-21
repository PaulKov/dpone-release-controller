import { readFileSync, writeFileSync } from "node:fs";

import { parseArguments, runBootstrapEngine } from "./bootstrap-live-workers.mjs";

/** Bind explicit fake provider ports while retaining local temporary-fixture behavior. */
export function runBootstrapForTest(arguments_, dependencies = {}) {
  const explode = (name) => () => {
    throw new Error(`unexpected bootstrap test effect: ${name}`);
  };
  return runBootstrapEngine(parseArguments(arguments_), {
    ...dependencies,
    fetch: dependencies.fetch ?? explode("fetch"),
    loadLiveWorkerConfig: dependencies.loadLiveWorkerConfig ?? explode("config read"),
    readFileSync: dependencies.readFileSync ?? readFileSync,
    spawnSync: dependencies.spawnSync ?? explode("provider spawn"),
    writeFileSync: dependencies.writeFileSync ?? writeFileSync,
    writeOutput: dependencies.writeOutput ?? (() => undefined),
  });
}
