import { readFileSync } from "node:fs";

import { loadLiveWorkerConfig } from "./live-worker-config.mjs";
import { parseArguments } from "./provision-worm-rpc-key-arguments.mjs";
import { runCeremonyEngine } from "./provision-worm-rpc-key-ceremony.mjs";

/** Bind only explicit fake provider effects while retaining real local fixture reads. */
export function provisionAuthorityKeysForTest(arguments_, dependencies = {}) {
  const providerEffect = dependencies.spawnSync;
  if (typeof providerEffect !== "function") {
    throw new Error("WORM ceremony semantic test requires an explicit fake provider effect port");
  }
  return runCeremonyEngine(parseArguments(arguments_), {
    ...dependencies,
    loadLiveWorkerConfig: dependencies.loadLiveWorkerConfig ?? loadLiveWorkerConfig,
    now: dependencies.now ?? Date.now,
    readFileSync: dependencies.readFileSync ?? readFileSync,
    spawnSync: providerEffect,
    writeOutput: dependencies.writeOutput ?? ((value) => process.stdout.write(value)),
  });
}
