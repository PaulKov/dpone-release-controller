import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parseArguments } from "./provision-worm-rpc-key-arguments.mjs";
import { runCeremony } from "./provision-worm-rpc-key-ceremony.mjs";
import { assertProviderMutationReleased } from "./provider-mutation-hold.mjs";

export { appendJournalEntry } from "./provision-worm-rpc-key-journal.mjs";
export { parseArguments };

export function main(arguments_, dependencies = {}) {
  const options = parseArguments(arguments_);
  if (options.apply) assertProviderMutationReleased("worm-authority-apply");
  return runCeremony(options, dependencies);
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2));
}
