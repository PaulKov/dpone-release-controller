import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { runCeremonyCommand } from "./provision-worm-rpc-key-ceremony.mjs";
import { assertProviderMutationReleased } from "./provider-mutation-hold.mjs";

export { appendJournalEntry } from "./provision-worm-rpc-key-journal.mjs";
export { parseArguments } from "./provision-worm-rpc-key-arguments.mjs";

export function main() {
  assertProviderMutationReleased("worm-authority-apply");
  return runCeremonyCommand();
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
