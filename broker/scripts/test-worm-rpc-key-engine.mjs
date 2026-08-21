import { simulateWormCeremony } from "./test-provider-trace-simulation.mjs";

/** Compatibility name for the JSON-only ceremony model; callback ports are impossible. */
export function provisionAuthorityKeysForTest(descriptor) {
  return simulateWormCeremony(descriptor);
}
