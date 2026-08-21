import { simulateBootstrap } from "./test-provider-trace-simulation.mjs";

/** Compatibility name for the data-only bootstrap model; callbacks are rejected by the model. */
export function runBootstrapForTest(descriptor) {
  return simulateBootstrap(descriptor);
}
