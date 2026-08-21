import { PROVIDER_MUTATION_BOUNDARIES } from "./provider-mutation-hold.mjs";
import { PROVIDER_BOUNDARY_INVENTORY } from "./provider-quarantine-inventory.mjs";

const CALLER_ARGUMENT_COUNT = 12;

/**
 * Import every independently pinned production boundary and invoke it with
 * caller-controlled exploding values. Every boundary must throw the shared
 * HOLD before JavaScript can inspect, destructure, iterate, or coerce one.
 */
export async function providerMutationCases(exploding) {
  assertIndependentBoundaryInventory();
  const modules = new Map();
  for (const { module } of PROVIDER_BOUNDARY_INVENTORY) {
    if (!modules.has(module)) modules.set(module, await import(`./${module}`));
  }
  return PROVIDER_BOUNDARY_INVENTORY.map(({ entrypoint, module, symbol }) => {
    const callable = modules.get(module)?.[symbol];
    if (typeof callable !== "function") {
      throw new Error(`provider boundary is not directly callable: ${module}#${symbol}`);
    }
    const arguments_ = Array.from({ length: CALLER_ARGUMENT_COUNT }, () => exploding);
    return [entrypoint, () => callable(...arguments_), `${module}#${symbol}`];
  });
}

function assertIndependentBoundaryInventory() {
  const runtime = PROVIDER_MUTATION_BOUNDARIES.map(boundaryKey).sort();
  const pinned = PROVIDER_BOUNDARY_INVENTORY.map(boundaryKey).sort();
  if (JSON.stringify(runtime) !== JSON.stringify(pinned)) {
    throw new Error("runtime mutation boundaries differ from the independent test inventory");
  }
}

function boundaryKey({ entrypoint, module, symbol }) {
  return `${entrypoint}\0${module}#${symbol}`;
}
