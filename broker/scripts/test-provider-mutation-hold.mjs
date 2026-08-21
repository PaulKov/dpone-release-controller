import { strict as assert } from "node:assert";

import {
  PROVIDER_MUTATION_BOUNDARIES,
  PROVIDER_MUTATION_ENTRYPOINTS,
  PROVIDER_MUTATION_HOLD_CODE,
  assertProviderMutationReleased,
} from "./provider-mutation-hold.mjs";
import { providerMutationCases } from "./test-provider-mutation-hold-cases.mjs";
import {
  simulateBootstrap,
  simulateCloudflareObserverTokenVerification,
  simulateGithubAppKeyProvision,
  simulateVersionDeployment,
  simulateVersionUpload,
  simulateWormCeremony,
} from "./test-provider-trace-simulation.mjs";

let effectPortReads = 0;
const explodingPorts = new Proxy(
  {},
  {
    get() {
      effectPortReads += 1;
      throw new Error("provider/local effect port was read before HOLD");
    },
  },
);
const cases = await providerMutationCases(explodingPorts);

assert.deepEqual([...PROVIDER_MUTATION_ENTRYPOINTS].sort(), [
  "bootstrap-live-apply",
  "cloudflare-observer-token-verify",
  "github-app-key-apply",
  "version-deploy",
  "version-upload",
  "worm-authority-apply",
]);
assert.deepEqual(
  cases.map(([, , boundary]) => boundary).sort(),
  PROVIDER_MUTATION_BOUNDARIES.map(({ module, symbol }) => `${module}#${symbol}`).sort(),
);
for (const [entrypoint, invoke] of cases) {
  await assert.rejects(
    async () => invoke(),
    (error) => error?.code === PROVIDER_MUTATION_HOLD_CODE && error?.entrypoint === entrypoint,
    `${entrypoint} must stop at the shared HOLD`,
  );
}
assert.equal(effectPortReads, 0);

for (const simulate of [
  simulateBootstrap,
  simulateCloudflareObserverTokenVerification,
  simulateGithubAppKeyProvision,
  simulateVersionDeployment,
  simulateVersionUpload,
  simulateWormCeremony,
]) {
  assertPrimitiveSimulationBoundary(simulate);
}

assert.throws(
  () => assertProviderMutationReleased("not-in-inventory"),
  (error) =>
    error?.code === PROVIDER_MUTATION_HOLD_CODE &&
    error?.entrypoint === "unclassified-provider-mutation",
);

process.stdout.write("provider mutation HOLD zero-effect regressions: PASS\n");

function assertPrimitiveSimulationBoundary(simulate) {
  let trapReads = 0;
  const proxy = new Proxy(
    {},
    {
      get() {
        trapReads += 1;
        throw new Error("simulation read Proxy input");
      },
      getPrototypeOf() {
        trapReads += 1;
        throw new Error("simulation inspected Proxy input");
      },
    },
  );
  assert.throws(() => simulate(proxy), /primitive JSON text/u);
  assert.equal(trapReads, 0);

  let getterReads = 0;
  const accessor = {};
  Object.defineProperty(accessor, "apply", {
    get() {
      getterReads += 1;
      throw new Error("simulation invoked stateful apply getter");
    },
  });
  assert.throws(() => simulate(accessor), /primitive JSON text/u);
  assert.equal(getterReads, 0);
}
