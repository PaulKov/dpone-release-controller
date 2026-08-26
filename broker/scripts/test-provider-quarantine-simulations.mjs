import { strict as assert } from "node:assert";

import { assertProviderSimulationsAreDataOnly } from "./provider-quarantine-policy.mjs";

const CENTRAL = "test-provider-trace-simulation.mjs";
const INSERTION = "  requireVersionMetadata(value);";

/** Exercise primitive boundaries, receiver provenance and exact simulation AST pins. */
export function runProviderSimulationRegressions(simulationModules, simulationSources) {
  assert.doesNotThrow(() =>
    assertProviderSimulationsAreDataOnly(simulationModules, simulationSources),
  );
  assert.throws(
    () =>
      assertProviderSimulationsAreDataOnly(
        [...simulationModules, "test-extra-engine.mjs"],
        simulationSources,
      ),
    /inventory drift/u,
  );
  for (const mutate of baseMutations())
    assertSimulationMutationFails(simulationModules, simulationSources, mutate);
  for (const method of ["add", "map", "test"]) {
    assertSimulationMutationFails(simulationModules, simulationSources, (source) =>
      source.replace(INSERTION, `  customProvider.${method}();\n${INSERTION}`),
    );
  }
  for (const intrinsic of ["Array", "RegExp", "Set"]) {
    assertSimulationMutationFails(
      simulationModules,
      simulationSources,
      (source) => `const ${intrinsic} = function ShadowedIntrinsic() {};\n${source}`,
      /Program AST drift|shadows an intrinsic|unreviewed callable binding/u,
    );
  }
  assertSimulationMutationFails(simulationModules, simulationSources, (source) =>
    source.replace(
      INSERTION,
      `  const memberAlias = PAIRED_AUTHORITIES.add;\n  memberAlias("x");\n${INSERTION}`,
    ),
  );
  assertSimulationMutationFails(
    simulationModules,
    simulationSources,
    (source) =>
      source.replace(
        "version upload simulation metadata missing",
        "version upload simulation metadata drift",
      ),
    /Program AST drift|function AST drift/u,
  );
  assertSimulationMutationFails(
    simulationModules,
    simulationSources,
    (source) => `${source}\nfunction unreviewedPrivateHelper() { return true; }\n`,
    /Program AST drift|function inventory drift/u,
  );
  for (const addition of [
    "Object.prototype.compromised = true;",
    "Set.prototype.add = parseSimulationInput;",
    "globalThis.compromised = true;",
    'Object.defineProperty(Object.prototype, "secret", { get() { return customProvider; } });',
  ]) {
    assertSimulationMutationFails(
      simulationModules,
      simulationSources,
      (source) => `${source}\n${addition}\n`,
      /Program AST drift|effectful top-level|executable module scope/u,
    );
  }
}

function baseMutations() {
  return [
    (source) => source.replace(INSERTION, `  void import("node:fs/promises");\n${INSERTION}`),
    (source) => `import { readFile as reader } from "fs/promises";\n${source}`,
    (source) => source.replace(INSERTION, `  globalThis.fetch(input);\n${INSERTION}`),
    (source) => source.replace(INSERTION, `  value.callback();\n${INSERTION}`),
    (source) =>
      source.replace(
        'if (typeof source !== "string") {',
        'if (typeof source !== "string") {}\n  if (false) {',
      ),
    (source) => source.replace('if (typeof source !== "string") {', "void source;\n  if (false) {"),
    (source) =>
      `${source}\nexport/*gap*/function simulateBypass(source, cb) { return cb(source); }\n`,
    (source) =>
      source.replace(INSERTION, `  const cb = value.callback;\n  cb(input);\n${INSERTION}`),
    (source) => `${source}\nnavigator.sendBeacon("https://example.invalid", "x");\n`,
    (source) =>
      source.replace(INSERTION, `  function parseSimulationInput() { return {}; }\n${INSERTION}`),
    (source) =>
      source.replace(
        INSERTION,
        `  { const parseSimulationInput = JSON.parse; parseSimulationInput(input); }\n${INSERTION}`,
      ),
  ];
}

function assertSimulationMutationFails(
  simulationModules,
  simulationSources,
  mutate,
  pattern = /effect capability|forbidden|import inventory|inventory drift|Program AST drift|primitive|sealed|shadow|unreviewed|callable member/u,
) {
  const mutated = new Map(simulationSources);
  mutated.set(CENTRAL, mutate(simulationSources.get(CENTRAL)));
  assert.throws(() => assertProviderSimulationsAreDataOnly(simulationModules, mutated), pattern);
}
