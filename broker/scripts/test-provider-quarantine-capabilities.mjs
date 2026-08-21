import { strict as assert } from "node:assert";

import { assertProductionScriptInventory } from "./provider-quarantine-policy.mjs";
import { runProviderQuarantineGraphRegressions } from "./test-provider-quarantine-graph.mjs";

/** Exercise the capability graph with syntax that previously escaped regex policy. */
export function runCapabilityRegressionMatrix(productionSources, reviewedScripts) {
  assertProductionMutationFails(
    productionSources,
    reviewedScripts,
    "worker-version-resource-common.mjs",
    (source) =>
      `import { writeFileSync } from "node:fs";\n${source}\n` +
      'export function durableMutation() { writeFileSync("/tmp/forbidden", "x"); }\n',
    /export inventory drift|import inventory drift/u,
  );
  assertProductionMutationFails(
    productionSources,
    reviewedScripts,
    "bootstrap-live-workers-common.mjs",
    (source) =>
      source.replace(
        'import { CLOUDFLARE_UUID } from "./cloudflare-ids.mjs";',
        'import * as identifiers from "./cloudflare-ids.mjs";',
      ),
    /effect data initializer AST drift|unresolved relative import form/u,
  );
  assertProductionMutationFails(
    productionSources,
    reviewedScripts,
    "worker-version-resource-common.mjs",
    (source) => `import Cloudflare from "cloudflare";\n${source}`,
    /unclassified external module/u,
  );
  assertProductionMutationFails(
    productionSources,
    reviewedScripts,
    "worker-version-resource-common.mjs",
    (source) => `${source}\nexport { effect } from "cloudflare";\n`,
    /unclassified re-export source/u,
  );
  assertProductionMutationFails(
    productionSources,
    reviewedScripts,
    "worker-version-resource-common.mjs",
    (source) => `import inspector from "node:inspector";\n${source}`,
    /unclassified external module/u,
  );
  assertProductionMutationFails(
    productionSources,
    reviewedScripts,
    "publication-privacy-policy.mjs",
    (source) =>
      source.replace(
        "function requireRecord(value, name) {",
        "function requireRecord(value, name) {\n" +
          "  const callback = value.callback;\n  callback();",
      ),
    /capability/u,
  );
  for (const statement of ["void value;", 'value.provider.set("x");']) {
    assertProductionMutationFails(
      productionSources,
      reviewedScripts,
      "publication-privacy-policy.mjs",
      (source) =>
        source.replace(
          "function requireRecord(value, name) {",
          `function requireRecord(value, name) {\n  ${statement}`,
        ),
      /local capability owner AST drift/u,
    );
  }
  for (const statement of [
    "return value.callback;",
    "consume(value.callback);",
    "return { callback: value.callback };",
    "return [value.callback];",
    "target.callback = value.callback;",
    "const callback = value.callback; return callback;",
  ]) {
    assertProductionMutationFails(
      productionSources,
      reviewedScripts,
      "publication-privacy-policy.mjs",
      (source) =>
        source.replace(
          "function requireRecord(value, name) {",
          `function requireRecord(value, name) {\n  ${statement}`,
        ),
      /capability|data-flow/u,
    );
  }
  for (const body of existingSpawnBypasses()) {
    assertProductionMutationFails(
      productionSources,
      reviewedScripts,
      "deploy-version.mjs",
      (source) => `${source}\nfunction unguardedBypass() { ${body} }\n`,
      /production capability|effect module|AST drift/u,
    );
  }
  assertProductionMutationFails(
    productionSources,
    reviewedScripts,
    "publication-privacy-policy.mjs",
    (source) =>
      source.replace(
        "function requireRecord(value, name) {",
        "function requireRecord(value, name) {\n  value.run();",
      ),
    /capability/u,
  );
  for (const body of globalBypasses()) {
    assertProductionMutationFails(
      productionSources,
      reviewedScripts,
      "worker-version-resource-common.mjs",
      (source) => `${source}\n${body}\n`,
      /production capability|effect module|AST drift/u,
    );
  }
  for (const [filename, addition] of [
    ["cloudflare-ids.mjs", "customProvider.deploy();"],
    [
      "cloudflare-ids.mjs",
      'const Dynamic = (() => {})["con" + "structor"]; const effect = Dynamic("customProvider.deploy()"); effect();',
    ],
    [
      "cloudflare-ids.mjs",
      'const builtin = process["get" + "BuiltinModule"]; const hiddenFs = builtin("node:fs"); hiddenFs.writeFileSync("/tmp/forbidden", "x");',
    ],
    [
      "check-module-size.mjs",
      "const reviewedAlias = formatViolations; reviewedAlias(customProvider);",
    ],
  ]) {
    assertProductionMutationFails(
      productionSources,
      reviewedScripts,
      filename,
      (source) => `${source}\n${addition}\n`,
      /production capability|effect module|AST drift/u,
    );
  }
  assertAmbientOriginBypassesFail(productionSources, reviewedScripts);
  assertImplicitCallerOperationsFail(productionSources, reviewedScripts);
  assertModuleScopeEffectsFail(productionSources, reviewedScripts);
  assertRelativeImportContainment(productionSources, reviewedScripts);
  runProviderQuarantineGraphRegressions();
}

function assertAmbientOriginBypassesFail(productionSources, reviewedScripts) {
  for (const addition of [
    'const { getBuiltinModule: hiddenLoader } = process; const hiddenFs = hiddenLoader("node:fs"); hiddenFs.writeFileSync("/tmp/forbidden", "x");',
    'const processAlias = process; const hiddenLoader = processAlias.getBuiltinModule; const hiddenFs = hiddenLoader("node:fs"); hiddenFs.writeFileSync("/tmp/forbidden", "x");',
    'const globalAlias = globalThis; globalAlias.fetch("https://example.invalid");',
    'const { constructor: HiddenFunction } = Object; const hiddenEffect = HiddenFunction("return fetch(\\"https://example.invalid\\")"); hiddenEffect();',
    'const HiddenFunction = Object["con" + "structor"]; HiddenFunction("return fetch(\\"https://example.invalid\\")")();',
    'function localCallable() {} const member = "call"; void localCallable[member];',
    "function localCallable() {} const { call: member } = localCallable; member(null);",
    "function localCallable() {} let member; ({ call: member } = localCallable); member(null);",
    "function localCallable() {} const produced = localCallable.call(null); produced();",
    'const processAlias = process; void processAlias["get" + "BuiltinModule"];',
  ]) {
    assertProductionMutationFails(
      productionSources,
      reviewedScripts,
      "cloudflare-ids.mjs",
      (source) => `${source}\n${addition}\n`,
      /production capability|effect module|AST drift/u,
    );
  }
}

function assertModuleScopeEffectsFail(productionSources, reviewedScripts) {
  for (const addition of [
    "VERSION_ID.test = () => true",
    'VERSION_ID.compile(".*", "u")',
    "VERSION_ID.lastIndex = 7",
    "const method = VERSION_ID.test; void method",
    "let localCounter = 0; localCounter++",
    "const localObject = {}; delete localObject.value",
  ]) {
    assertProductionMutationFails(
      productionSources,
      reviewedScripts,
      "bootstrap-live-workers-common.mjs",
      (source) => `${source}\n${addition};\n`,
      /mutates state before HOLD|unpinned member before HOLD/u,
    );
  }
  for (const addition of [
    'readFileSync("/tmp/forbidden-secret")',
    "process.stdout.write(process.env.DPONE_SECRET)",
    "process.argv.slice(2)",
    "Object.prototype.compromised = true",
    "Object.prototype.counter++",
    "delete Object.prototype.compromised",
    'Object.defineProperty(globalThis, "compromised", { value: true })',
  ]) {
    assertProductionMutationFails(
      productionSources,
      reviewedScripts,
      "bootstrap-live-workers-plan.mjs",
      (source) => `${source}\n${addition};\n`,
      /production capability|restricted local capability|effect module|AST drift/u,
    );
  }
  for (const addition of [
    "void globalThis.navigator",
    "void globalThis.performance",
    "void globalThis.crypto",
    "void process.env.DPONE_SECRET",
    "void process.report",
    "void process.kill",
    "void process.chdir",
    "void process.exit",
  ]) {
    assertProductionMutationFails(
      productionSources,
      reviewedScripts,
      "cloudflare-ids.mjs",
      (source) => `${source}\n${addition};\n`,
      /production capability|effect module|AST drift/u,
    );
  }
  for (const mutate of [
    (source) => `${source}\nvoid process.argv[1];\n`,
    (source) => source.replaceAll("process.argv[1]", "process.argv[2]"),
  ]) {
    assertProductionMutationFails(
      productionSources,
      reviewedScripts,
      "deploy-version.mjs",
      mutate,
      /production capability|effect module|AST drift/u,
    );
  }
}

function assertImplicitCallerOperationsFail(productionSources, reviewedScripts) {
  for (const statement of [
    "void value.property;",
    "const { property } = value; void property;",
    "const copy = [...value]; void copy;",
    "for (const item of value) void item;",
    "new value();",
    "new URL(value);",
    "await value;",
    "void `${value}`;",
    'void (value + "");',
    "value++;",
    "delete value.property;",
    'void ("property" in value);',
    "void (value instanceof Object);",
  ]) {
    assertProductionMutationFails(
      productionSources,
      reviewedScripts,
      "cloudflare-ids.mjs",
      (source) => `${source}\nasync function implicitCaller(value) { ${statement} }\n`,
      /production capability|effect module|AST drift/u,
    );
  }
  for (const statement of ["void this;", "void arguments;", "const alias = this; void alias;"]) {
    assertProductionMutationFails(
      productionSources,
      reviewedScripts,
      "cloudflare-ids.mjs",
      (source) => `${source}\nfunction implicitReceiver() { ${statement} }\n`,
      /production capability|effect module|AST drift/u,
    );
  }
}

function existingSpawnBypasses() {
  return [
    'spawnSync("provider-command", []);',
    '(() => spawnSync("provider-command", []))();',
    'class Hidden { run() { spawnSync("provider-command", []); } } new Hidden().run();',
    'const effect = spawnSync; effect("provider-command", []);',
    'Reflect.apply(spawnSync, null, ["provider-command", []]);',
    'spawnSync.call(null, "provider-command", []);',
    'const effect = spawnSync.bind(null); effect("provider-command", []);',
    "consume(spawnSync);",
    "return spawnSync;",
    "const leaked = { spawnSync }; void leaked;",
  ];
}

function globalBypasses() {
  return [
    'globalThis["fetch"]("https://example.invalid");',
    'window.fetch("https://example.invalid");',
    'self.fetch("https://example.invalid");',
    'process.getBuiltinModule("node:fs");',
    'const loader = process.getBuiltinModule; loader("node:fs");',
    'process.binding("fs");',
    'process.mainModule.require("node:fs");',
    'Bun.spawn(["provider-command"]);',
    'new Deno.Command("provider-command");',
    'eval("providerEffect()");',
    'const evaluator = eval; evaluator("providerEffect()");',
    'const loader = require; loader("node:fs");',
    'Function("return providerEffect")()();',
    "makeRunner()();",
    `const dynamic = (() => {}).constructor('return fetch("https://example.invalid")'); dynamic();`,
    'const Socket = WebSocket; new Socket("wss://example.invalid");',
    'new Worker("provider-worker.js");',
    'new SharedWorker("provider-worker.js");',
    'const beacon = navigator.sendBeacon; beacon("https://example.invalid", "x");',
  ];
}

function assertRelativeImportContainment(productionSources, reviewedScripts) {
  for (const [replacement, pattern] of [
    ["./../cloudflare-ids.mjs", /relative import escapes scripts inventory/u],
    ["./unknown.mjs", /relative import target is unclassified/u],
  ]) {
    assertProductionMutationFails(
      productionSources,
      reviewedScripts,
      "provider-quarantine-ast-classifier.mjs",
      (source) => source.replace("./provider-quarantine-ast-utils.mjs", replacement),
      pattern,
    );
  }
}

function assertProductionMutationFails(
  productionSources,
  reviewedScripts,
  filename,
  mutate,
  pattern,
) {
  const sources = new Map(productionSources);
  sources.set(filename, mutate(sources.get(filename)));
  assert.throws(() => assertProductionScriptInventory(reviewedScripts, sources), pattern);
}
