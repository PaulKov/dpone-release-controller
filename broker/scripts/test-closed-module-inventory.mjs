import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { assertClosedModuleInventory } from "./closed-module-inventory.mjs";
import {
  canonicalImportInventory,
  parseQuarantineModule,
} from "./provider-quarantine-ast-core.mjs";
import { readRegularContainedScripts } from "./provider-quarantine-filesystem.mjs";
import { runCapabilityRegressionMatrix } from "./test-provider-quarantine-capabilities.mjs";
import { runPreImportBootstrapRegressions } from "./test-provider-quarantine-bootstrap.mjs";
import { runProviderBoundaryExportRegressions } from "./test-provider-quarantine-boundaries.mjs";
import { runProviderSimulationRegressions } from "./test-provider-quarantine-simulations.mjs";
import {
  PROVIDER_MUTATION_BOUNDARIES,
  PROVIDER_MUTATION_ENTRYPOINTS,
} from "./provider-mutation-hold.mjs";
import {
  PRODUCTION_EFFECT_MODULE_EXPORTS,
  PRODUCTION_SCRIPT_INVENTORY,
  PROVIDER_SIMULATION_MODULES,
  assertProductionScriptInventory,
  assertProviderBoundarySources,
  assertProviderPackageScripts,
  assertSupportedExportSyntax,
} from "./provider-quarantine-policy.mjs";

const inventory = ["bootstrap-main.mjs", "bootstrap-plan.mjs"];
const sources = new Map([
  ["bootstrap-main.mjs", 'import { plan } from "./bootstrap-plan.mjs";\n'],
  ["bootstrap-plan.mjs", "export const plan = {};\n"],
]);
const input = () => ({
  actual: [...inventory],
  boundary: /^bootstrap-[a-z-]+\.mjs$/u,
  inventory: [...inventory],
  root: "bootstrap-main.mjs",
  sources: new Map(sources),
});

assert.deepEqual(assertClosedModuleInventory(input()), [...inventory].sort());

const scratch = mkdtempSync(join(tmpdir(), "dpone-provider-quarantine-"));
try {
  const rootUrl = pathToFileURL(`${scratch}/`);
  writeFileSync(join(scratch, "regular.mjs"), "export const reviewed = true;\n", "utf8");
  assert.equal(
    readRegularContainedScripts(rootUrl, ["regular.mjs"]).get("regular.mjs"),
    "export const reviewed = true;\n",
  );
  symlinkSync(join(scratch, "regular.mjs"), join(scratch, "linked.mjs"));
  assert.throws(() => readRegularContainedScripts(rootUrl, ["linked.mjs"]), /regular non-symlink/u);
  mkdirSync(join(scratch, "directory.mjs"));
  assert.throws(
    () => readRegularContainedScripts(rootUrl, ["directory.mjs"]),
    /regular non-symlink/u,
  );
  writeFileSync(join(scratch, "invalid-utf8.mjs"), Uint8Array.from([0xc3, 0x28]));
  assert.throws(
    () => readRegularContainedScripts(rootUrl, ["invalid-utf8.mjs"]),
    /not exact UTF-8/u,
  );
  writeFileSync(
    join(scratch, "bom.mjs"),
    Uint8Array.from([0xef, 0xbb, 0xbf, 0x65, 0x78, 0x70, 0x6f, 0x72, 0x74]),
  );
  assert.throws(() => readRegularContainedScripts(rootUrl, ["bom.mjs"]), /forbidden BOM/u);
} finally {
  rmSync(scratch, { force: true, recursive: true });
}

const environmentScratch = mkdtempSync(join(tmpdir(), "dpone-provider-env-probe-"));
try {
  const marker = join(environmentScratch, "executed");
  const fakePnpm = join(environmentScratch, "pnpm.cjs");
  writeFileSync(
    fakePnpm,
    `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "executed");\n`,
    "utf8",
  );
  const verification = spawnSync(
    process.execPath,
    [fileURLToPath(new URL("./verify-project-config.mjs", import.meta.url))],
    {
      cwd: fileURLToPath(new URL("../", import.meta.url)),
      encoding: "utf8",
      env: { ...process.env, npm_execpath: fakePnpm },
    },
  );
  assert.equal(verification.status, 0, verification.stderr);
  assert.equal(existsSync(marker), false, "npm_execpath must not execute code");
} finally {
  rmSync(environmentScratch, { force: true, recursive: true });
}

assert.throws(
  () => assertClosedModuleInventory({ ...input(), actual: [...inventory, "bootstrap-extra.mjs"] }),
  /missing or extra/u,
);
assert.throws(
  () =>
    assertClosedModuleInventory({
      ...input(),
      sources: new Map([
        ["bootstrap-main.mjs", 'import "./bootstrap-unreviewed.mjs";\n'],
        ["bootstrap-plan.mjs", "export const plan = {};\n"],
      ]),
    }),
  /import escapes inventory/u,
);
assert.throws(
  () =>
    assertClosedModuleInventory({
      ...input(),
      sources: new Map([
        ["bootstrap-main.mjs", "export const main = {};\n"],
        ["bootstrap-plan.mjs", "export const plan = {};\n"],
      ]),
    }),
  /unreachable files/u,
);

const productionSources = new Map(
  PRODUCTION_SCRIPT_INVENTORY.map((filename) => [
    filename,
    readFileSync(new URL(`./${filename}`, import.meta.url), "utf8"),
  ]),
);
const reviewedScripts = [...PRODUCTION_SCRIPT_INVENTORY, "test-reviewed.mjs"];
assert.doesNotThrow(() => assertProductionScriptInventory(reviewedScripts, productionSources));
for (const mutate of [
  (source) =>
    source.replace(
      'await import("./provider-quarantine-policy.mjs")',
      'await import("./unreviewed-policy.mjs")',
    ),
  (source) => `${source}\nvoid import("./provider-quarantine-policy.mjs");\n`,
]) {
  const mutated = new Map(productionSources);
  mutated.set(
    "verify-provider-quarantine.mjs",
    mutate(mutated.get("verify-provider-quarantine.mjs")),
  );
  assert.throws(
    () => assertProductionScriptInventory(reviewedScripts, mutated),
    /unclassified dynamic import/u,
  );
}
for (const filename of ["evil.js", "evil.cjs", "evil.mjs"]) {
  assert.throws(
    () => assertProductionScriptInventory([...reviewedScripts, filename], productionSources),
    /unclassified/u,
  );
}
for (const source of [
  "export default function effect() {}\n",
  "export/*gap*/default function effect() {}\n",
  'export * from "./effect.mjs";\n',
  "export let effect = true;\n",
  "export var effect = true;\n",
  "export function* effect() {}\n",
  "const effect = true; export { effect as default };\n",
  'export { default as effect } from "./effect.mjs";\n',
  "export const effect: number = 1;\n",
]) {
  assert.throws(
    () => assertSupportedExportSyntax("synthetic.mjs", source),
    /export form|strict ECMAScript/u,
  );
}

const simulationSources = new Map(
  PROVIDER_SIMULATION_MODULES.map((filename) => [
    filename,
    readFileSync(new URL(`./${filename}`, import.meta.url), "utf8"),
  ]),
);
runProviderSimulationRegressions(PROVIDER_SIMULATION_MODULES, simulationSources);

assert.deepEqual(
  canonicalImportInventory(
    "reviewable.mjs",
    parseQuarantineModule(
      "reviewable.mjs",
      'import { readFile as reader } from "node:fs";\nexport { reader };\n',
    ),
  ),
  [{ bindings: ["readFile>reader"], kind: "import", source: "node:fs" }],
);

const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
runPreImportBootstrapRegressions(fileURLToPath(new URL("../", import.meta.url)));
assert.doesNotThrow(() => assertProviderPackageScripts(packageJson));
assert.throws(
  () =>
    assertProviderPackageScripts({
      ...packageJson,
      scripts: { ...packageJson.scripts, evil: "node scripts/evil.js" },
    }),
  /rollout/u,
);

const effectSources = new Map(
  Object.keys(PRODUCTION_EFFECT_MODULE_EXPORTS).map((filename) => [
    filename,
    readFileSync(new URL(`./${filename}`, import.meta.url), "utf8"),
  ]),
);
effectSources.set(
  "provider-mutation-hold.mjs",
  productionSources.get("provider-mutation-hold.mjs"),
);
assert.doesNotThrow(() =>
  assertProviderBoundarySources(
    PROVIDER_MUTATION_BOUNDARIES,
    PROVIDER_MUTATION_ENTRYPOINTS,
    effectSources,
  ),
);
assertBoundaryMutationFails(
  "bootstrap-live-workers.mjs",
  (source) =>
    source.replace(
      "export async function main() {",
      "export async function main(caller = readSecrets()) {",
    ),
  /effectful parameter/u,
);
assertBoundaryMutationFails(
  "upload-version.mjs",
  (source) =>
    source.replace(
      'export function runVersionUpload(options, dependencies) {\n  assertProviderMutationReleased("version-upload");',
      'export function runVersionUpload(options, dependencies) {\n  void dependencies;\n  assertProviderMutationReleased("version-upload");',
    ),
  /does not start/u,
);
assertBoundaryMutationFails(
  "upload-version.mjs",
  (source) =>
    source.replace(
      '  assertProviderMutationReleased("version-upload");',
      '  // assertProviderMutationReleased("version-upload");',
    ),
  /does not start/u,
);
assertBoundaryMutationFails(
  "upload-version.mjs",
  (source) =>
    source.replace(
      '  assertProviderMutationReleased("version-upload");',
      '  if (false) assertProviderMutationReleased("version-upload");',
    ),
  /does not start/u,
);
assertBoundaryMutationFails(
  "upload-version.mjs",
  (source) =>
    source.replace(
      '  assertProviderMutationReleased("version-upload");',
      '  assertProviderMutationReleased("version-upload");\n  function assertProviderMutationReleased() {}',
    ),
  /shadowed/u,
);
assertBoundaryMutationFails(
  "upload-version.mjs",
  (source) => `${source}\nexport function unreviewedMutation() {}\n`,
  /export inventory drift/u,
);
assertBoundaryMutationFails(
  "bootstrap-live-workers-common.mjs",
  (source) =>
    source.replace(
      "export const MAX_SMOKE_BYTES = 65_536;",
      "export const MAX_SMOKE_BYTES = () => 65_536;",
    ),
  /initializer AST drift|unsupported callable binding/u,
);
for (const mutate of [
  (source) => source.replace("  throw error;", "  return error;"),
  (source) =>
    source.replace(
      "export function assertProviderMutationReleased(entrypoint) {",
      "export function assertProviderMutationReleased(entrypoint) {\n  return;",
    ),
  (source) =>
    source.replace(
      "export function assertProviderMutationReleased(entrypoint) {",
      'export function assertProviderMutationReleased(entrypoint) {\n  if (false) throw new Error("dead HOLD");',
    ),
]) {
  assertBoundaryMutationFails(
    "provider-mutation-hold.mjs",
    mutate,
    /HOLD (?:Program|implementation) AST drift/u,
  );
}
assertBoundaryMutationFails(
  "provider-mutation-hold.mjs",
  (source) => `${source}\nlet preHoldMutation = 0; preHoldMutation++;\n`,
  /HOLD Program AST drift/u,
);

runCapabilityRegressionMatrix(productionSources, reviewedScripts);
runProviderBoundaryExportRegressions(effectSources);

process.stdout.write("closed module inventory regressions: PASS\n");

function assertBoundaryMutationFails(filename, mutate, pattern) {
  const sources = new Map(effectSources);
  sources.set(filename, mutate(sources.get(filename)));
  assert.throws(
    () =>
      assertProviderBoundarySources(
        PROVIDER_MUTATION_BOUNDARIES,
        PROVIDER_MUTATION_ENTRYPOINTS,
        sources,
      ),
    pattern,
  );
}
