import { strict as assert } from "node:assert";

import { assertClosedModuleInventory } from "./closed-module-inventory.mjs";

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

process.stdout.write("closed module inventory regressions: PASS\n");
