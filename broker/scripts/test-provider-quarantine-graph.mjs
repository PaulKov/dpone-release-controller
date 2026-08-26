import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";

import { assertAstProductionModules } from "./provider-quarantine-ast-capabilities.mjs";
import {
  analyzeCapabilityRegion,
  buildLexicalReferenceIndex,
} from "./provider-quarantine-ast-classifier.mjs";
import { canonicalImportDigest, parseQuarantineModule } from "./provider-quarantine-ast-core.mjs";

/** Exercise isolated capability classifiers and cross-module graph resolution. */
export function runProviderQuarantineGraphRegressions() {
  assertSyntheticBuiltinClassification();
  assertSyntheticTaintClassification();
  assertAmbientAliasClassification();
  assertModuleScopeEffectClassification();
  assertImplicitCallerClassification();
  assertLocalOwnerDoesNotOwnDescendants();
  assertReexportFacadeEdge();
  assertCrossModuleAliasEdge();
}

function assertModuleScopeEffectClassification() {
  const filename = "module-effects.mjs";
  const source =
    'import { readFileSync } from "node:fs";\n' +
    'readFileSync("/tmp/forbidden-secret");\n' +
    "process.stdout.write(process.env.DPONE_SECRET);\n" +
    "Object.prototype.compromised = true;\n" +
    "void process.argv[2];\n" +
    "void globalThis.crypto;\n";
  const program = parseQuarantineModule(filename, source);
  const analysis = analyzeCapabilityRegion({
    expectedExports: {},
    functions: new Map(),
    imports: new Map([["readFileSync", { imported: "readFileSync", source: "node:fs" }]]),
    key: `${filename}#<module>`,
    lexicalReferences: buildLexicalReferenceIndex(program),
    root: program,
  });
  for (const expected of [
    "filesystem-read:readFileSync",
    "ambient-call:ambient:process.stdout.write",
    "intrinsic-member-reference:intrinsic:Object.compromised",
    "ambient-computed-reference:ambient:process.argv",
    "ambient-reference:ambient:globalThis.crypto",
  ]) {
    assert.ok(analysis.capabilities.has(expected), expected);
  }
}

function assertAmbientAliasClassification() {
  const source =
    "const processAlias = process;\n" +
    "const { getBuiltinModule: loader } = processAlias;\n" +
    'const hiddenFs = loader("node:fs");\n' +
    'hiddenFs.writeFileSync("/tmp/forbidden", "x");\n' +
    "const { constructor: HiddenFunction } = Object;\n" +
    'HiddenFunction("return fetch(\\"https://example.invalid\\")")();\n';
  const program = parseQuarantineModule("ambient.mjs", source);
  const analysis = analyzeCapabilityRegion({
    expectedExports: {},
    functions: new Map(),
    imports: new Map(),
    key: "ambient.mjs#<module>",
    lexicalReferences: buildLexicalReferenceIndex(program),
    root: program,
  });
  for (const expected of ["ambient-reference", "builtin-module-loader", "dynamic-code"]) {
    assert.ok(
      [...analysis.capabilities].some((capability) => capability.includes(expected)),
      `${expected}: ${[...analysis.capabilities].join(",")}`,
    );
  }
}

function assertImplicitCallerClassification() {
  const source =
    "export async function implicit(value) {\n" +
    "  const alias = value;\n" +
    "  const { item } = alias;\n" +
    "  void [...value];\n" +
    "  for (const entry of value) void entry;\n" +
    "  await value;\n" +
    "  void `${value}`;\n" +
    "  void (value instanceof Object);\n" +
    "  void this;\n" +
    "  void arguments;\n" +
    "  return item;\n" +
    "}\n";
  const program = parseQuarantineModule("implicit.mjs", source);
  const declaration = program.body[0].declaration;
  const analysis = analyzeCapabilityRegion({
    expectedExports: { "implicit.mjs": ["implicit"] },
    functions: new Map([["implicit", declaration]]),
    imports: new Map(),
    key: "implicit.mjs#implicit",
    lexicalReferences: buildLexicalReferenceIndex(program),
    root: declaration,
  });
  for (const expected of [
    "injected-reference:value",
    "injected-reference:alias",
    "injected-reference:this",
    "injected-reference:arguments",
  ]) {
    assert.ok(analysis.capabilities.has(expected), expected);
  }
}

function assertLocalOwnerDoesNotOwnDescendants() {
  const filename = "owner.mjs";
  const source =
    'import { spawnSync } from "node:child_process";\n' +
    'function hiddenEffect() { spawnSync("provider-command", []); }\n' +
    "export function reviewedOwner() { hiddenEffect(); }\n";
  const program = parseQuarantineModule(filename, source);
  const declaration = program.body[2].declaration;
  assert.throws(
    () =>
      assertAstProductionModules({
        boundaries: [],
        expectedExports: { [filename]: ["reviewedOwner"] },
        expectedImportDigests: { [filename]: canonicalImportDigest(filename, program) },
        localCapabilityOwnerDigests: { [filename + "#reviewedOwner"]: astDigest(declaration) },
        localCapabilityOwners: { [filename + "#reviewedOwner"]: [] },
        sources: new Map([[filename, source]]),
      }),
    /unguarded production capability/u,
  );
}

function astDigest(node) {
  return createHash("sha256")
    .update(
      JSON.stringify(node, (key, value) =>
        ["comments", "end", "loc", "range", "raw", "start", "tokens"].includes(key)
          ? undefined
          : value,
      ),
    )
    .digest("hex");
}

function assertSyntheticBuiltinClassification() {
  for (const [source, expected] of [
    ['import fs from "node:fs"; fs.writeFileSync("x", "y");', "filesystem-capability"],
    ['import * as fs from "node:fs"; fs.writeFileSync("x", "y");', "filesystem-capability"],
    ['import { copyFileSync } from "node:fs"; copyFileSync("x", "y");', "filesystem-capability"],
    ['import { promises as fs } from "node:fs"; fs.writeFile("x", "y");', "filesystem-capability"],
    ['import cp from "node:child_process"; cp.spawnSync("x", []);', "child-process"],
    ['import { connect } from "node:http2"; connect("https://example.invalid");', "network-module"],
    [
      'import { setEnvironmentData } from "node:worker_threads"; setEnvironmentData("x", "y");',
      "execution-module",
    ],
    ['import vm from "node:vm"; vm.runInNewContext("x");', "execution-module"],
    [
      'import { createRequire } from "node:module"; createRequire(import.meta.url);',
      "module-loader",
    ],
  ]) {
    const program = parseQuarantineModule("synthetic-capability.mjs", source);
    const imports = new Map();
    for (const statement of program.body) {
      if (statement.type !== "ImportDeclaration") continue;
      for (const specifier of statement.specifiers) {
        const imported =
          specifier.type === "ImportDefaultSpecifier"
            ? "default"
            : specifier.type === "ImportNamespaceSpecifier"
              ? "*"
              : specifier.imported.name;
        imports.set(specifier.local.name, { imported, source: statement.source.value });
      }
    }
    const analysis = analyzeCapabilityRegion({
      expectedExports: {},
      functions: new Map(),
      imports,
      key: "synthetic-capability.mjs#<module>",
      lexicalReferences: buildLexicalReferenceIndex(program),
      root: program,
    });
    assert.ok(
      [...analysis.capabilities].some((item) => item.includes(expected)),
      `${expected}: ${[...analysis.capabilities].join(",")}`,
    );
  }
}

function assertSyntheticTaintClassification() {
  const source =
    "export function unsafe(value, options) {\n" +
    '  value.provider.set("x");\n' +
    "  options.client.get();\n" +
    "  let alias;\n" +
    "  alias = options.client;\n" +
    "  alias.map();\n" +
    "}\n";
  const program = parseQuarantineModule("taint.mjs", source);
  const declaration = program.body[0].declaration;
  const analysis = analyzeCapabilityRegion({
    expectedExports: { "taint.mjs": ["unsafe"] },
    functions: new Map([["unsafe", declaration]]),
    imports: new Map(),
    key: "taint.mjs#unsafe",
    lexicalReferences: buildLexicalReferenceIndex(program),
    root: declaration,
  });
  for (const capability of [
    "injected-call:value.set",
    "injected-call:options.get",
    "injected-call:alias.map",
  ]) {
    assert.ok(analysis.capabilities.has(capability), capability);
  }
  assert.throws(
    () =>
      assertAstProductionModules({
        boundaries: [],
        expectedExports: { "taint.mjs": ["unsafe"] },
        expectedImportDigests: { "taint.mjs": canonicalImportDigest("taint.mjs", program) },
        localCapabilityOwnerDigests: {},
        localCapabilityOwners: {},
        sources: new Map([["taint.mjs", source]]),
      }),
    /unguarded production capability/u,
  );
}

function assertReexportFacadeEdge() {
  const expectedExports = {
    "facade.mjs": ["effect"],
    "middle.mjs": ["effect"],
    "effect.mjs": ["effect"],
  };
  const sources = new Map([
    ["facade.mjs", 'export { effect } from "./middle.mjs";\n'],
    ["middle.mjs", 'export { effect } from "./effect.mjs";\n'],
    ["effect.mjs", "export function effect(dependencies) { dependencies.run(); }\n"],
  ]);
  const expectedImportDigests = Object.fromEntries(
    [...sources].map(([filename, source]) => [
      filename,
      canonicalImportDigest(filename, parseQuarantineModule(filename, source)),
    ]),
  );
  assert.throws(
    () =>
      assertAstProductionModules({
        boundaries: [],
        expectedExports,
        expectedImportDigests,
        localCapabilityOwnerDigests: {},
        localCapabilityOwners: {},
        sources,
      }),
    /facade\.mjs#effect -> effect\.mjs#effect/u,
  );

  const cycleSources = new Map([
    ["facade.mjs", 'export { effect } from "./middle.mjs";\n'],
    ["middle.mjs", 'export { effect } from "./facade.mjs";\n'],
  ]);
  const cycleExports = { "facade.mjs": ["effect"], "middle.mjs": ["effect"] };
  const cycleDigests = Object.fromEntries(
    [...cycleSources].map(([filename, source]) => [
      filename,
      canonicalImportDigest(filename, parseQuarantineModule(filename, source)),
    ]),
  );
  assert.throws(
    () =>
      assertAstProductionModules({
        boundaries: [],
        expectedExports: cycleExports,
        expectedImportDigests: cycleDigests,
        localCapabilityOwnerDigests: {},
        localCapabilityOwners: {},
        sources: cycleSources,
      }),
    /production re-export cycle/u,
  );

  const safeSource = "export function safe(value) { return value; }\n";
  assert.throws(
    () =>
      assertAstProductionModules({
        boundaries: [],
        expectedExports: { "safe.mjs": ["safe"] },
        expectedImportDigests: {
          "safe.mjs": canonicalImportDigest(
            "safe.mjs",
            parseQuarantineModule("safe.mjs", safeSource),
          ),
        },
        localCapabilityOwners: { "safe.mjs#safe": ["child-process:spawnSync"] },
        localCapabilityOwnerDigests: { "safe.mjs#safe": "unreviewed" },
        sources: new Map([["safe.mjs", safeSource]]),
      }),
    /forbidden effect|may classify injected data only/u,
  );
}

function assertCrossModuleAliasEdge() {
  const program = parseQuarantineModule(
    "alias-consumer.mjs",
    'import { dangerous as provider } from "./alias-provider.mjs";\n' +
      "export function safe() { const alias = provider; alias(); }\n",
  );
  const declaration = program.body[1].declaration;
  const analysis = analyzeCapabilityRegion({
    expectedExports: { "alias-provider.mjs": ["dangerous"] },
    functions: new Map([["safe", declaration]]),
    imports: new Map([["provider", { imported: "dangerous", source: "./alias-provider.mjs" }]]),
    key: "alias-consumer.mjs#safe",
    lexicalReferences: buildLexicalReferenceIndex(program),
    root: declaration,
  });
  assert.ok(analysis.edges.has("alias-provider.mjs#dangerous"));
}
