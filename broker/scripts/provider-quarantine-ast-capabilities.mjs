import { createHash } from "node:crypto";

import {
  assertExactModuleExports,
  astNodes,
  canonicalImportDigest,
  canonicalImportInventory,
  collectModuleExports,
  parseQuarantineModule,
} from "./provider-quarantine-ast-core.mjs";
import {
  analyzeCapabilityRegion,
  buildLexicalReferenceIndex,
} from "./provider-quarantine-ast-classifier.mjs";
import {
  assertEffectModuleScope,
  isReviewedLocalCapability,
} from "./provider-quarantine-ast-effects.mjs";
import {
  combineGraphs,
  materializeCallableExportAliases,
} from "./provider-quarantine-ast-graph.mjs";
import {
  assertCapabilityOwnership,
  normalizedAstDigest,
} from "./provider-quarantine-ast-ownership.mjs";

const REVIEWED_NODE_MODULES = new Set([
  "node:child_process",
  "node:crypto",
  "node:fs",
  "node:fs/promises",
  "node:os",
  "node:path",
  "node:url",
  "node:util",
]);
const TRUSTED_BOOTSTRAP_MODULE = "verify-provider-quarantine.mjs";

export function assertAstProductionModules({
  boundaries,
  expectedExports,
  expectedImportDigests,
  localCapabilityOwnerDigests,
  localCapabilityOwners,
  sources,
}) {
  assertExactKeys("production source", sources.keys(), Object.keys(expectedExports));
  assertExactKeys(
    "production import",
    Object.keys(expectedImportDigests),
    Object.keys(expectedExports),
  );
  assertExactKeys(
    "local capability owner digest",
    Object.keys(localCapabilityOwnerDigests),
    Object.keys(localCapabilityOwners),
  );
  for (const [key, expected] of Object.entries(localCapabilityOwners)) {
    if (expected.some((capability) => !isReviewedLocalCapability(capability))) {
      throw new Error(`local capability owner contains a forbidden effect: ${key}`);
    }
  }
  const effectModules = new Set(boundaries.map(({ module }) => module));
  const modules = new Map();
  for (const [filename, expected] of Object.entries(expectedExports)) {
    const program = parseQuarantineModule(filename, sources.get(filename));
    if (effectModules.has(filename)) {
      assertEffectModuleScope(filename, program, collectTopLevelFunctionNodes(program));
    }
    assertStaticProductionImports(filename, program, expectedExports);
    assertExactModuleExports(filename, program, expected);
    const importDigest = canonicalImportDigest(filename, program);
    if (importDigest !== expectedImportDigests[filename]) {
      throw new Error(
        `production module import inventory drift: ${filename}; actual=${importDigest}; ` +
          `imports=${JSON.stringify(canonicalImportInventory(filename, program))}`,
      );
    }
    modules.set(
      filename,
      buildModule(
        filename,
        program,
        expectedExports,
        localCapabilityOwners,
        localCapabilityOwnerDigests,
      ),
    );
  }
  const graph = combineGraphs(modules);
  materializeCallableExportAliases(modules, graph);
  const guarded = new Set([
    ...boundaries.map(({ module, symbol }) => `${module}#${symbol}`),
    `${TRUSTED_BOOTSTRAP_MODULE}#<module>`,
  ]);
  assertCapabilityOwnership(
    modules,
    graph,
    guarded,
    localCapabilityOwners,
    localCapabilityOwnerDigests,
    effectModules,
  );
}

function collectTopLevelFunctionNodes(program) {
  return new Set(collectTopLevelFunctions("reviewed-effect-module", program).values());
}

function assertStaticProductionImports(filename, program, expectedExports) {
  for (const statement of program.body) {
    if (
      statement.type === "ExportNamedDeclaration" &&
      statement.source !== null &&
      !statement.source.value.startsWith("./")
    ) {
      throw new Error(`production script uses an unclassified re-export source: ${filename}`);
    }
    if (
      statement.type === "ImportDeclaration" &&
      !statement.source.value.startsWith("./") &&
      !REVIEWED_NODE_MODULES.has(statement.source.value) &&
      !["eslint-scope", "espree"].includes(statement.source.value)
    ) {
      throw new Error(`production script imports an unclassified external module: ${filename}`);
    }
    if (
      statement.type === "ImportDeclaration" &&
      statement.source.value.startsWith("./") &&
      statement.specifiers.some((specifier) =>
        ["ImportDefaultSpecifier", "ImportNamespaceSpecifier"].includes(specifier.type),
      )
    ) {
      throw new Error(`production script uses an unresolved relative import form: ${filename}`);
    }
    if (
      (statement.type === "ImportDeclaration" ||
        (statement.type === "ExportNamedDeclaration" && statement.source !== null)) &&
      statement.source.value.startsWith("./test-")
    ) {
      throw new Error(`production script imports a test-only module: ${filename}`);
    }
    if (
      (statement.type === "ImportDeclaration" ||
        (statement.type === "ExportNamedDeclaration" && statement.source !== null)) &&
      statement.source.value.startsWith(".")
    ) {
      exactRelativeTarget(filename, statement.source.value, expectedExports);
    }
  }
  const nodes = astNodes(program);
  const dynamicImports = nodes.filter((node) => node.type === "ImportExpression");
  if (
    (filename === TRUSTED_BOOTSTRAP_MODULE &&
      (dynamicImports.length !== 1 ||
        !isExactTrustedBootstrapImport(filename, dynamicImports[0]))) ||
    (filename !== TRUSTED_BOOTSTRAP_MODULE && dynamicImports.length !== 0)
  ) {
    throw new Error(`production script uses an unclassified dynamic import: ${filename}`);
  }
  for (const node of nodes) {
    if (
      node.type === "CallExpression" &&
      node.callee.type === "Identifier" &&
      node.callee.name === "require"
    ) {
      throw new Error(`production script uses an unclassified require call: ${filename}`);
    }
  }
}

function isExactTrustedBootstrapImport(filename, node) {
  return (
    filename === TRUSTED_BOOTSTRAP_MODULE &&
    node.source.type === "Literal" &&
    node.source.value === "./provider-quarantine-policy.mjs"
  );
}

function buildModule(
  filename,
  program,
  expectedExports,
  localCapabilityOwners,
  localCapabilityOwnerDigests,
) {
  const moduleKey = `${filename}#<module>`;
  const functions = collectTopLevelFunctions(filename, program);
  const imports = collectImportBindings(filename, program, expectedExports);
  const lexicalReferences = buildLexicalReferenceIndex(program);
  const moduleDigest = localCapabilityOwnerDigests[moduleKey];
  if (moduleDigest !== undefined && normalizedAstDigest(program, createHash) !== moduleDigest) {
    throw new Error(`local capability owner AST drift: ${moduleKey}`);
  }
  const nodes = new Map([
    [
      moduleKey,
      analyzeCapabilityRegion({
        expectedExports,
        functions,
        imports,
        key: moduleKey,
        lexicalReferences,
        root: program,
        skipped: new Set(functions.values()),
      }),
    ],
  ]);
  for (const [name, declaration] of functions) {
    const key = `${filename}#${name}`;
    const reviewedDigest = localCapabilityOwnerDigests[key];
    if (
      reviewedDigest !== undefined &&
      normalizedAstDigest(declaration, createHash) !== reviewedDigest
    ) {
      throw new Error(`local capability owner AST drift: ${key}`);
    }
    nodes.set(
      key,
      analyzeCapabilityRegion({
        allowReviewedPureTaintedMethods: Object.hasOwn(localCapabilityOwners, key),
        expectedExports,
        functions,
        imports,
        key,
        lexicalReferences,
        root: declaration,
      }),
    );
  }
  return {
    exportAliases: collectExportAliases(filename, program, functions, imports, expectedExports),
    exportedFunctionKeys: collectDirectExportedFunctionKeys(filename, program, functions),
    filename,
    moduleKey,
    nodes,
    program,
  };
}

function collectTopLevelFunctions(filename, program) {
  const functions = new Map();
  for (const statement of program.body) {
    const declaration =
      statement.type === "ExportNamedDeclaration" ? statement.declaration : statement;
    if (declaration?.type === "FunctionDeclaration" && declaration.id !== null) {
      addFunction(functions, filename, declaration.id.name, declaration);
    }
    if (declaration?.type === "VariableDeclaration") {
      for (const item of declaration.declarations) {
        if (
          item.id.type === "Identifier" &&
          (item.init?.type === "ArrowFunctionExpression" ||
            item.init?.type === "FunctionExpression")
        ) {
          addFunction(functions, filename, item.id.name, item.init);
        }
      }
    }
  }
  return functions;
}

function addFunction(functions, filename, name, declaration) {
  if (functions.has(name)) throw new Error(`duplicate top-level function: ${filename}#${name}`);
  functions.set(name, declaration);
}

function collectImportBindings(filename, program, expectedExports) {
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
      if (statement.source.value.startsWith("./") && imported !== "*") {
        assertRelativeExportExists(filename, statement.source.value, imported, expectedExports);
      }
      imports.set(specifier.local.name, { imported, source: statement.source.value });
    }
  }
  return imports;
}

function collectDirectExportedFunctionKeys(filename, program, functions) {
  const keys = new Set();
  for (const symbol of collectModuleExports(filename, program)) {
    if (functions.has(symbol)) keys.add(`${filename}#${symbol}`);
  }
  return keys;
}

function collectExportAliases(filename, program, functions, imports, expectedExports) {
  const aliases = new Map();
  for (const statement of program.body) {
    if (statement.type !== "ExportNamedDeclaration" || statement.declaration !== null) continue;
    for (const specifier of statement.specifiers) {
      if (specifier.local.type !== "Identifier" || specifier.exported.type !== "Identifier")
        continue;
      const alias = `${filename}#${specifier.exported.name}`;
      const imported = imports.get(specifier.local.name);
      let target = null;
      if (statement.source?.value.startsWith("./")) {
        const targetFilename = assertRelativeExportExists(
          filename,
          statement.source.value,
          specifier.local.name,
          expectedExports,
        );
        target = `${targetFilename}#${specifier.local.name}`;
      } else if (statement.source === null && functions.has(specifier.local.name)) {
        target = `${filename}#${specifier.local.name}`;
      } else if (statement.source === null && imported?.source.startsWith("./")) {
        const targetFilename = assertRelativeExportExists(
          filename,
          imported.source,
          imported.imported,
          expectedExports,
        );
        target = `${targetFilename}#${imported.imported}`;
      }
      if (target !== null && target !== alias) aliases.set(alias, target);
    }
  }
  return aliases;
}

function assertRelativeExportExists(filename, source, imported, expectedExports) {
  const target = exactRelativeTarget(filename, source, expectedExports);
  if (typeof imported !== "string" || !expectedExports[target].includes(imported)) {
    throw new Error(
      `production relative binding escapes export inventory: ${filename} -> ${source}`,
    );
  }
  return target;
}

function exactRelativeTarget(filename, source, expectedExports) {
  if (!/^\.\/[A-Za-z0-9-]+\.mjs$/u.test(source)) {
    throw new Error(
      `production relative import escapes scripts inventory: ${filename} -> ${source}`,
    );
  }
  const target = source.slice(2);
  if (!Object.hasOwn(expectedExports, target)) {
    throw new Error(`production relative import target is unclassified: ${filename} -> ${source}`);
  }
  return target;
}

function assertExactKeys(label, actualIterable, expectedIterable) {
  const actual = [...actualIterable].sort();
  const expected = [...expectedIterable].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected))
    throw new Error(`${label} inventory drift`);
}
