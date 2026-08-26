import { createHash } from "node:crypto";

import {
  assertExactModuleExports,
  assertUnshadowedNamedImport,
  astNodes,
  findDirectExportedFunction,
  parseQuarantineModule,
} from "./provider-quarantine-ast-core.mjs";
import { assertExactEffectDataExports } from "./provider-quarantine-effect-data.mjs";

const HOLD_MODULE = "./provider-mutation-hold.mjs";
const HOLD_SYMBOL = "assertProviderMutationReleased";
const HOLD_FILENAME = "provider-mutation-hold.mjs";
const HOLD_EXPORTS = Object.freeze([
  "PROVIDER_MUTATION_BOUNDARIES",
  "PROVIDER_MUTATION_ENTRYPOINTS",
  "PROVIDER_MUTATION_HOLD_CODE",
  "PROVIDER_MUTATION_HOLD_MARKER",
  HOLD_SYMBOL,
]);
const HOLD_FUNCTION_AST_SHA256 = "8ddf4923bc41d16d399ae7496fe18946c0ff003c87dcfe400ba7b2a92ba0e971";
const HOLD_PROGRAM_AST_SHA256 = "186d27269dca7ad266fd850fb42dd240a998bb08434a73ce9e7ac1a880632aa1";

/** Prove every inventoried mutation boundary reaches the real HOLD first. */
export function assertAstProviderBoundaries(boundaries, entrypoints, effectExports, sources) {
  assertHoldImplementation(sources.get(HOLD_FILENAME));
  const programs = new Map();
  for (const [filename, expected] of Object.entries(effectExports)) {
    const program = parseQuarantineModule(filename, sources.get(filename));
    assertExactModuleExports(filename, program, expected);
    programs.set(filename, program);
  }
  const actualEntrypoints = [...new Set(boundaries.map(({ entrypoint }) => entrypoint))].sort();
  if (JSON.stringify(actualEntrypoints) !== JSON.stringify([...entrypoints].sort())) {
    throw new Error("provider mutation HOLD inventory differs from executable boundaries");
  }
  const keys = boundaries.map(({ module, symbol }) => `${module}#${symbol}`);
  if (new Set(keys).size !== keys.length) {
    throw new Error("provider mutation boundary inventory contains duplicates");
  }
  const boundaryByKey = new Map(
    boundaries.map((boundary) => [`${boundary.module}#${boundary.symbol}`, boundary]),
  );
  const callableKeys = effectCallableKeys(programs);
  if (JSON.stringify(callableKeys.sort()) !== JSON.stringify([...keys].sort())) {
    throw new Error(
      "provider runtime callable exports differ from the exact HOLD boundary inventory",
    );
  }
  for (const boundary of boundaries) {
    assertBoundary(boundary, boundaryByKey, effectExports, programs);
  }
}

function effectCallableKeys(programs) {
  const keys = [];
  const dataKeys = assertExactEffectDataExports(programs);
  for (const [filename, program] of programs) {
    assertNoLocalCallableExportAliases(filename, program);
    for (const symbol of exportedSymbols(program)) {
      if (dataKeys.has(`${filename}#${symbol}`)) continue;
      if (resolvesToCallableExport(filename, symbol, programs, new Set())) {
        keys.push(`${filename}#${symbol}`);
      } else {
        throw new Error(
          `provider runtime export has no callable or exact-data class: ${filename}#${symbol}`,
        );
      }
    }
  }
  return keys;
}

function assertNoLocalCallableExportAliases(filename, program) {
  const callableNames = topLevelCallableNames(program);
  for (const statement of program.body) {
    if (statement.type !== "ExportNamedDeclaration") continue;
    if (
      statement.source === null &&
      statement.declaration === null &&
      statement.specifiers.length
    ) {
      throw new Error(`provider runtime uses a source-local export alias: ${filename}`);
    }
    const declaration = statement.declaration;
    if (declaration?.type === "ClassDeclaration") {
      throw new Error(`provider runtime exports an unsupported callable class: ${filename}`);
    }
    if (declaration?.type !== "VariableDeclaration") continue;
    for (const declarator of declaration.declarations) {
      if (
        isCallableExpression(declarator.init) ||
        (declarator.init?.type === "Identifier" && callableNames.has(declarator.init.name))
      ) {
        throw new Error(`provider runtime exports an unsupported callable binding: ${filename}`);
      }
    }
  }
}

function resolvesToCallableExport(filename, symbol, programs, seen) {
  const key = `${filename}#${symbol}`;
  if (seen.has(key)) throw new Error(`provider runtime callable re-export cycle: ${key}`);
  seen.add(key);
  const program = programs.get(filename);
  for (const statement of program.body) {
    if (statement.type !== "ExportNamedDeclaration") continue;
    const declaration = statement.declaration;
    if (declaration?.type === "FunctionDeclaration" && declaration.id.name === symbol) return true;
    if (declaration?.type === "VariableDeclaration") {
      const declarator = declaration.declarations.find((item) => item.id.name === symbol);
      if (declarator !== undefined) return isCallableExpression(declarator.init);
    }
    if (statement.source === null) continue;
    for (const specifier of statement.specifiers) {
      if (specifier.exported.name !== symbol) continue;
      const target = exactReexportTarget(filename, statement.source.value, programs);
      return resolvesToCallableExport(target, specifier.local.name, programs, seen);
    }
  }
  return false;
}

function exportedSymbols(program) {
  const symbols = [];
  for (const statement of program.body) {
    if (statement.type !== "ExportNamedDeclaration") continue;
    const declaration = statement.declaration;
    if (declaration?.type === "FunctionDeclaration" || declaration?.type === "ClassDeclaration") {
      symbols.push(declaration.id.name);
    } else if (declaration?.type === "VariableDeclaration") {
      for (const item of declaration.declarations) {
        if (item.id.type !== "Identifier") throw new Error("provider runtime export must be named");
        symbols.push(item.id.name);
      }
    }
    for (const specifier of statement.specifiers) symbols.push(specifier.exported.name);
  }
  return symbols;
}

function topLevelCallableNames(program) {
  const names = new Set();
  let changed = true;
  while (changed) {
    changed = false;
    for (const statement of program.body) {
      const declaration =
        statement.type === "ExportNamedDeclaration" ? statement.declaration : statement;
      if (
        (declaration?.type === "FunctionDeclaration" || declaration?.type === "ClassDeclaration") &&
        !names.has(declaration.id.name)
      ) {
        names.add(declaration.id.name);
        changed = true;
      }
      if (declaration?.type !== "VariableDeclaration") continue;
      for (const item of declaration.declarations) {
        if (
          item.id.type === "Identifier" &&
          (isCallableExpression(item.init) ||
            (item.init?.type === "Identifier" && names.has(item.init.name))) &&
          !names.has(item.id.name)
        ) {
          names.add(item.id.name);
          changed = true;
        }
      }
    }
  }
  return names;
}

function isCallableExpression(node) {
  return ["ArrowFunctionExpression", "ClassExpression", "FunctionExpression"].includes(node?.type);
}

function exactReexportTarget(filename, source, programs) {
  if (!/^\.\/[A-Za-z0-9-]+\.mjs$/u.test(source) || !programs.has(source.slice(2))) {
    throw new Error(`provider runtime re-export escapes effect inventory: ${filename}`);
  }
  return source.slice(2);
}

function assertHoldImplementation(source) {
  const program = parseQuarantineModule(HOLD_FILENAME, source);
  if (astDigest(program) !== HOLD_PROGRAM_AST_SHA256) {
    throw new Error("provider mutation HOLD Program AST drift");
  }
  assertExactModuleExports(HOLD_FILENAME, program, HOLD_EXPORTS);
  for (const node of astNodes(program)) {
    if (
      node.type === "ImportDeclaration" ||
      node.type === "ImportExpression" ||
      (node.type === "ExportNamedDeclaration" && node.source !== null)
    ) {
      throw new Error("provider mutation HOLD implementation must remain import-free");
    }
  }
  const declaration = findDirectExportedFunction(program, HOLD_SYMBOL);
  const finalStatement = declaration?.body.body.at(-1);
  const forbiddenControl = new Set([
    "DoWhileStatement",
    "ForInStatement",
    "ForOfStatement",
    "ForStatement",
    "IfStatement",
    "ReturnStatement",
    "SwitchStatement",
    "TryStatement",
    "WhileStatement",
    "WithStatement",
  ]);
  if (
    declaration === null ||
    declaration.async ||
    declaration.generator ||
    declaration.params.length !== 1 ||
    declaration.params[0]?.type !== "Identifier" ||
    declaration.params[0].name !== "entrypoint" ||
    finalStatement?.type !== "ThrowStatement" ||
    finalStatement.argument?.type !== "Identifier" ||
    finalStatement.argument.name !== "error" ||
    astNodes(declaration).some((node) => forbiddenControl.has(node.type)) ||
    astDigest(declaration) !== HOLD_FUNCTION_AST_SHA256
  ) {
    throw new Error("provider mutation HOLD implementation AST drift");
  }
}

function astDigest(node) {
  const canonical = JSON.stringify(node, (key, value) =>
    ["end", "loc", "range", "raw", "start"].includes(key) ? undefined : value,
  );
  return createHash("sha256").update(canonical).digest("hex");
}

function assertBoundary(boundary, boundaryByKey, effectExports, programs) {
  const { entrypoint, module, symbol } = boundary;
  if (!effectExports[module]?.includes(symbol)) {
    throw new Error(
      `provider mutation boundary is not an exact exported symbol: ${module}#${symbol}`,
    );
  }
  const program = programs.get(module);
  const declaration = findDirectExportedFunction(program, symbol);
  if (declaration === null) {
    assertGuardedReexport(boundary, boundaryByKey, program);
    return;
  }
  assertUnshadowedNamedImport(program, HOLD_SYMBOL, HOLD_SYMBOL, HOLD_MODULE);
  if (declaration.params.some((parameter) => parameter.type !== "Identifier")) {
    throw new Error(`provider mutation boundary has an effectful parameter: ${module}#${symbol}`);
  }
  const first = declaration.body.body[0];
  if (!isExactHoldStatement(first, entrypoint)) {
    throw new Error(`provider mutation boundary does not start with HOLD: ${module}#${symbol}`);
  }
}

function assertGuardedReexport(boundary, boundaryByKey, program) {
  const matches = [];
  for (const statement of program.body) {
    if (statement.type !== "ExportNamedDeclaration" || statement.source === null) continue;
    for (const specifier of statement.specifiers) {
      if (
        specifier.type === "ExportSpecifier" &&
        specifier.local.type === "Identifier" &&
        specifier.exported.type === "Identifier" &&
        specifier.local.name === boundary.symbol &&
        specifier.exported.name === boundary.symbol
      ) {
        matches.push(statement.source.value);
      }
    }
  }
  if (matches.length !== 1 || typeof matches[0] !== "string" || !matches[0].startsWith("./")) {
    throw new Error(
      `provider mutation boundary is not a direct guarded function: ${boundary.module}#${boundary.symbol}`,
    );
  }
  const target = matches[0].slice(2);
  const resolved = boundaryByKey.get(`${target}#${boundary.symbol}`);
  if (resolved?.entrypoint !== boundary.entrypoint) {
    throw new Error(
      `provider mutation re-export does not resolve to a guarded target: ${boundary.module}#${boundary.symbol}`,
    );
  }
}

function isExactHoldStatement(statement, entrypoint) {
  if (statement?.type !== "ExpressionStatement") return false;
  const call = statement.expression;
  return (
    call.type === "CallExpression" &&
    call.optional !== true &&
    call.callee.type === "Identifier" &&
    call.callee.name === HOLD_SYMBOL &&
    call.arguments.length === 1 &&
    call.arguments[0]?.type === "Literal" &&
    call.arguments[0].value === entrypoint
  );
}
