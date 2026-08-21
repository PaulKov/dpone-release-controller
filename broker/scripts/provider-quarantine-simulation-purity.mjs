import { createHash } from "node:crypto";

import { astNodes } from "./provider-quarantine-ast-core.mjs";
import { buildLexicalReferenceIndex } from "./provider-quarantine-ast-lexical.mjs";
import { bindingNames, regionEntries } from "./provider-quarantine-ast-utils.mjs";
import { assertSimulationProgramShell } from "./provider-quarantine-simulation-program.mjs";

const FORBIDDEN_IDENTIFIERS = new Set([
  "Buffer",
  "Bun",
  "Deno",
  "EventSource",
  "WebSocket",
  "XMLHttpRequest",
  "document",
  "fetch",
  "globalThis",
  "navigator",
  "process",
  "require",
  "window",
]);
const INTRINSIC_BINDINGS = new Set([
  "Array",
  "Date",
  "Error",
  "JSON",
  "Number",
  "Object",
  "RegExp",
  "Set",
]);
const PURE_STATIC_CALLS = new Set([
  "Array.isArray",
  "Date.parse",
  "JSON.parse",
  "JSON.stringify",
  "Number.isFinite",
  "Number.isSafeInteger",
  "Object.freeze",
  "Object.fromEntries",
]);
const METHODS_BY_RECEIVER = Object.freeze({
  array: new Set(["at", "includes", "map", "push"]),
  regexp: new Set(["test"]),
  set: new Set(["add", "has"]),
  validatedJsonArray: new Set(["at", "map"]),
});
const REVIEWED_METHODS = new Set(
  Object.values(METHODS_BY_RECEIVER).flatMap((methods) => [...methods]),
);

/** Prove exact simulation functions and every callable receiver before accepting test models. */
export function assertPureSimulationPrograms(programs, expectedDigests) {
  const actualDigests = {};
  for (const [filename, program] of programs) {
    assertSimulationProgramShell(filename, program);
    const functions = collectTopLevelFunctions(filename, program);
    const lexical = buildLexicalReferenceIndex(program);
    const ownerByNode = indexFunctionOwners(program, functions);
    assertNoIntrinsicShadowing(filename, program);
    assertPureProgram(filename, program, functions, lexical, ownerByNode);
    for (const [name, declaration] of functions) {
      actualDigests[`${filename}#${name}`] = normalizedAstDigest(declaration);
    }
  }
  assertExactDigestMap(actualDigests, expectedDigests);
}

function assertPureProgram(filename, program, functions, lexical, ownerByNode) {
  const localFunctions = new Set(functions.keys());
  const reviewedCallBindings = new Set();
  for (const declaration of functions.values()) {
    const binding = declaration.id === null ? undefined : lexical.bindings.get(declaration.id);
    if (binding !== undefined) reviewedCallBindings.add(binding);
  }
  for (const statement of program.body) {
    if (statement.type !== "ImportDeclaration") continue;
    for (const specifier of statement.specifiers) {
      const binding = lexical.bindings.get(specifier.local);
      if (binding !== undefined) reviewedCallBindings.add(binding);
    }
  }
  const topLevelFunctions = new Set(functions.values());
  for (const { node, parent } of regionEntries(program)) {
    if (node.type === "Identifier" && FORBIDDEN_IDENTIFIERS.has(node.name)) {
      throw new Error(`provider simulation references a forbidden capability: ${filename}`);
    }
    if (node.type === "ImportExpression" || node.type === "TaggedTemplateExpression") {
      throw new Error(`provider simulation imports or invokes an effect capability: ${filename}`);
    }
    if (node.type === "FunctionExpression") {
      throw new Error(
        `provider simulation contains an unreviewed function expression: ${filename}`,
      );
    }
    if (node.type === "FunctionDeclaration" && !topLevelFunctions.has(node)) {
      throw new Error(`provider simulation contains a nested helper: ${filename}`);
    }
    if (node.type === "ArrowFunctionExpression" && !isDirectMapCallback(node, parent)) {
      throw new Error(`provider simulation contains an unreviewed callback: ${filename}`);
    }
    if (node.type === "MemberExpression") assertNoMemberAlias(filename, node, parent);
    if (node.type === "NewExpression") assertPureConstructor(filename, node, lexical);
    if (node.type === "CallExpression") {
      assertPureCall(
        filename,
        node,
        localFunctions,
        reviewedCallBindings,
        lexical,
        ownerByNode.get(node),
      );
    }
  }
}

function assertPureCall(filename, call, localFunctions, reviewedCallBindings, lexical, owner) {
  if (call.optional === true)
    throw new Error(`provider simulation uses an optional call: ${filename}`);
  if (call.callee.type === "Identifier") {
    if (!reviewedCallBindings.has(lexical.bindings.get(call.callee))) {
      throw new Error(`provider simulation invokes an unreviewed function: ${filename}`);
    }
    return;
  }
  if (
    call.callee.type !== "MemberExpression" ||
    call.callee.optional === true ||
    call.callee.computed
  ) {
    throw new Error(`provider simulation invokes an unreviewed capability: ${filename}`);
  }
  const pair = staticMemberPair(call.callee);
  if (PURE_STATIC_CALLS.has(pair)) {
    if (!isUnshadowedGlobal(call.callee.object, lexical)) {
      throw new Error(`provider simulation shadows an intrinsic receiver: ${filename}`);
    }
    return;
  }
  const method = call.callee.property.name;
  const receiver = receiverKind(call.callee.object, lexical, owner);
  if (!METHODS_BY_RECEIVER[receiver]?.has(method)) {
    throw new Error(`provider simulation invokes an unreviewed member receiver: ${filename}`);
  }
  if (method === "map") {
    assertPureCallbackArguments(
      filename,
      call.arguments,
      localFunctions,
      reviewedCallBindings,
      lexical,
    );
  }
}

function receiverKind(expression, lexical, owner) {
  if (expression.type === "ArrayExpression") return "array";
  if (expression.type === "Literal" && expression.regex !== undefined) return "regexp";
  if (expression.type !== "Identifier") return null;
  const variable = lexical.bindings.get(expression);
  const definition = variable?.defs.length === 1 ? variable.defs[0] : null;
  if (definition?.type === "Parameter") {
    return owner === "requireExactRoles" && expression.name === "workers"
      ? "validatedJsonArray"
      : null;
  }
  const initializer = definition?.type === "Variable" ? definition.node.init : null;
  if (initializer?.type === "ArrayExpression") return "array";
  if (initializer?.type === "Literal" && initializer.regex !== undefined) return "regexp";
  if (isUnshadowedSetConstruction(initializer, lexical)) return "set";
  if (isFrozenArray(initializer, lexical)) return "array";
  if (
    owner === "simulateBootstrap" &&
    initializer?.type === "CallExpression" &&
    initializer.callee.type === "Identifier" &&
    initializer.callee.name === "requireExactRoles"
  ) {
    return "validatedJsonArray";
  }
  return null;
}

function assertPureConstructor(filename, expression, lexical) {
  if (
    expression.callee.type !== "Identifier" ||
    !["Error", "Set"].includes(expression.callee.name) ||
    !isUnshadowedGlobal(expression.callee, lexical)
  ) {
    throw new Error(`provider simulation invokes an unreviewed constructor: ${filename}`);
  }
}

function assertPureCallbackArguments(
  filename,
  arguments_,
  localFunctions,
  reviewedCallBindings,
  lexical,
) {
  const callback = arguments_[0];
  if (
    callback?.type !== "ArrowFunctionExpression" &&
    !(
      callback?.type === "Identifier" &&
      localFunctions.has(callback.name) &&
      reviewedCallBindings.has(lexical.bindings.get(callback))
    )
  ) {
    throw new Error(`provider simulation accepts an unreviewed callback: ${filename}`);
  }
}

function assertNoMemberAlias(filename, member, parent) {
  const method = memberName(member);
  if (
    REVIEWED_METHODS.has(method) &&
    !(parent?.type === "CallExpression" && parent.callee === member)
  ) {
    throw new Error(`provider simulation escapes a callable member: ${filename}`);
  }
}

function assertNoIntrinsicShadowing(filename, program) {
  for (const node of astNodes(program)) {
    const bindings =
      node.type === "VariableDeclarator"
        ? bindingNames(node.id)
        : node.type === "ImportDeclaration"
          ? node.specifiers.map((specifier) => specifier.local.name)
          : ["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"].includes(
                node.type,
              )
            ? [
                ...(node.id === null || node.id === undefined ? [] : [node.id.name]),
                ...node.params.flatMap(bindingNames),
              ]
            : node.type === "CatchClause"
              ? bindingNames(node.param)
              : [];
    if (bindings.some((name) => INTRINSIC_BINDINGS.has(name))) {
      throw new Error(`provider simulation shadows an intrinsic binding: ${filename}`);
    }
    if (
      (node.type === "AssignmentExpression" || node.type === "UpdateExpression") &&
      bindingNames(node.type === "AssignmentExpression" ? node.left : node.argument).some((name) =>
        INTRINSIC_BINDINGS.has(name),
      )
    ) {
      throw new Error(`provider simulation reassigns an intrinsic binding: ${filename}`);
    }
  }
}

function collectTopLevelFunctions(filename, program) {
  const functions = new Map();
  for (const statement of program.body) {
    const declaration =
      statement.type === "ExportNamedDeclaration" ? statement.declaration : statement;
    if (declaration?.type === "FunctionDeclaration" && declaration.id !== null) {
      if (functions.has(declaration.id.name)) {
        throw new Error(`provider simulation duplicates a helper: ${filename}`);
      }
      functions.set(declaration.id.name, declaration);
    }
    if (
      declaration?.type === "VariableDeclaration" &&
      declaration.declarations.some((item) =>
        ["ArrowFunctionExpression", "FunctionExpression"].includes(item.init?.type),
      )
    ) {
      throw new Error(`provider simulation uses an unreviewed callable binding: ${filename}`);
    }
  }
  return functions;
}

function indexFunctionOwners(program, functions) {
  const owners = new WeakMap();
  const names = new Map([...functions].map(([name, node]) => [node, name]));
  visit(program, null);
  return owners;

  function visit(node, owner) {
    if (node === null || typeof node !== "object" || typeof node.type !== "string") return;
    const current = names.get(node) ?? owner;
    owners.set(node, current);
    for (const [key, value] of Object.entries(node)) {
      if (["comments", "end", "loc", "range", "start", "tokens"].includes(key)) continue;
      if (Array.isArray(value)) for (const child of value) visit(child, current);
      else visit(value, current);
    }
  }
}

function isDirectMapCallback(node, parent) {
  return (
    parent?.type === "CallExpression" &&
    parent.arguments.includes(node) &&
    parent.callee.type === "MemberExpression" &&
    !parent.callee.computed &&
    parent.callee.property.type === "Identifier" &&
    parent.callee.property.name === "map"
  );
}

function isFrozenArray(expression, lexical) {
  return (
    expression?.type === "CallExpression" &&
    expression.callee.type === "MemberExpression" &&
    staticMemberPair(expression.callee) === "Object.freeze" &&
    isUnshadowedGlobal(expression.callee.object, lexical) &&
    expression.arguments.length === 1 &&
    expression.arguments[0]?.type === "ArrayExpression"
  );
}

function isUnshadowedSetConstruction(expression, lexical) {
  return (
    expression?.type === "NewExpression" &&
    expression.callee.type === "Identifier" &&
    expression.callee.name === "Set" &&
    isUnshadowedGlobal(expression.callee, lexical)
  );
}

function isUnshadowedGlobal(identifier, lexical) {
  return identifier.type === "Identifier" && lexical.unresolved.has(identifier);
}

function memberName(member) {
  if (!member.computed && member.property.type === "Identifier") return member.property.name;
  return member.computed && member.property.type === "Literal" ? member.property.value : null;
}

function staticMemberPair(member) {
  return member.object.type === "Identifier" && member.property.type === "Identifier"
    ? `${member.object.name}.${member.property.name}`
    : "";
}

function normalizedAstDigest(node) {
  const canonical = JSON.stringify(node, (key, value) =>
    ["comments", "end", "loc", "range", "raw", "start", "tokens"].includes(key) ? undefined : value,
  );
  return createHash("sha256").update(canonical).digest("hex");
}

function assertExactDigestMap(actual, expected) {
  const actualKeys = Object.keys(actual).sort();
  const expectedKeys = Object.keys(expected).sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
    throw new Error("provider simulation function inventory drift");
  }
  for (const key of expectedKeys) {
    if (actual[key] !== expected[key]) {
      throw new Error(`provider simulation function AST drift: ${key}`);
    }
  }
}
