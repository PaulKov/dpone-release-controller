import { analyze as analyzeScopes, version as eslintScopeVersion } from "eslint-scope";

import {
  bindingNames,
  isFunction,
  memberProperty,
  regionEntries,
  unwrapChain,
} from "./provider-quarantine-ast-utils.mjs";

if (eslintScopeVersion !== "9.1.2") {
  throw new Error("provider quarantine requires eslint-scope 9.1.2");
}

const AMBIENT_ROOTS = new Set(["globalThis", "process"]);
const REVIEWED_INTRINSICS = new Set([
  "Array",
  "Buffer",
  "Date",
  "Error",
  "JSON",
  "Map",
  "Math",
  "Number",
  "Object",
  "Promise",
  "RegExp",
  "Set",
  "String",
  "TypeError",
  "URL",
  "Uint8Array",
  "WeakMap",
  "WeakSet",
]);
const PROCESS_LOADERS = new Set([
  "_linkedBinding",
  "binding",
  "dlopen",
  "getBuiltinModule",
  "mainModule",
  "require",
]);

/** Build binding-identity references. Names alone are never accepted as provenance. */
export function buildLexicalReferenceIndex(program) {
  const manager = analyzeScopes(program, {
    ecmaVersion: 2026,
    ignoreEval: false,
    optimistic: false,
    sourceType: "module",
  });
  const bindings = new WeakMap();
  const unresolved = new WeakSet();
  for (const scope of manager.scopes) {
    for (const variable of scope.variables) {
      for (const identifier of variable.identifiers) bindings.set(identifier, variable);
    }
    for (const reference of scope.references) {
      if (reference.resolved === null) unresolved.add(reference.identifier);
      else bindings.set(reference.identifier, reference.resolved);
    }
  }
  return Object.freeze({ bindings, unresolved });
}

/** Resolve caller-owned and ambient origins through aliases and destructuring to a fixed point. */
export function buildRegionValueFlow(root, lexical) {
  const entries = regionEntries(root);
  const originsByBinding = new Map();
  seedCallableBindings(entries, lexical, originsByBinding);
  seedCallableInputs(root, lexical, originsByBinding);
  let changed = true;
  while (changed) {
    changed = false;
    for (const { node } of entries) {
      const flow = assignmentFlow(node);
      if (flow === null) continue;
      const sourceOrigins = originsForExpression(flow.source);
      if (sourceOrigins.size === 0) continue;
      changed = addPatternOrigins(flow.target, sourceOrigins, lexical, originsByBinding) || changed;
    }
  }
  return Object.freeze({
    callerRoot(expression) {
      return callerRoot(expression, originsForExpression);
    },
    origins: originsForExpression,
  });

  function originsForExpression(expression, active = new Set()) {
    const node = expression === null || expression === undefined ? null : unwrapChain(expression);
    if (node === null || active.has(node)) return new Set();
    active.add(node);
    let result;
    if (node.type === "Identifier") {
      result = identifierOrigins(node, lexical, originsByBinding);
    } else if (node.type === "ThisExpression") {
      result = new Set(["caller"]);
    } else if (isFunction(node) || /ClassExpression$/u.test(node.type)) {
      result = new Set(["callable"]);
    } else if (node.type === "MemberExpression") {
      result = projectOrigins(
        originsForExpression(node.object, active),
        memberProperty(node),
        node.computed,
      );
    } else if (node.type === "CallExpression" || node.type === "NewExpression") {
      result = callResultOrigins(node, originsForExpression, active);
    } else {
      result = childOrigins(node, originsForExpression, active);
    }
    active.delete(node);
    return result;
  }
}

function seedCallableBindings(entries, lexical, originsByBinding) {
  for (const { node } of entries) {
    if (isFunction(node) && node.id?.type === "Identifier") {
      addBindingOrigin(node.id, "callable", lexical, originsByBinding);
    }
    if (
      node.type === "VariableDeclarator" &&
      (isFunctionNode(node.init) || node.init?.type === "ClassExpression")
    ) {
      for (const name of bindingNames(node.id)) {
        const identifier = bindingIdentifier(node.id, name);
        if (identifier !== null)
          addBindingOrigin(identifier, "callable", lexical, originsByBinding);
      }
    }
  }
}

function isFunctionNode(node) {
  return node !== null && node !== undefined && isFunction(node);
}

function seedCallableInputs(root, lexical, originsByBinding) {
  if (!isFunction(root)) return;
  for (const parameter of root.params) {
    for (const name of bindingNames(parameter)) {
      const identifier = bindingIdentifier(parameter, name);
      if (identifier !== null) addBindingOrigin(identifier, "caller", lexical, originsByBinding);
    }
  }
}

function assignmentFlow(node) {
  if (node.type === "VariableDeclarator") return { source: node.init, target: node.id };
  if (node.type === "AssignmentExpression") return { source: node.right, target: node.left };
  if (node.type === "ForInStatement" || node.type === "ForOfStatement") {
    const target =
      node.left.type === "VariableDeclaration" ? node.left.declarations[0]?.id : node.left;
    return { source: node.right, target };
  }
  if (node.type === "AssignmentPattern") {
    return { source: node.right, target: node.left };
  }
  return null;
}

function addPatternOrigins(pattern, origins, lexical, originsByBinding) {
  if (pattern === null || pattern === undefined) return false;
  if (pattern.type === "Identifier") {
    return addOrigins(lexical.bindings.get(pattern), origins, originsByBinding);
  }
  if (pattern.type === "AssignmentPattern" || pattern.type === "RestElement") {
    return addPatternOrigins(pattern.left ?? pattern.argument, origins, lexical, originsByBinding);
  }
  if (pattern.type === "ArrayPattern") {
    return pattern.elements.reduce(
      (changed, item) =>
        addPatternOrigins(item, projectOrigins(origins, null, true), lexical, originsByBinding) ||
        changed,
      false,
    );
  }
  if (pattern.type !== "ObjectPattern") return false;
  let changed = false;
  for (const property of pattern.properties) {
    const target = property.type === "RestElement" ? property.argument : property.value;
    const key = property.type === "RestElement" ? null : propertyName(property);
    const projected = ["__proto__", "constructor", "prototype"].includes(key)
      ? new Set(["dynamic-code"])
      : projectOrigins(origins, key, key === null);
    changed = addPatternOrigins(target, projected, lexical, originsByBinding) || changed;
  }
  return changed;
}

function identifierOrigins(identifier, lexical, originsByBinding) {
  if (identifier.name === "arguments") return new Set(["caller"]);
  const binding = lexical.bindings.get(identifier);
  if (binding !== undefined) return new Set(originsByBinding.get(binding) ?? []);
  if (!lexical.unresolved.has(identifier)) return new Set();
  if (AMBIENT_ROOTS.has(identifier.name)) return new Set([`ambient:${identifier.name}`]);
  if (REVIEWED_INTRINSICS.has(identifier.name)) return new Set([`intrinsic:${identifier.name}`]);
  if (identifier.name === "undefined") return new Set();
  return new Set([`free:${identifier.name}`]);
}

function projectOrigins(origins, property, computed) {
  const projected = new Set();
  for (const origin of origins) {
    if (origin === "caller") projected.add("caller");
    else if (origin === "callable") projected.add(computed ? "dynamic-code" : "callable-member");
    else if (origin === "callable-member") projected.add("dynamic-code");
    else if (origin === "intrinsic:Object" && property === "constructor")
      projected.add("dynamic-code");
    else if (origin === "ambient:process" && PROCESS_LOADERS.has(property))
      projected.add("builtin-loader");
    else if (origin.startsWith("ambient:")) {
      projected.add(`${origin}.${computed || property === null ? "?" : property}`);
    } else if (origin.startsWith("intrinsic:") || origin.startsWith("free:")) {
      projected.add(origin);
    } else if (["builtin-loader", "capability-result", "dynamic-code"].includes(origin)) {
      projected.add("capability-result");
    }
  }
  return projected;
}

function callResultOrigins(node, originsForExpression, active) {
  const origins = originsForExpression(node.callee, active);
  const result = new Set();
  if (
    [...origins].some(
      (origin) =>
        origin === "builtin-loader" ||
        origin === "callable-member" ||
        origin === "capability-result" ||
        origin === "dynamic-code" ||
        origin.startsWith("ambient:") ||
        origin.startsWith("free:"),
    )
  ) {
    result.add("capability-result");
  }
  if (origins.has("caller")) result.add("caller");
  for (const argument of node.arguments) {
    const value = argument.type === "SpreadElement" ? argument.argument : argument;
    if (originsForExpression(value, active).has("caller")) {
      result.add("caller");
    }
  }
  return result;
}

function childOrigins(node, originsForExpression, active) {
  const origins = new Set();
  for (const [key, value] of Object.entries(node)) {
    if (["comments", "end", "loc", "range", "raw", "start", "tokens", "type"].includes(key))
      continue;
    const children = Array.isArray(value) ? value : [value];
    for (const child of children) {
      if (child !== null && typeof child === "object" && typeof child.type === "string") {
        for (const origin of originsForExpression(child, active)) origins.add(origin);
      }
    }
  }
  return origins;
}

function callerRoot(expression, originsForExpression) {
  let current = unwrapChain(expression);
  while (current.type === "MemberExpression") current = unwrapChain(current.object);
  if (!originsForExpression(current).has("caller")) return null;
  return current.type === "Identifier"
    ? current.name
    : current.type === "ThisExpression"
      ? "this"
      : "caller";
}

function addBindingOrigin(identifier, origin, lexical, originsByBinding) {
  return addOrigins(lexical.bindings.get(identifier), new Set([origin]), originsByBinding);
}

function addOrigins(binding, origins, originsByBinding) {
  if (binding === undefined) return false;
  const current = originsByBinding.get(binding) ?? new Set();
  const before = current.size;
  for (const origin of origins) current.add(origin);
  originsByBinding.set(binding, current);
  return current.size !== before;
}

function bindingIdentifier(pattern, name) {
  if (pattern?.type === "Identifier") return pattern.name === name ? pattern : null;
  for (const { node } of regionEntries(pattern)) {
    if (node.type === "Identifier" && node.name === name) return node;
  }
  return null;
}

function propertyName(property) {
  if (!property.computed && property.key.type === "Identifier") return property.key.name;
  return property.key.type === "Literal" && typeof property.key.value === "string"
    ? property.key.value
    : null;
}
