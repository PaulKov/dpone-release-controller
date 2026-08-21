import {
  isNonReferenceIdentifier,
  memberProperty,
  memberRoot,
  regionEntries,
  unwrapChain,
} from "./provider-quarantine-ast-utils.mjs";
import {
  GLOBAL_EFFECT_CONSTRUCTORS,
  GLOBAL_EFFECT_ROOTS,
  PROCESS_LOADER_METHODS,
  firstOrigin,
  importedCapability,
} from "./provider-quarantine-ast-effects.mjs";
import { buildRegionValueFlow } from "./provider-quarantine-ast-lexical.mjs";

export { buildLexicalReferenceIndex } from "./provider-quarantine-ast-lexical.mjs";

export function analyzeCapabilityRegion({
  expectedExports,
  functions,
  imports,
  key,
  lexicalReferences,
  root,
  skipped = new Set(),
}) {
  const edges = new Set();
  const capabilities = new Set();
  const capabilityCalls = [];
  const flow = buildRegionValueFlow(root, lexicalReferences);
  for (const { node, parent } of regionEntries(root, skipped)) {
    const referenced = resolveReferencedFunction(
      key,
      node,
      parent,
      functions,
      imports,
      expectedExports,
    );
    if (referenced !== null) edges.add(referenced);
    const reference = classifyCapabilityReference(node, parent, imports, flow);
    if (reference !== null) capabilities.add(reference);
    if (node.type === "ImportExpression") capabilities.add("dynamic-import");
    if (node.type === "TaggedTemplateExpression") capabilities.add("dynamic-tag-call");
    if (node.type === "NewExpression") {
      const capability = classifyConstructor(node, flow);
      if (capability !== null) capabilities.add(capability);
      const constructed = resolveCalledFunction(
        key,
        node.callee,
        functions,
        imports,
        expectedExports,
      );
      if (constructed !== null) edges.add(constructed);
    }
    if (node.type !== "CallExpression") continue;
    const capability = classifyCapabilityCall(node, imports, flow);
    if (capability !== null) {
      capabilities.add(capability);
      capabilityCalls.push({ capability, node });
    }
    const called = resolveCalledFunction(key, node.callee, functions, imports, expectedExports);
    if (called !== null) edges.add(called);
  }
  return { capabilities, capabilityCalls, edges, key };
}

function classifyCapabilityCall(call, imports, flow) {
  const callee = unwrapChain(call.callee);
  if (callee.type === "Identifier") {
    const imported = imports.get(callee.name);
    if (callee.name === "fetch") return "global-fetch";
    if (["eval", "Function", "require"].includes(callee.name)) {
      return `dynamic-code:${callee.name}`;
    }
    if (GLOBAL_EFFECT_CONSTRUCTORS.has(callee.name)) {
      return `global-effect-call:${callee.name}`;
    }
    if (GLOBAL_EFFECT_ROOTS.has(callee.name)) return `global-effect-call:${callee.name}`;
    const origins = flow.origins(callee);
    if (origins.has("caller")) return `injected-call:${callee.name}`;
    if (origins.has("builtin-loader")) return "builtin-module-loader";
    if (origins.has("dynamic-code") || origins.has("callable-member")) {
      return "dynamic-code:alias";
    }
    if (origins.has("capability-result")) return "capability-result-call";
    const ambient = firstOrigin(origins, "ambient:");
    if (ambient !== undefined) return `ambient-call:${ambient}`;
    if ([...origins].some((origin) => origin.startsWith("free:"))) {
      return `unresolved-free-call:${callee.name}`;
    }
    const intrinsic = firstOrigin(origins, "intrinsic:");
    if (intrinsic !== undefined && intrinsic !== `intrinsic:${callee.name}`) {
      return `intrinsic-alias-call:${intrinsic}`;
    }
    if (imported !== undefined) return importedCapability(imported);
    return null;
  }
  if (callee.type !== "MemberExpression") return "dynamic-call";
  const root = memberRoot(callee);
  const property = memberProperty(callee);
  if (["__proto__", "constructor", "prototype"].includes(property)) {
    return `dynamic-code-member:${property}`;
  }
  if (["apply", "bind", "call"].includes(property)) return "reflective-call";
  if (callee.computed) {
    if (root === "globalThis" && property === "fetch") return "global-fetch";
    return "computed-call";
  }
  const namespace = root === null ? undefined : imports.get(root);
  if (["*", "default"].includes(namespace?.imported) && property !== null) {
    return importedCapability({ imported: property, source: namespace.source });
  }
  if (root === "Reflect" && ["apply", "construct"].includes(property)) return "reflective-call";
  if (root === "process" && PROCESS_LOADER_METHODS.has(property)) {
    return "builtin-module-loader";
  }
  if (root === "globalThis" && property === "fetch") return "global-fetch";
  if (
    root === "globalThis" &&
    (GLOBAL_EFFECT_CONSTRUCTORS.has(property) || ["Bun", "Deno"].includes(property))
  ) {
    return `global-effect-call:globalThis.${property}`;
  }
  if (root === "globalThis" && PROCESS_LOADER_METHODS.has(property)) {
    return "builtin-module-loader";
  }
  if (GLOBAL_EFFECT_ROOTS.has(root)) return `global-effect-call:${root}.${property ?? "?"}`;
  if (root === "navigator" && property === "sendBeacon") return "global-network";
  const caller = flow.callerRoot(callee.object);
  if (caller !== null) return `injected-call:${caller}.${property ?? "?"}`;
  const objectOrigins = flow.origins(callee.object);
  if (objectOrigins.has("builtin-loader")) return "builtin-module-loader";
  if (objectOrigins.has("dynamic-code") || objectOrigins.has("callable-member")) {
    return "dynamic-code:alias";
  }
  if (objectOrigins.has("capability-result")) return "capability-result-call";
  const ambient = firstOrigin(objectOrigins, "ambient:");
  if (ambient !== undefined) return `ambient-call:${ambient}.${property ?? "?"}`;
  if ([...objectOrigins].some((origin) => origin.startsWith("free:"))) {
    return `unresolved-free-call:${root ?? "alias"}.${property ?? "?"}`;
  }
  const intrinsic = firstOrigin(objectOrigins, "intrinsic:");
  if (intrinsic !== undefined && root !== intrinsic.slice("intrinsic:".length)) {
    return `intrinsic-alias-call:${intrinsic}.${property ?? "?"}`;
  }
  return null;
}

function classifyCapabilityReference(node, parent, imports, flow) {
  if (node.type === "Identifier" && !isNonReferenceIdentifier(node, parent)) {
    if (
      ["CallExpression", "NewExpression"].includes(parent?.type) &&
      unwrapChain(parent.callee) === node
    ) {
      return null;
    }
    if (node.name === "fetch") return "capability-reference:global-fetch";
    if (["eval", "require"].includes(node.name)) {
      return `capability-reference:dynamic-code:${node.name}`;
    }
    if (GLOBAL_EFFECT_CONSTRUCTORS.has(node.name) || GLOBAL_EFFECT_ROOTS.has(node.name)) {
      return `capability-reference:global-effect:${node.name}`;
    }
    const imported = imports.get(node.name);
    const capability = imported === undefined ? null : importedCapability(imported);
    if (capability !== null) return `capability-reference:${capability}`;
    const origins = flow.origins(node);
    if (origins.has("caller")) {
      if (parent?.type === "MemberExpression" && parent.object === node) return null;
      return `injected-reference:${node.name}`;
    }
    const ambient = firstOrigin(origins, "ambient:");
    if (ambient !== undefined) {
      if (parent?.type === "MemberExpression" && parent.object === node) return null;
      return `ambient-reference:${ambient}`;
    }
    if (origins.has("builtin-loader")) return "capability-reference:builtin-module-loader";
    if (origins.has("dynamic-code") || origins.has("callable-member")) {
      return "capability-reference:dynamic-code:alias";
    }
    if (origins.has("capability-result")) return "capability-reference:capability-result";
    if ([...origins].some((origin) => origin.startsWith("free:"))) {
      return `unresolved-free-reference:${node.name}`;
    }
    const intrinsic = firstOrigin(origins, "intrinsic:");
    if (
      intrinsic !== undefined &&
      !(parent?.type === "MemberExpression" && parent.object === node)
    ) {
      return `intrinsic-reference:${intrinsic}`;
    }
  }
  if (node.type === "MemberExpression") {
    if (parent?.type === "MemberExpression" && parent.object === node) return null;
    if (
      ["CallExpression", "NewExpression"].includes(parent?.type) &&
      unwrapChain(parent.callee) === node
    ) {
      return null;
    }
    if (node.computed) {
      if (
        node.object.type === "MemberExpression" &&
        !node.object.computed &&
        memberRoot(node.object) === "process" &&
        memberProperty(node.object) === "argv" &&
        node.property.type === "Literal" &&
        node.property.value === 1
      ) {
        return "native-entry-dispatch:process.argv[1]";
      }
      const caller = flow.callerRoot(node.object);
      if (caller !== null) return `injected-reference:${caller}.?`;
      const objectOrigins = flow.origins(node.object);
      const ambient = firstOrigin(objectOrigins, "ambient:");
      if (ambient !== undefined) return `ambient-computed-reference:${ambient}`;
      const computedRoot = memberRoot(node);
      const importedRoot = computedRoot === null ? undefined : imports.get(computedRoot);
      if (
        objectOrigins.has("callable") ||
        objectOrigins.has("callable-member") ||
        objectOrigins.has("dynamic-code") ||
        objectOrigins.has("builtin-loader") ||
        objectOrigins.has("capability-result") ||
        [...objectOrigins].some(
          (origin) =>
            origin.startsWith("ambient:") ||
            origin.startsWith("free:") ||
            origin.startsWith("intrinsic:"),
        ) ||
        importedRoot?.source.startsWith("./")
      ) {
        return "computed-member-reference";
      }
      return null;
    }
    const root = memberRoot(node);
    const property = memberProperty(node);
    if (["__proto__", "constructor"].includes(property)) {
      return `capability-reference:dynamic-code-member:${property}`;
    }
    if (property === "prototype") {
      const intrinsic = firstOrigin(flow.origins(node.object), "intrinsic:");
      return intrinsic === undefined
        ? "capability-reference:dynamic-code-member:prototype"
        : `intrinsic-prototype-reference:${intrinsic}`;
    }
    if (root === "globalThis" && property === "fetch") {
      return "capability-reference:global-fetch";
    }
    if (
      root === "globalThis" &&
      (GLOBAL_EFFECT_CONSTRUCTORS.has(property) || ["Bun", "Deno"].includes(property))
    ) {
      return `capability-reference:global-effect:globalThis.${property}`;
    }
    if (root === "globalThis" && PROCESS_LOADER_METHODS.has(property)) {
      return "capability-reference:builtin-module-loader";
    }
    if (GLOBAL_EFFECT_ROOTS.has(root)) {
      return `capability-reference:global-effect:${root}.${property ?? "?"}`;
    }
    if (root === "process" && PROCESS_LOADER_METHODS.has(property)) {
      return "capability-reference:builtin-module-loader";
    }
    if (root === "navigator" && property === "sendBeacon") {
      return "capability-reference:global-network";
    }
    const namespace = root === null ? undefined : imports.get(root);
    if (["*", "default"].includes(namespace?.imported) && property !== null) {
      const capability = importedCapability({ imported: property, source: namespace.source });
      if (capability !== null) return `capability-reference:${capability}`;
    }
    const caller = flow.callerRoot(node.object);
    if (caller !== null) return `injected-reference:${caller}.${property ?? "?"}`;
    const objectOrigins = flow.origins(node.object);
    const ambient = firstOrigin(objectOrigins, "ambient:");
    if (ambient !== undefined) return `ambient-reference:${ambient}.${property ?? "?"}`;
    if (objectOrigins.has("builtin-loader")) return "capability-reference:builtin-module-loader";
    if (objectOrigins.has("dynamic-code") || objectOrigins.has("callable-member")) {
      return "capability-reference:dynamic-code:alias";
    }
    if (objectOrigins.has("capability-result")) return "capability-reference:capability-result";
    if ([...objectOrigins].some((origin) => origin.startsWith("free:"))) {
      return `unresolved-free-reference:${root ?? "alias"}.${property ?? "?"}`;
    }
    const intrinsic = firstOrigin(objectOrigins, "intrinsic:");
    if (intrinsic !== undefined) {
      return `intrinsic-member-reference:${intrinsic}.${property ?? "?"}`;
    }
  }
  if (node.type === "ThisExpression") return "injected-reference:this";
  return null;
}

function classifyConstructor(expression, flow) {
  const callee = unwrapChain(expression.callee);
  if (callee.type === "Identifier") {
    if (GLOBAL_EFFECT_CONSTRUCTORS.has(callee.name)) {
      return `effect-constructor:${callee.name}`;
    }
    const origins = flow.origins(callee);
    if (origins.has("caller")) return `injected-constructor:${callee.name}`;
    if (origins.has("dynamic-code") || origins.has("callable-member")) {
      return "dynamic-constructor";
    }
    if (origins.has("capability-result")) return "capability-result-constructor";
    const ambient = firstOrigin(origins, "ambient:");
    if (ambient !== undefined) return `ambient-constructor:${ambient}`;
    if ([...origins].some((origin) => origin.startsWith("free:"))) {
      return `unresolved-free-constructor:${callee.name}`;
    }
    const intrinsic = firstOrigin(origins, "intrinsic:");
    if (intrinsic !== undefined && intrinsic !== `intrinsic:${callee.name}`) {
      return `intrinsic-alias-constructor:${intrinsic}`;
    }
    return null;
  }
  return "dynamic-constructor";
}

function resolveCalledFunction(key, calleeNode, functions, imports, expectedExports) {
  const callee = unwrapChain(calleeNode);
  if (callee.type !== "Identifier") return null;
  if (functions.has(callee.name)) return `${key.split("#")[0]}#${callee.name}`;
  const imported = imports.get(callee.name);
  if (imported === undefined || !imported.source.startsWith("./")) return null;
  const filename = imported.source.slice(2);
  if (!Object.hasOwn(expectedExports, filename) || imported.imported === "*") return null;
  return `${filename}#${imported.imported}`;
}

function resolveReferencedFunction(key, node, parent, functions, imports, expectedExports) {
  if (
    node.type !== "Identifier" ||
    isNonReferenceIdentifier(node, parent) ||
    (parent?.type === "CallExpression" && unwrapChain(parent.callee) === node)
  ) {
    return null;
  }
  if (functions.has(node.name)) return `${key.split("#")[0]}#${node.name}`;
  const imported = imports.get(node.name);
  if (
    imported === undefined ||
    !imported.source.startsWith("./") ||
    imported.imported === "*" ||
    imported.imported === "default"
  ) {
    return null;
  }
  const filename = imported.source.slice(2);
  return Object.hasOwn(expectedExports, filename) ? `${filename}#${imported.imported}` : null;
}
