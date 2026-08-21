import { astNodes } from "./provider-quarantine-ast-core.mjs";

/** Iterate one AST region while preserving parent identities and exact skip boundaries. */
export function regionEntries(root, skipped = new Set()) {
  const entries = [];
  visit(root, null);
  return entries;

  function visit(node, parent) {
    if (node === null || typeof node !== "object" || typeof node.type !== "string") return;
    if (node !== root && skipped.has(node)) return;
    entries.push({ node, parent });
    for (const [key, value] of Object.entries(node)) {
      if (["loc", "range", "tokens", "comments"].includes(key)) continue;
      if (Array.isArray(value)) for (const child of value) visit(child, node);
      else visit(value, node);
    }
  }
}

export function expressionUsesTaint(node, tainted) {
  return astNodes(node).some((item) => item.type === "Identifier" && tainted.has(item.name));
}

export function bindingNames(pattern) {
  if (pattern?.type === "Identifier") return [pattern.name];
  if (pattern?.type === "AssignmentPattern") return bindingNames(pattern.left);
  if (pattern?.type === "RestElement") return bindingNames(pattern.argument);
  if (pattern?.type === "ArrayPattern") {
    return pattern.elements.flatMap((item) => bindingNames(item));
  }
  if (pattern?.type === "ObjectPattern") {
    return pattern.properties.flatMap((property) =>
      property.type === "RestElement"
        ? bindingNames(property.argument)
        : bindingNames(property.value),
    );
  }
  return [];
}

export function isNonReferenceIdentifier(node, parent) {
  if (parent === null) return false;
  if (/^Import/u.test(parent.type)) return true;
  if (
    (isFunction(parent) && (parent.id === node || parent.params.includes(node))) ||
    parent.id === node
  ) {
    return true;
  }
  if (
    parent.type === "Property" &&
    parent.key === node &&
    parent.value !== node &&
    !parent.computed
  ) {
    return true;
  }
  if (parent.type === "MemberExpression" && parent.property === node && !parent.computed)
    return true;
  return false;
}

export function isEscapeParent(node, parent) {
  return (
    parent?.type === "ReturnStatement" ||
    parent?.type === "ArrayExpression" ||
    parent?.type === "AssignmentExpression" ||
    (parent?.type === "Property" && parent.value === node) ||
    (parent?.type === "CallExpression" && parent.callee !== node)
  );
}

export function isFunction(node) {
  return ["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"].includes(
    node.type,
  );
}

export function unwrapChain(node) {
  return node.type === "ChainExpression" ? node.expression : node;
}

export function memberRoot(member) {
  let current = unwrapChain(member);
  while (current.type === "MemberExpression") current = unwrapChain(current.object);
  return current.type === "Identifier" ? current.name : null;
}

export function memberProperty(member) {
  if (!member.computed && member.property.type === "Identifier") return member.property.name;
  return member.computed &&
    member.property.type === "Literal" &&
    typeof member.property.value === "string"
    ? member.property.value
    : null;
}
