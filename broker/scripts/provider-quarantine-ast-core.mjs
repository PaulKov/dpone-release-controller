import { createHash } from "node:crypto";

import { parse, version as espreeVersion } from "espree";

if (espreeVersion !== "11.2.0") throw new Error("provider quarantine requires espree 11.2.0");

/** Parse one strict ECMAScript module. Espree rejects TypeScript-only syntax. */
export function parseQuarantineModule(filename, source) {
  if (typeof source !== "string") throw new Error(`module source is not text: ${filename}`);
  try {
    return parse(source, {
      ecmaVersion: "latest",
      range: true,
      sourceType: "module",
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`module is not strict ECMAScript: ${filename}: ${detail}`, { cause: error });
  }
}

/** Return the complete, syntax-checked public value-export inventory. */
export function collectModuleExports(filename, program) {
  const exports = [];
  for (const statement of program.body) {
    if (
      statement.type === "ExportDefaultDeclaration" ||
      statement.type === "ExportAllDeclaration"
    ) {
      throw new Error(`module contains an unclassified export form: ${filename}`);
    }
    if (statement.type !== "ExportNamedDeclaration") continue;
    if (statement.exportKind === "type") {
      throw new Error(`module contains an unclassified export form: ${filename}`);
    }
    if (statement.declaration !== null) {
      collectDeclarationExports(filename, statement.declaration, exports);
      continue;
    }
    for (const specifier of statement.specifiers) {
      if (specifier.type !== "ExportSpecifier" || specifier.exported.type !== "Identifier") {
        throw new Error(`module contains an unclassified export form: ${filename}`);
      }
      if (specifier.exported.name === "default") {
        throw new Error(`module contains an unclassified export form: ${filename}`);
      }
      if (specifier.local.type === "Identifier" && specifier.local.name === "default") {
        throw new Error(`module contains an unclassified export form: ${filename}`);
      }
      exports.push(specifier.exported.name);
    }
  }
  const ordered = [...exports].sort(asciiCompare);
  if (new Set(ordered).size !== ordered.length) {
    throw new Error(`module contains a duplicate export: ${filename}`);
  }
  return ordered;
}

export function assertExactModuleExports(filename, program, expected) {
  const actual = collectModuleExports(filename, program);
  if (JSON.stringify(actual) !== JSON.stringify([...expected].sort(asciiCompare))) {
    throw new Error(`production module export inventory drift: ${filename}`);
  }
}

/** Hash the exact static import/re-export binding graph represented by the AST. */
export function canonicalImportDigest(filename, program) {
  return createHash("sha256")
    .update(JSON.stringify(canonicalImportInventory(filename, program)))
    .digest("hex");
}

/** Reviewable canonical form underlying each pinned per-module import digest. */
export function canonicalImportInventory(filename, program) {
  const entries = [];
  for (const statement of program.body) {
    if (statement.type === "ImportDeclaration") {
      if (statement.attributes?.length > 0 || statement.assertions?.length > 0) {
        throw new Error(`module import attributes are not classified: ${filename}`);
      }
      entries.push({
        bindings: statement.specifiers.map(importBinding).sort(asciiCompare),
        kind: "import",
        source: exactModuleSource(filename, statement.source),
      });
    }
    if (statement.type === "ExportNamedDeclaration" && statement.source !== null) {
      entries.push({
        bindings: statement.specifiers.map(exportBinding).sort(asciiCompare),
        kind: "reexport",
        source: exactModuleSource(filename, statement.source),
      });
    }
  }
  entries.sort((left, right) => asciiCompare(JSON.stringify(left), JSON.stringify(right)));
  return entries;
}

/** Resolve and lock a security-sensitive named import; local shadowing is forbidden. */
export function assertUnshadowedNamedImport(program, local, imported, source) {
  let matched = null;
  for (const statement of program.body) {
    if (statement.type !== "ImportDeclaration" || statement.source.value !== source) continue;
    for (const specifier of statement.specifiers) {
      if (
        specifier.type === "ImportSpecifier" &&
        specifier.local.name === local &&
        specifier.imported.type === "Identifier" &&
        specifier.imported.name === imported
      ) {
        if (matched !== null) throw new Error(`duplicate security import binding: ${local}`);
        matched = specifier;
      }
    }
  }
  if (matched === null) throw new Error(`security import binding is not exact: ${local}`);
  for (const node of astNodes(program)) {
    if (node.type === "ImportDeclaration") continue;
    if (declaresBinding(node, local)) {
      throw new Error(`security import binding is shadowed: ${local}`);
    }
    if (
      (node.type === "AssignmentExpression" && bindingContains(node.left, local)) ||
      (node.type === "UpdateExpression" && bindingContains(node.argument, local))
    ) {
      throw new Error(`security import binding is reassigned: ${local}`);
    }
  }
}

export function findDirectExportedFunction(program, symbol) {
  for (const statement of program.body) {
    const declaration = statement.type === "ExportNamedDeclaration" ? statement.declaration : null;
    if (declaration?.type === "FunctionDeclaration" && declaration.id?.name === symbol) {
      return declaration;
    }
  }
  return null;
}

export function findNamedReexport(program, symbol, source) {
  return program.body.some(
    (statement) =>
      statement.type === "ExportNamedDeclaration" &&
      statement.source?.value === source &&
      statement.specifiers.some(
        (specifier) =>
          specifier.type === "ExportSpecifier" &&
          specifier.exported.type === "Identifier" &&
          specifier.exported.name === symbol &&
          specifier.local.type === "Identifier" &&
          specifier.local.name === symbol,
      ),
  );
}

export function astNodes(root) {
  const nodes = [];
  visit(root);
  return nodes;

  function visit(node) {
    if (node === null || typeof node !== "object" || typeof node.type !== "string") return;
    nodes.push(node);
    for (const [key, value] of Object.entries(node)) {
      if (key === "loc" || key === "range" || key === "tokens" || key === "comments") continue;
      if (Array.isArray(value)) for (const child of value) visit(child);
      else visit(value);
    }
  }
}

function collectDeclarationExports(filename, declaration, exports) {
  if (declaration.type === "FunctionDeclaration") {
    if (declaration.generator || declaration.id === null) {
      throw new Error(`module contains an unclassified export form: ${filename}`);
    }
    exports.push(declaration.id.name);
    return;
  }
  if (declaration.type === "ClassDeclaration" && declaration.id !== null) {
    exports.push(declaration.id.name);
    return;
  }
  if (declaration.type === "VariableDeclaration" && declaration.kind === "const") {
    for (const item of declaration.declarations) {
      if (item.id.type !== "Identifier") {
        throw new Error(`module contains an unclassified export form: ${filename}`);
      }
      exports.push(item.id.name);
    }
    return;
  }
  throw new Error(`module contains an unclassified export form: ${filename}`);
}

function importBinding(specifier) {
  if (specifier.type === "ImportDefaultSpecifier") return `default>${specifier.local.name}`;
  if (specifier.type === "ImportNamespaceSpecifier") return `*>${specifier.local.name}`;
  if (specifier.imported.type !== "Identifier") throw new Error("string import name rejected");
  return `${specifier.imported.name}>${specifier.local.name}`;
}

function exportBinding(specifier) {
  if (
    specifier.type !== "ExportSpecifier" ||
    specifier.local.type !== "Identifier" ||
    specifier.exported.type !== "Identifier" ||
    specifier.local.name === "default"
  ) {
    throw new Error("string re-export name rejected");
  }
  return `${specifier.local.name}>${specifier.exported.name}`;
}

function exactModuleSource(filename, source) {
  if (source.type !== "Literal" || typeof source.value !== "string") {
    throw new Error(`module source is not a string literal: ${filename}`);
  }
  return source.value;
}

function declaresBinding(node, name) {
  if (
    (node.type === "FunctionDeclaration" ||
      node.type === "FunctionExpression" ||
      node.type === "ClassDeclaration" ||
      node.type === "ClassExpression") &&
    node.id?.name === name
  ) {
    return true;
  }
  if (
    (node.type === "FunctionDeclaration" ||
      node.type === "FunctionExpression" ||
      node.type === "ArrowFunctionExpression") &&
    node.params.some((parameter) => bindingContains(parameter, name))
  ) {
    return true;
  }
  return (
    (node.type === "VariableDeclarator" && bindingContains(node.id, name)) ||
    (node.type === "CatchClause" && bindingContains(node.param, name))
  );
}

function bindingContains(pattern, name) {
  if (pattern === null || typeof pattern !== "object") return false;
  if (pattern.type === "Identifier") return pattern.name === name;
  if (pattern.type === "Property") return bindingContains(pattern.value, name);
  if (pattern.type === "RestElement") return bindingContains(pattern.argument, name);
  if (pattern.type === "AssignmentPattern") return bindingContains(pattern.left, name);
  if (pattern.type === "ArrayPattern") {
    return pattern.elements.some((element) => bindingContains(element, name));
  }
  if (pattern.type === "ObjectPattern") {
    return pattern.properties.some((property) => bindingContains(property, name));
  }
  if (pattern.type === "MemberExpression") return false;
  return false;
}

function asciiCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}
