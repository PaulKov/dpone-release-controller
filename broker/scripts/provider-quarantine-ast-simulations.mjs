import {
  assertExactModuleExports,
  assertUnshadowedNamedImport,
  astNodes,
  canonicalImportDigest,
  canonicalImportInventory,
  findDirectExportedFunction,
  parseQuarantineModule,
} from "./provider-quarantine-ast-core.mjs";
import { assertPureSimulationPrograms } from "./provider-quarantine-simulation-purity.mjs";

const CENTRAL = "test-provider-trace-simulation.mjs";
const PARSER = "parseSimulationInput";

/** Prove every simulation is a primitive-JSON, in-memory, pure-call model. */
export function assertAstProviderSimulations({
  actual,
  delegates,
  expectedExports,
  expectedFunctionDigests,
  expectedImportDigests,
  sources,
}) {
  assertSameInventory(actual, Object.keys(expectedExports));
  assertSameInventory(sources.keys(), Object.keys(expectedExports));
  const programs = new Map();
  for (const [filename, expected] of Object.entries(expectedExports)) {
    const program = parseQuarantineModule(filename, sources.get(filename));
    assertExactModuleExports(filename, program, expected);
    const importDigest = canonicalImportDigest(filename, program);
    if (importDigest !== expectedImportDigests[filename]) {
      throw new Error(
        `provider simulation import inventory drift: ${filename}; actual=${importDigest}; ` +
          `imports=${JSON.stringify(canonicalImportInventory(filename, program))}`,
      );
    }
    programs.set(filename, program);
  }
  assertCentralSimulationBoundaries(programs.get(CENTRAL), expectedExports[CENTRAL]);
  for (const [filename, descriptor] of Object.entries(delegates)) {
    assertWrapperBoundary(filename, programs.get(filename), descriptor);
  }
  assertPureSimulationPrograms(programs, expectedFunctionDigests);
}

function assertCentralSimulationBoundaries(program, exports) {
  assertUnshadowedLocalFunction(program, PARSER);
  for (const symbol of exports) {
    const declaration = requirePrimitiveFunction(CENTRAL, program, symbol);
    const parameter = declaration.params[0].name;
    const first = declaration.body.body[0];
    if (symbol === PARSER) {
      if (!isPrimitiveStringGuard(first, parameter)) {
        throw new Error(
          `provider simulation export lacks primitive boundary: ${CENTRAL}#${symbol}`,
        );
      }
      continue;
    }
    if (!isSealedParserAssignment(first, parameter)) {
      throw new Error(
        `provider simulation export lacks sealed parser delegation: ${CENTRAL}#${symbol}`,
      );
    }
  }
}

function assertWrapperBoundary(filename, program, descriptor) {
  const { imported, source, symbol } = descriptor;
  assertUnshadowedNamedImport(program, imported, imported, source);
  const declaration = requirePrimitiveFunction(filename, program, symbol);
  const parameter = declaration.params[0].name;
  const statements = declaration.body.body;
  const call = statements[0]?.type === "ReturnStatement" ? statements[0].argument : null;
  if (
    statements.length !== 1 ||
    call?.type !== "CallExpression" ||
    call.optional === true ||
    call.callee.type !== "Identifier" ||
    call.callee.name !== imported ||
    call.arguments.length !== 1 ||
    call.arguments[0]?.type !== "Identifier" ||
    call.arguments[0].name !== parameter
  ) {
    throw new Error(`provider simulation wrapper is not a direct primitive delegate: ${filename}`);
  }
}

function requirePrimitiveFunction(filename, program, symbol) {
  const declaration = findDirectExportedFunction(program, symbol);
  if (
    declaration === null ||
    declaration.async ||
    declaration.generator ||
    declaration.params.length !== 1 ||
    declaration.params[0].type !== "Identifier"
  ) {
    throw new Error(`provider simulation export lacks primitive boundary: ${filename}#${symbol}`);
  }
  return declaration;
}

function isPrimitiveStringGuard(statement, parameter) {
  if (statement?.type !== "IfStatement" || statement.alternate !== null) return false;
  const test = statement.test;
  const consequent =
    statement.consequent.type === "BlockStatement"
      ? statement.consequent.body.length === 1
        ? statement.consequent.body[0]
        : null
      : statement.consequent;
  return (
    test.type === "BinaryExpression" &&
    test.operator === "!==" &&
    test.left.type === "UnaryExpression" &&
    test.left.operator === "typeof" &&
    test.left.argument.type === "Identifier" &&
    test.left.argument.name === parameter &&
    test.right.type === "Literal" &&
    test.right.value === "string" &&
    consequent?.type === "ThrowStatement"
  );
}

function isSealedParserAssignment(statement, parameter) {
  if (statement?.type !== "VariableDeclaration" || statement.kind !== "const") return false;
  const declaration = statement.declarations[0];
  const call = declaration?.init;
  return (
    statement.declarations.length === 1 &&
    declaration.id.type === "Identifier" &&
    call?.type === "CallExpression" &&
    call.optional !== true &&
    call.callee.type === "Identifier" &&
    call.callee.name === PARSER &&
    call.arguments.length === 1 &&
    call.arguments[0]?.type === "Identifier" &&
    call.arguments[0].name === parameter
  );
}

function assertUnshadowedLocalFunction(program, name) {
  const target = findDirectExportedFunction(program, name);
  if (target === null) throw new Error(`sealed simulation parser missing: ${name}`);
  let declarations = 0;
  for (const node of astNodes(program)) {
    if (
      ((node.type === "FunctionDeclaration" || node.type === "FunctionExpression") &&
        node.id?.name === name) ||
      (node.type === "VariableDeclarator" && bindingIncludes(node.id, name)) ||
      ((node.type === "FunctionDeclaration" ||
        node.type === "FunctionExpression" ||
        node.type === "ArrowFunctionExpression") &&
        node.params.some((parameter) => bindingIncludes(parameter, name)))
    ) {
      declarations += 1;
    }
    if (
      (node.type === "AssignmentExpression" && bindingIncludes(node.left, name)) ||
      (node.type === "UpdateExpression" && bindingIncludes(node.argument, name))
    ) {
      throw new Error(`sealed simulation parser is reassigned: ${name}`);
    }
  }
  if (declarations !== 1) throw new Error(`sealed simulation parser is shadowed: ${name}`);
}

function bindingIncludes(pattern, name) {
  return astNodes(pattern).some((node) => node.type === "Identifier" && node.name === name);
}

function assertSameInventory(actualIterable, expectedIterable) {
  const actual = [...actualIterable].sort();
  const expected = [...expectedIterable].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error("provider simulation module inventory drift");
  }
}
