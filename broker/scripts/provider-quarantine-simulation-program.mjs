import { createHash } from "node:crypto";

import { normalizedAstDigest } from "./provider-quarantine-ast-ownership.mjs";

export const PROVIDER_SIMULATION_PROGRAM_DIGESTS = Object.freeze({
  "test-bootstrap-live-workers-engine.mjs":
    "8bd78b86b6be1fbf8540f05d0ed85bb4d6df66f00f8a44b09fb56c7ff13365ca",
  "test-provider-trace-simulation.mjs":
    "edb8a311e9e277ef728abc7e00ba7b4baf1c942771c85a8e14f7d3ab749c3017",
  "test-worm-rpc-key-engine.mjs":
    "617b87a136f9bff5da173157348817c867ce728118b11d29f2b24f9f0652bc47",
});

/** Prove simulations have no executable module-scope statement or mutable global initializer. */
export function assertSimulationProgramShell(filename, program) {
  if (normalizedAstDigest(program, createHash) !== PROVIDER_SIMULATION_PROGRAM_DIGESTS[filename]) {
    throw new Error(`provider simulation Program AST drift: ${filename}`);
  }
  for (const statement of program.body) {
    if (statement.type === "ImportDeclaration" || isFunctionDeclaration(statement)) continue;
    const declaration =
      statement.type === "ExportNamedDeclaration" ? statement.declaration : statement;
    if (declaration?.type !== "VariableDeclaration" || declaration.kind !== "const") {
      throw new Error(`provider simulation has executable module scope: ${filename}`);
    }
    for (const item of declaration.declarations) {
      if (item.id.type !== "Identifier" || !isSealedDataInitializer(item.init)) {
        throw new Error(`provider simulation has an effectful top-level initializer: ${filename}`);
      }
    }
  }
}

function isFunctionDeclaration(statement) {
  return (
    statement.type === "FunctionDeclaration" ||
    (statement.type === "ExportNamedDeclaration" &&
      statement.declaration?.type === "FunctionDeclaration")
  );
}

function isSealedDataInitializer(initializer) {
  if (initializer?.type === "Literal") return initializer.regex !== undefined;
  if (
    initializer?.type === "CallExpression" &&
    initializer.callee.type === "MemberExpression" &&
    !initializer.callee.computed &&
    initializer.callee.object.type === "Identifier" &&
    initializer.callee.object.name === "Object" &&
    initializer.callee.property.type === "Identifier" &&
    initializer.callee.property.name === "freeze" &&
    initializer.arguments.length === 1
  ) {
    return isPrimitiveArray(initializer.arguments[0]);
  }
  return (
    initializer?.type === "NewExpression" &&
    initializer.callee.type === "Identifier" &&
    initializer.callee.name === "Set" &&
    initializer.arguments.length === 1 &&
    isPrimitiveArray(initializer.arguments[0])
  );
}

function isPrimitiveArray(value) {
  return (
    value?.type === "ArrayExpression" &&
    value.elements.every(
      (item) =>
        item?.type === "Literal" && ["boolean", "number", "string"].includes(typeof item.value),
    )
  );
}
