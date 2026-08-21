import { createHash } from "node:crypto";

import { normalizedAstDigest } from "./provider-quarantine-ast-ownership.mjs";

/** Exact reviewed taxonomy for every non-function export in provider-runtime modules. */
export const PROVIDER_EFFECT_DATA_EXPORTS = Object.freeze({
  "bootstrap-live-workers-common.mjs#BOOTSTRAP_INGRESS_SOURCE": descriptor(
    "CallExpression",
    "CallExpression",
    "cc9da685cdea37c696b5039aa2e2efd85e92aceae3b2ad0d4a9c99282a73cca2",
  ),
  "bootstrap-live-workers-common.mjs#BOOTSTRAP_PRIVATE_SOURCE": descriptor(
    "CallExpression",
    "CallExpression",
    "1f8007e675c4dcad08df41d2286d39c49647019d29e47a5f83c7a1591b9a78d8",
  ),
  "bootstrap-live-workers-common.mjs#BOOTSTRAP_WORM_SOURCE": descriptor(
    "CallExpression",
    "CallExpression",
    "d9697e8374af5ef11d19f13aa52565ae27ec15c78e3b45b15010069dba046259",
  ),
  "bootstrap-live-workers-common.mjs#EXPECTED_DURABLE_EXPORTS": descriptor(
    "CallExpression",
    "CallExpression",
    "97a5a1e1ce66ffc8b07dfe42d4059cb828b72c8c827b56ffd5373d51fd63be9a",
  ),
  "bootstrap-live-workers-common.mjs#EXPECTED_WORM_DURABLE_EXPORTS": descriptor(
    "CallExpression",
    "CallExpression",
    "4967f10953dbfcbe53e246ac7b0c14bd8fad37326214099ff794ea5ff3cfeabb",
  ),
  "bootstrap-live-workers-common.mjs#FINAL_INGRESS_SOURCE": descriptor(
    "CallExpression",
    "CallExpression",
    "bee5727ad73295eb43c697bac3fcece517a48485076fe20436bd7e27d8364157",
  ),
  "bootstrap-live-workers-common.mjs#FINAL_WORM_SOURCE": descriptor(
    "CallExpression",
    "CallExpression",
    "ff81db090153be8ca1da6236b6b7ed59586e43610f47680e75543e2959186267",
  ),
  "bootstrap-live-workers-common.mjs#INGRESS_CONFIG": descriptor(
    "Literal",
    "Literal",
    "56d23de02f3775c390b7ce8ffca2aa625116f54867f5ee975062a38b259dd7cc",
  ),
  "bootstrap-live-workers-common.mjs#MAX_PROVIDER_BYTES": descriptor(
    "Literal",
    "Literal",
    "dba4ecdd4abd71a4ace7bfed2ef58081815ba467c933ae247ee32ff61ee64ad1",
  ),
  "bootstrap-live-workers-common.mjs#MAX_SMOKE_BYTES": descriptor(
    "Literal",
    "Literal",
    "238e0739a5e50ce31bf8b6bd80ceb545d0f8e7f62c7ae54b22db8d210d028c1d",
  ),
  "bootstrap-live-workers-common.mjs#PRIVATE_CONFIGS": descriptor(
    "CallExpression",
    "CallExpression",
    "75e480d0c8c8bc163e4eceed70d3d85bcc800742639b803d234dcd6ad3d80578",
  ),
  "bootstrap-live-workers-common.mjs#PROJECT_ROOT": descriptor(
    "CallExpression",
    "CallExpression",
    "e9b7222eca60e48a74897c9188e5388c3db4051be3051d43a53afe52d49e744e",
  ),
  "bootstrap-live-workers-common.mjs#VERSION_ID": descriptor(
    "Identifier",
    "import:./cloudflare-ids.mjs#CLOUDFLARE_UUID",
    "54ee3ca7730f9397d9dc2238bcb14db777b95cfdec743ca64ea7bbe2294ed8e1",
  ),
  "bootstrap-live-workers-common.mjs#WRANGLER": descriptor(
    "CallExpression",
    "CallExpression",
    "3f9da7701aff56c7f0685666a0b033ece1daf454102121ff2973d34aa832e43b",
  ),
});

/** Return exact data-export keys after kind, binding-origin and initializer-AST proof. */
export function assertExactEffectDataExports(programs) {
  const actual = {};
  for (const [filename, program] of programs) {
    for (const statement of program.body) {
      if (statement.type !== "ExportNamedDeclaration") continue;
      const declaration = statement.declaration;
      if (declaration?.type !== "VariableDeclaration") continue;
      if (declaration.kind !== "const") {
        throw new Error(`provider effect data export is mutable: ${filename}`);
      }
      for (const item of declaration.declarations) {
        if (item.id.type !== "Identifier" || item.init === null) {
          throw new Error(`provider effect data export is not exact: ${filename}`);
        }
        actual[`${filename}#${item.id.name}`] = descriptor(
          item.init.type,
          initializerOrigin(program, item.init),
          normalizedAstDigest(item.init, createHash),
        );
      }
    }
  }
  assertExactDescriptors(actual);
  return new Set(Object.keys(actual));
}

function initializerOrigin(program, initializer) {
  if (initializer.type !== "Identifier") return initializer.type;
  for (const statement of program.body) {
    if (statement.type !== "ImportDeclaration") continue;
    for (const specifier of statement.specifiers) {
      if (specifier.local.name !== initializer.name) continue;
      const imported =
        specifier.type === "ImportSpecifier"
          ? specifier.imported.name
          : specifier.type === "ImportDefaultSpecifier"
            ? "default"
            : "*";
      return `import:${statement.source.value}#${imported}`;
    }
  }
  return `identifier:${initializer.name}`;
}

function assertExactDescriptors(actual) {
  const actualKeys = Object.keys(actual).sort();
  const expectedKeys = Object.keys(PROVIDER_EFFECT_DATA_EXPORTS).sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
    throw new Error("provider effect data export inventory drift");
  }
  for (const key of expectedKeys) {
    if (JSON.stringify(actual[key]) !== JSON.stringify(PROVIDER_EFFECT_DATA_EXPORTS[key])) {
      throw new Error(`provider effect data initializer AST drift: ${key}`);
    }
  }
}

function descriptor(type, origin, sha256) {
  return Object.freeze({ declarationKind: "const", origin, sha256, type });
}
