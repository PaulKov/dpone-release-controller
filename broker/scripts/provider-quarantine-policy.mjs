import { assertAstProviderBoundaries } from "./provider-quarantine-ast-boundaries.mjs";
import { assertAstProductionModules } from "./provider-quarantine-ast-capabilities.mjs";
import {
  astNodes,
  collectModuleExports,
  parseQuarantineModule,
} from "./provider-quarantine-ast-core.mjs";
import { assertAstProviderSimulations } from "./provider-quarantine-ast-simulations.mjs";
import { assertExactEffectDataExports } from "./provider-quarantine-effect-data.mjs";
import {
  LOCAL_CAPABILITY_OWNER_AST_DIGESTS,
  LOCAL_CAPABILITY_OWNERS,
  PRODUCTION_EFFECT_MODULE_EXPORTS,
  PRODUCTION_IMPORT_DIGESTS,
  PRODUCTION_MODULE_EXPORTS,
  PRODUCTION_SCRIPT_INVENTORY,
  PROVIDER_BOUNDARY_INVENTORY,
  PROVIDER_MUTATION_ENTRYPOINT_INVENTORY,
  PROVIDER_SIMULATION_DELEGATES,
  PROVIDER_SIMULATION_EXPORTS,
  PROVIDER_SIMULATION_FUNCTION_DIGESTS,
  PROVIDER_SIMULATION_IMPORT_DIGESTS,
} from "./provider-quarantine-inventory.mjs";

export {
  PRODUCTION_EFFECT_MODULE_EXPORTS,
  PRODUCTION_SCRIPT_INVENTORY,
  PROVIDER_SIMULATION_MODULES,
} from "./provider-quarantine-inventory.mjs";

/** Verify runtime inventory equality and import-resolved first-statement HOLDs. */
export function assertProviderBoundarySources(boundaries, entrypoints, sources) {
  if (
    JSON.stringify(boundaries) !== JSON.stringify(PROVIDER_BOUNDARY_INVENTORY) ||
    JSON.stringify(entrypoints) !== JSON.stringify(PROVIDER_MUTATION_ENTRYPOINT_INVENTORY)
  ) {
    throw new Error("runtime provider mutation inventory differs from the pinned AST policy");
  }
  assertAstProviderBoundaries(boundaries, entrypoints, PRODUCTION_EFFECT_MODULE_EXPORTS, sources);
}

/** Run the boundary proof from the pinned TCB inventory before importing runtime modules. */
export function assertPinnedProviderBoundarySources(sources) {
  assertAstProviderBoundaries(
    PROVIDER_BOUNDARY_INVENTORY,
    PROVIDER_MUTATION_ENTRYPOINT_INVENTORY,
    PRODUCTION_EFFECT_MODULE_EXPORTS,
    sources,
  );
}

/** Fail closed over every executable file plus every production import/export/call edge. */
export function assertProductionScriptInventory(actualScripts, sources) {
  if (
    actualScripts.some(
      (filename) =>
        !PRODUCTION_SCRIPT_INVENTORY.includes(filename) &&
        !/^test-[a-z0-9-]+\.mjs$/u.test(filename),
    )
  ) {
    throw new Error("scripts directory contains an unclassified executable file");
  }
  assertExactEffectDataExports(
    new Map(
      Object.keys(PRODUCTION_EFFECT_MODULE_EXPORTS).map((filename) => [
        filename,
        parseQuarantineModule(filename, sources.get(filename)),
      ]),
    ),
  );
  assertAstProductionModules({
    boundaries: PROVIDER_BOUNDARY_INVENTORY,
    expectedExports: PRODUCTION_MODULE_EXPORTS,
    expectedImportDigests: PRODUCTION_IMPORT_DIGESTS,
    localCapabilityOwnerDigests: LOCAL_CAPABILITY_OWNER_AST_DIGESTS,
    localCapabilityOwners: LOCAL_CAPABILITY_OWNERS,
    sources,
  });
}

/** Focused AST assertion retained for callers that audit only graph test imports. */
export function assertProductionGraphExcludesTests(sources) {
  for (const [filename, source] of sources) {
    const program = parseQuarantineModule(filename, source);
    const nodes = astNodes(program);
    const dynamicImports = nodes.filter((node) => node.type === "ImportExpression");
    const trustedBootstrapImport =
      filename === "verify-provider-quarantine.mjs" &&
      dynamicImports.length === 1 &&
      dynamicImports[0].source.type === "Literal" &&
      dynamicImports[0].source.value === "./provider-quarantine-policy.mjs";
    if (dynamicImports.length !== 0 && !trustedBootstrapImport) {
      throw new Error(`production script uses an unclassified dynamic import: ${filename}`);
    }
    for (const node of nodes) {
      if (
        (node.type === "ImportDeclaration" ||
          (node.type === "ExportNamedDeclaration" && node.source !== null)) &&
        node.source.value.startsWith("./test-")
      ) {
        throw new Error(`production script imports a test-only module: ${filename}`);
      }
    }
  }
}

export function assertProviderSimulationsAreDataOnly(actual, sources) {
  assertAstProviderSimulations({
    actual,
    delegates: PROVIDER_SIMULATION_DELEGATES,
    expectedExports: PROVIDER_SIMULATION_EXPORTS,
    expectedFunctionDigests: PROVIDER_SIMULATION_FUNCTION_DIGESTS,
    expectedImportDigests: PROVIDER_SIMULATION_IMPORT_DIGESTS,
    sources,
  });
}

export function assertSupportedExportSyntax(filename, source) {
  collectModuleExports(filename, parseQuarantineModule(filename, source));
}

export function assertProviderPackageScripts(packageJson) {
  const expectedScripts = {
    "authority-keys:provision": "node scripts/provision-worm-rpc-key.mjs",
    "bootstrap:live": "node scripts/bootstrap-live-workers.mjs",
    "cloudflare-observer-token:verify":
      "node scripts/provision-cloudflare-deployment-observer-token.mjs",
    check:
      "pnpm run config:check && pnpm run privacy:check && pnpm run module-size:check && pnpm run format:check && pnpm run lint && pnpm run typecheck && pnpm run test",
    "config:check":
      "node scripts/verify-provider-quarantine.mjs && node scripts/verify-project-config.mjs",
    format: "prettier --write .",
    "format:check": "prettier --check .",
    "github-app-key:provision": "node scripts/provision-github-app-key.mjs",
    lint: "eslint . --max-warnings=0",
    "module-size:check": "node scripts/check-module-size.mjs",
    "privacy:check": "node scripts/check-publication-privacy.mjs",
    test: "pnpm run test:module-size && pnpm run test:module-inventory && pnpm run test:privacy && pnpm run test:mutation-hold && pnpm run test:bootstrap && pnpm run test:cloudflare-observer-token && pnpm run test:deployment && pnpm run test:github-app-key && pnpm run test:worm-rpc-key && pnpm run test:unit && pnpm run test:candidate-stream",
    "test:bootstrap": "node scripts/test-bootstrap-live-workers.mjs",
    "test:candidate-stream": "node scripts/test-candidate-stream-boundary.mjs",
    "test:cloudflare-observer-token": "node scripts/test-cloudflare-deployment-observer-token.mjs",
    "test:deployment": "node scripts/test-deployment-tooling.mjs",
    "test:github-app-key": "node scripts/test-github-app-key-provision.mjs",
    "test:module-inventory": "node scripts/test-closed-module-inventory.mjs",
    "test:module-size": "node scripts/test-module-size.mjs",
    "test:mutation-hold": "node scripts/test-provider-mutation-hold.mjs",
    "test:privacy": "node scripts/test-publication-privacy.mjs",
    "test:unit": "vitest run",
    "test:watch": "vitest",
    "test:worm-rpc-key": "node scripts/test-worm-rpc-key-provision.mjs",
    typecheck: "tsc --noEmit",
    "version:deploy": "node scripts/deploy-version.mjs",
    "version:upload": "node scripts/upload-version.mjs",
    "worm-rpc-key:provision": "node scripts/provision-worm-rpc-key.mjs",
  };
  if (
    packageJson.packageManager !== "pnpm@11.19.0" ||
    packageJson.engines?.node !== ">=22.0.0" ||
    packageJson.devDependencies?.["eslint-scope"] !== "9.1.2" ||
    packageJson.devDependencies?.espree !== "11.2.0" ||
    JSON.stringify(Object.entries(packageJson.scripts ?? {}).sort()) !==
      JSON.stringify(Object.entries(expectedScripts).sort())
  ) {
    throw new Error("production rollout must use pinned explicit immutable version scripts");
  }
}
