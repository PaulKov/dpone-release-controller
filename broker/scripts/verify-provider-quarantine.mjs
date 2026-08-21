import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { TextDecoder } from "node:util";

const EXPECTED_NODE_VERSION = "24.19.0";
const POLICY_ROOT = "provider-quarantine-policy.mjs";
const POLICY_SHA256 = Object.freeze({
  "provider-quarantine-ast-boundaries.mjs":
    "80671e6274b8eb9216dc5437c5480a5d317f6e29a03d185f7204ca253c591bbe",
  "provider-quarantine-ast-capabilities.mjs":
    "9d1d9bdc7ed979687f05443c23a7f55a775c569dec2a814c893948c3e7b8c51a",
  "provider-quarantine-ast-classifier.mjs":
    "1fc51718e66454126d252f381dd637eac4ebf72ec44d434ab69021c10ebc59a2",
  "provider-quarantine-ast-core.mjs":
    "a2a89561d34fa24131a13a6a0a6ec15f30eb00093c338e67fd74ee131371e377",
  "provider-quarantine-ast-effects.mjs":
    "8142feaca59856c42bb33d3fbd2e83c6b272dbc2d274fbc29ae74b536bc963e5",
  "provider-quarantine-ast-graph.mjs":
    "119eeadf301b8ea63f5be602a94676f16e486dc0e5d875052394af5b08e46420",
  "provider-quarantine-ast-lexical.mjs":
    "93529d3bbea5eb15d3174aadb4f70991238cc63f45f2e3382f0c9c3e96b8e0a5",
  "provider-quarantine-ast-ownership.mjs":
    "581887cf569248f1fa0cab6c023fef7f39957630f101d81f6d8c8e9616111207",
  "provider-quarantine-ast-simulations.mjs":
    "97020802ceb9fc3177d80f5006e14f9f2dc8dce5f2ffb4ba05725d2049a98e64",
  "provider-quarantine-ast-utils.mjs":
    "21683ccfe44da9e721298c73ae8bef004d6d5768ad2c728d1cd967f1f331e3f7",
  "provider-quarantine-effect-data.mjs":
    "56ea655b7668a7ed92120794060b5cfa47a54c1471b7fa7640fb543300b2cd6b",
  "provider-quarantine-inventory.mjs":
    "e424544fd3b7edef381cb3b85e38041cd56d664a43e5f0a04346547ff18f0d9c",
  "provider-quarantine-policy.mjs":
    "44ab518bf5d0a13c2f92105afcad1bff67a6036f479b49cf3b047c9360249887",
  "provider-quarantine-production-exports.mjs":
    "c444c90a44d035b281336df368a67f55521ad7ffdff2215e98abf921b3690b2d",
  "provider-quarantine-production-imports.mjs":
    "875d468ef3c896da987c55ef42330ad9f006e2f458f3cd79f3c07ee55a141bdd",
  "provider-quarantine-reviewed-data-flows-a.mjs":
    "1b859614238e0062c6f8381fd2a062e323e4cee85ffc17b9156e91a934cd1901",
  "provider-quarantine-reviewed-data-flows-b.mjs":
    "feeab6e22d9f3d61416e12e694ed89ac93c22b00a8c125d8aa76ed118d669efe",
  "provider-quarantine-reviewed-node-digests-a.mjs":
    "bfff9b824b57831e78ff048da8338bb9bcc26bbb7c3dbb12469c36e2c7337461",
  "provider-quarantine-reviewed-node-digests-b.mjs":
    "4f6181f0563dcd2b7be7779244ffc00da87147ab452fffae9a89912164d03a19",
  "provider-quarantine-simulation-program.mjs":
    "242ad76f2cc180faa5042fdfe6ee403034438105988159bef3ac9ec70ed2cfa8",
  "provider-quarantine-simulation-purity.mjs":
    "fa1a248e781acedc85d0c70f3274b5fb11a00baf990b83d8356016177a5fecc0",
});
const POLICY_IMPORTS = Object.freeze({
  "provider-quarantine-ast-boundaries.mjs": [
    "./provider-quarantine-ast-core.mjs",
    "./provider-quarantine-effect-data.mjs",
    "node:crypto",
  ],
  "provider-quarantine-ast-capabilities.mjs": [
    "./provider-quarantine-ast-classifier.mjs",
    "./provider-quarantine-ast-core.mjs",
    "./provider-quarantine-ast-effects.mjs",
    "./provider-quarantine-ast-graph.mjs",
    "./provider-quarantine-ast-ownership.mjs",
    "node:crypto",
  ],
  "provider-quarantine-ast-classifier.mjs": [
    "./provider-quarantine-ast-effects.mjs",
    "./provider-quarantine-ast-lexical.mjs",
    "./provider-quarantine-ast-utils.mjs",
  ],
  "provider-quarantine-ast-core.mjs": ["espree", "node:crypto"],
  "provider-quarantine-ast-effects.mjs": ["./provider-quarantine-ast-utils.mjs"],
  "provider-quarantine-ast-graph.mjs": [],
  "provider-quarantine-ast-lexical.mjs": ["./provider-quarantine-ast-utils.mjs", "eslint-scope"],
  "provider-quarantine-ast-ownership.mjs": ["./provider-quarantine-ast-graph.mjs"],
  "provider-quarantine-ast-simulations.mjs": [
    "./provider-quarantine-ast-core.mjs",
    "./provider-quarantine-simulation-purity.mjs",
  ],
  "provider-quarantine-ast-utils.mjs": ["./provider-quarantine-ast-core.mjs"],
  "provider-quarantine-effect-data.mjs": ["./provider-quarantine-ast-ownership.mjs", "node:crypto"],
  "provider-quarantine-inventory.mjs": [
    "./provider-quarantine-effect-data.mjs",
    "./provider-quarantine-production-exports.mjs",
    "./provider-quarantine-production-imports.mjs",
    "./provider-quarantine-reviewed-data-flows-a.mjs",
    "./provider-quarantine-reviewed-data-flows-b.mjs",
    "./provider-quarantine-reviewed-node-digests-a.mjs",
    "./provider-quarantine-reviewed-node-digests-b.mjs",
    "./provider-quarantine-simulation-program.mjs",
  ],
  "provider-quarantine-policy.mjs": [
    "./provider-quarantine-ast-boundaries.mjs",
    "./provider-quarantine-ast-capabilities.mjs",
    "./provider-quarantine-ast-core.mjs",
    "./provider-quarantine-ast-simulations.mjs",
    "./provider-quarantine-effect-data.mjs",
    "./provider-quarantine-inventory.mjs",
  ],
  "provider-quarantine-production-exports.mjs": [],
  "provider-quarantine-production-imports.mjs": [],
  "provider-quarantine-reviewed-data-flows-a.mjs": [],
  "provider-quarantine-reviewed-data-flows-b.mjs": [],
  "provider-quarantine-reviewed-node-digests-a.mjs": [],
  "provider-quarantine-reviewed-node-digests-b.mjs": [],
  "provider-quarantine-simulation-program.mjs": [
    "./provider-quarantine-ast-ownership.mjs",
    "node:crypto",
  ],
  "provider-quarantine-simulation-purity.mjs": [
    "./provider-quarantine-ast-core.mjs",
    "./provider-quarantine-ast-lexical.mjs",
    "./provider-quarantine-ast-utils.mjs",
    "./provider-quarantine-simulation-program.mjs",
    "node:crypto",
  ],
});
const PROJECT_SHA256 = Object.freeze({
  ".node-version": "7e8a2fa94951112b894a3dbe3d05efef5e9263741fa49125f0a70f40fedab4cc",
  "package.json": "c947864752aa6cace126bd67267375ec44919d437ca478528f7873c3a0f062f4",
  "pnpm-lock.yaml": "21244f0f8c401dfaa0fda814657377fe0dffeb6e491d126e521b2aaaad955ee7",
});

const scriptsRoot = exactDirectory(new URL(".", import.meta.url));
const projectRoot = exactDirectory(new URL("..", import.meta.url));
const policySources = readHashedFiles(scriptsRoot, POLICY_SHA256);
assertExactPolicyClosure(policySources);
const projectSources = readHashedFiles(projectRoot, PROJECT_SHA256);
assertPinnedRuntime(projectSources);

const policy = await import("./provider-quarantine-policy.mjs");
const scriptNames = readdirSync(scriptsRoot).sort(asciiCompare);
const scriptSources = readRegularTextFiles(scriptsRoot, scriptNames);
const productionSources = new Map(
  policy.PRODUCTION_SCRIPT_INVENTORY.map((filename) => [filename, scriptSources.get(filename)]),
);
policy.assertProductionScriptInventory(scriptNames, productionSources);

const effectSources = new Map(
  Object.keys(policy.PRODUCTION_EFFECT_MODULE_EXPORTS).map((filename) => [
    filename,
    scriptSources.get(filename),
  ]),
);
effectSources.set("provider-mutation-hold.mjs", scriptSources.get("provider-mutation-hold.mjs"));
policy.assertPinnedProviderBoundarySources(effectSources);

const actualSimulations = scriptNames.filter((filename) =>
  /^test-[a-z0-9-]+-(?:engine|simulation)\.mjs$/u.test(filename),
);
policy.assertProviderSimulationsAreDataOnly(
  actualSimulations,
  new Map(
    policy.PROVIDER_SIMULATION_MODULES.map((filename) => [filename, scriptSources.get(filename)]),
  ),
);
const packageJson = JSON.parse(projectSources.get("package.json"));
policy.assertProviderPackageScripts(packageJson);

process.stdout.write(
  `provider quarantine AST gate: ${policy.PRODUCTION_SCRIPT_INVENTORY.length} production modules, ` +
    `${policy.PROVIDER_SIMULATION_MODULES.length} simulations PASS\n`,
);

function exactDirectory(url) {
  const input = fileURLToPath(url);
  const metadata = lstatSync(input);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("provider quarantine root must be a regular non-symlink directory");
  }
  return realpathSync(input);
}

function readHashedFiles(root, manifest) {
  const sources = readRegularTextFiles(root, Object.keys(manifest));
  for (const [filename, expected] of Object.entries(manifest)) {
    const actual = createHash("sha256")
      .update(readFileSync(join(root, filename)))
      .digest("hex");
    if (actual !== expected) throw new Error(`pre-import quarantine byte drift: ${filename}`);
  }
  return sources;
}

function readRegularTextFiles(root, filenames) {
  const sources = new Map();
  for (const filename of filenames) {
    if (typeof filename !== "string" || basename(filename) !== filename) {
      throw new Error("provider quarantine filename escapes its reviewed directory");
    }
    const path = join(root, filename);
    const metadata = lstatSync(path);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`provider quarantine input must be a regular non-symlink file: ${filename}`);
    }
    const resolved = realpathSync(path);
    if (dirname(resolved) !== root) {
      throw new Error(`provider quarantine input escapes its reviewed directory: ${filename}`);
    }
    const bytes = readFileSync(resolved);
    let source;
    try {
      source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    } catch {
      throw new Error(`provider quarantine input is not exact UTF-8: ${filename}`);
    }
    if (source.startsWith("\uFEFF")) {
      throw new Error(`provider quarantine input begins with a forbidden BOM: ${filename}`);
    }
    sources.set(filename, source);
  }
  return sources;
}

function assertExactPolicyClosure(sources) {
  if (
    JSON.stringify([...sources.keys()].sort()) !==
    JSON.stringify(Object.keys(POLICY_IMPORTS).sort())
  ) {
    throw new Error("pre-import quarantine policy closure inventory drift");
  }
  const exactImport =
    /^\s*(?:import(?:[\s\S]*?\sfrom\s+|\s*)|export[\s\S]*?\sfrom\s+)["']([^"'\r\n]+)["']\s*;?\s*$/gmu;
  for (const [filename, source] of sources) {
    const actual = [...new Set([...source.matchAll(exactImport)].map((match) => match[1]))].sort();
    const expected = [...POLICY_IMPORTS[filename]].sort();
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      throw new Error(`pre-import quarantine policy closure drift: ${filename}`);
    }
    if (actual.some((target) => target.startsWith("./") && !sources.has(target.slice(2)))) {
      throw new Error(`pre-import quarantine policy escapes hashed closure: ${filename}`);
    }
  }
  if (!sources.has(POLICY_ROOT)) throw new Error("pre-import quarantine policy root missing");
}

function assertPinnedRuntime(sources) {
  if (sources.get(".node-version") !== `${EXPECTED_NODE_VERSION}\n`) {
    throw new Error("provider quarantine Node pin drift");
  }
  if (process.versions.node !== EXPECTED_NODE_VERSION) {
    throw new Error(
      `provider quarantine requires Node ${EXPECTED_NODE_VERSION}; received ${process.versions.node}`,
    );
  }
}

function asciiCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}
