import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";

import { assertClosedModuleInventory } from "./closed-module-inventory.mjs";
import { loadLiveWorkerConfig, LIVE_WORKER_IDENTITIES } from "./live-worker-config.mjs";
import {
  PROVIDER_MUTATION_BOUNDARIES,
  PROVIDER_MUTATION_ENTRYPOINTS,
} from "./provider-mutation-hold.mjs";
import {
  PRODUCTION_EFFECT_MODULE_EXPORTS,
  PRODUCTION_SCRIPT_INVENTORY,
  PROVIDER_SIMULATION_MODULES,
  assertProductionGraphExcludesTests,
  assertProductionScriptInventory,
  assertProviderBoundarySources,
  assertProviderPackageScripts,
  assertProviderSimulationsAreDataOnly,
} from "./provider-quarantine-policy.mjs";
import { parseReviewedJsonc } from "./reviewed-jsonc.mjs";

const expectedWorkspace = `allowBuilds:
  esbuild: true
  workerd: true
blockExoticSubdeps: true
minimumReleaseAge: 1440
minimumReleaseAgeIgnoreMissingTime: false
minimumReleaseAgeStrict: true
trustLockfile: false
trustPolicy: no-downgrade
`;
const actualWorkspace = readFileSync(new URL("../pnpm-workspace.yaml", import.meta.url), "utf8");
if (actualWorkspace !== expectedWorkspace) {
  throw new Error("pnpm-workspace.yaml differs from the reviewed supply-chain policy");
}

const expectedNpmrc = `engine-strict=true
save-exact=true
strict-peer-dependencies=true
`;
const actualNpmrc = readFileSync(new URL("../.npmrc", import.meta.url), "utf8");
if (actualNpmrc !== expectedNpmrc) {
  throw new Error(".npmrc differs from the reviewed package-manager policy");
}

const frozenFixtures = new Map([
  [
    "../docs/schemas/release/github-ruleset-projection-v1.schema.json",
    "2d09c0b60a668a30116e8bc64e74490695e1d8a431e1b5e00a1b744a5b36a0e4",
  ],
  [
    "../test/fixtures/github-ruleset-projection-v1-golden.json",
    "554ae67c234b3111dad0ff1ecc9e5a500a9ec68240ae84f738ba362e74529ba9",
  ],
  [
    "../test/fixtures/release-candidate-handoff-v2.schema.json",
    "b4245cfadeab72fc104e5723a3188169ac0c6a705d190e00140ea0e1d10103c3",
  ],
  [
    "../test/fixtures/release-candidate-handoff-v2-golden.json",
    "ea2974c03c496c2152064405ad630edb1fd126f6b6c7431c66d1af1aa0614e1a",
  ],
  [
    "../test/fixtures/release-candidate-stream-v1.json",
    "95798ad5d1c9424cdd1fda250966b5b7fa96f3622229460b94c17c00fe4f7322",
  ],
  [
    "../test/fixtures/release-candidate-stream-http-boundary-v1.json",
    "6d139e7a3cd24cc67d00b6d10460bcf822022155f9e6fa733a59639c2ee05673",
  ],
  [
    "../test/fixtures/release-controller-action-bundle-v1.schema.json",
    "481fd94602156d9674be387780a2aebd51b6f653555aa4e5b5c950aee7127869",
  ],
  [
    "../test/fixtures/release-controller-closure-manifest-v1.schema.json",
    "49bf555f99bb6aa125719cce6c0d2db88e519ab669b229dcc8d7b905251dd638",
  ],
  [
    "../test/fixtures/release-evidence-v2.schema.json",
    "cff5232f2b63d5d7fb73301f60b3a9b462cc7ec848a572411054d1e7c2769794",
  ],
  [
    "../test/fixtures/release-receipt-envelope-v2.schema.json",
    "c6a36e3b8bdf1cb9b52029be375587d9be824f32eaf3ebd0d37a23775572e641",
  ],
  [
    "../test/fixtures/release-identity-v2-golden.json",
    "24d648014da664163eb4f5d72ae98412fd735d7078d99460823fd88606f9a659",
  ],
]);
for (const [path, expectedDigest] of frozenFixtures) {
  const bytes = readFileSync(new URL(path, import.meta.url));
  const actualDigest = createHash("sha256").update(bytes).digest("hex");
  if (actualDigest !== expectedDigest) {
    throw new Error(`frozen cross-repository fixture digest mismatch: ${path}`);
  }
}

// Runtime closure transport/gate fixtures remain development-only until the
// separately authenticated deployment-protection-rule codec is byte-frozen.
// The public runtime route is fail-closed, so these superseded drafts must not
// be presented as authoritative cross-repository fixtures by config:check.

const expectedObservability = {
  enabled: false,
  head_sampling_rate: 0,
  traces: {
    destinations: [],
    enabled: false,
    head_sampling_rate: 0,
    persist: false,
  },
};
const authorityWorkerConfigs = [
  ["../wrangler.jsonc", "dpone-release-authority-broker-provisioning", "src/index.ts"],
  [
    "../wrangler.candidate-reader.jsonc",
    "dpone-release-candidate-reader-provisioning",
    "src/private/candidate-reader-worker.ts",
  ],
  [
    "../wrangler.cloudflare-deployment-observer.jsonc",
    "dpone-release-cloudflare-deployment-observer-provisioning",
    "src/private/cloudflare-deployment-observer-worker.ts",
  ],
  [
    "../wrangler.controller-run-reader.jsonc",
    "dpone-release-controller-run-reader-provisioning",
    "src/private/controller-run-reader-worker.ts",
  ],
  [
    "../wrangler.governance-reader.jsonc",
    "dpone-release-governance-reader-provisioning",
    "src/private/governance-reader-worker.ts",
  ],
  [
    "../wrangler.worm-mirror.jsonc",
    "dpone-release-worm-mirror-provisioning",
    "src/private/worm-mirror-worker.ts",
  ],
  [
    "../wrangler.worm-version-observer.jsonc",
    "dpone-release-worm-version-observer-provisioning",
    "src/private/worm-version-observer-worker.ts",
  ],
];
for (const [path, expectedName, expectedMain] of authorityWorkerConfigs) {
  const config = parseReviewedJsonc(readFileSync(new URL(path, import.meta.url), "utf8"), path);
  if (
    config.name !== expectedName ||
    config.main !== expectedMain ||
    config.compatibility_date !== "2026-08-15" ||
    config.workers_dev !== false ||
    config.preview_urls !== false ||
    JSON.stringify(config.observability) !== JSON.stringify(expectedObservability) ||
    JSON.stringify(config.vars) !== JSON.stringify({ OPERATING_MODE: "provisioning" }) ||
    JSON.stringify(config.version_metadata) !==
      JSON.stringify({ binding: "CF_VERSION_METADATA" }) ||
    "account_id" in config ||
    "route" in config ||
    "routes" in config ||
    "services" in config
  ) {
    throw new Error(`authority Worker provisioning boundary drift: ${path}`);
  }
}

for (const filename of Object.keys(LIVE_WORKER_IDENTITIES)) {
  const path = new URL(`../${filename}`, import.meta.url);
  if (existsSync(path)) loadLiveWorkerConfig(path.pathname);
}

const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
assertProviderPackageScripts(packageJson);

const productionEffectModuleExports = Object.entries(PRODUCTION_EFFECT_MODULE_EXPORTS);
const productionEffectSources = new Map(
  productionEffectModuleExports.map(([filename]) => [
    filename,
    readFileSync(new URL(`./${filename}`, import.meta.url), "utf8"),
  ]),
);
productionEffectSources.set(
  "provider-mutation-hold.mjs",
  readFileSync(new URL("./provider-mutation-hold.mjs", import.meta.url), "utf8"),
);
assertProviderBoundarySources(
  PROVIDER_MUTATION_BOUNDARIES,
  PROVIDER_MUTATION_ENTRYPOINTS,
  productionEffectSources,
);

const scriptNames = readdirSync(new URL(".", import.meta.url));
const productionScriptSources = new Map(
  PRODUCTION_SCRIPT_INVENTORY.map((filename) => [
    filename,
    readFileSync(new URL(`./${filename}`, import.meta.url), "utf8"),
  ]),
);
assertProductionScriptInventory(scriptNames, productionScriptSources);
assertProductionGraphExcludesTests(productionScriptSources);

const actualProviderSimulationModules = scriptNames.filter((filename) =>
  /^test-[a-z0-9-]+-(?:engine|simulation)\.mjs$/u.test(filename),
);
assertProviderSimulationsAreDataOnly(
  actualProviderSimulationModules,
  new Map(
    PROVIDER_SIMULATION_MODULES.map((filename) => [
      filename,
      readFileSync(new URL(`./${filename}`, import.meta.url), "utf8"),
    ]),
  ),
);

const bootstrapProvisionerModules = [
  "bootstrap-live-workers.mjs",
  "bootstrap-live-workers-common.mjs",
  "bootstrap-live-workers-deploy.mjs",
  "bootstrap-live-workers-plan.mjs",
  "bootstrap-live-workers-smoke.mjs",
  "bootstrap-worker-config.mjs",
];
const bootstrapProvisionerSources = new Map(
  bootstrapProvisionerModules.map((filename) => [
    filename,
    readFileSync(new URL(`./${filename}`, import.meta.url), "utf8"),
  ]),
);
const actualBootstrapProvisionerModules = readdirSync(new URL(".", import.meta.url)).filter(
  (filename) =>
    /^bootstrap-live-workers(?:-[a-z-]+)?\.mjs$/u.test(filename) ||
    filename === "bootstrap-worker-config.mjs",
);
assertClosedModuleInventory({
  actual: actualBootstrapProvisionerModules,
  boundary: /^(?:bootstrap-live-workers(?:-[a-z-]+)?|bootstrap-worker-config)\.mjs$/u,
  inventory: bootstrapProvisionerModules,
  root: "bootstrap-live-workers.mjs",
  sources: bootstrapProvisionerSources,
});
const bootstrapProvisioner = bootstrapProvisionerModules
  .map((filename) => bootstrapProvisionerSources.get(filename))
  .join("\n");
if (
  !bootstrapProvisioner.includes('"src/bootstrap-private.ts"') ||
  !bootstrapProvisioner.includes('"src/bootstrap-ingress.ts"') ||
  !bootstrapProvisioner.includes('"src/bootstrap-worm.ts"') ||
  !/"deployments"\s*,\s*"status"\s*,\s*"--json"/u.test(bootstrapProvisioner) ||
  !/"versions"\s*,\s*"view"/u.test(bootstrapProvisioner) ||
  !bootstrapProvisioner.includes('"--strict"') ||
  bootstrapProvisioner.includes('"--secrets-file"') ||
  !bootstrapProvisioner.includes("lifecycle_migrations: lifecycleMigrationProjection(workers)") ||
  !bootstrapProvisioner.includes("bootstrap_secret_absent: true") ||
  /WORM_RPC_AUTH_KEY/u.test(bootstrapProvisioner) ||
  /"versions"\s*,\s*"(?:upload|deploy|secret)"/u.test(bootstrapProvisioner)
) {
  throw new Error("blank-account bootstrap must remain one-use, deny-only and provider-requeried");
}

const keyProvisioner = readFileSync(
  new URL("./provision-github-app-key.mjs", import.meta.url),
  "utf8",
);
if (
  !/"versions"\s*,\s*"secret"\s*,\s*"put"/u.test(keyProvisioner) ||
  /\[\s*wrangler\s*,\s*"secret"\s*,\s*"put"/u.test(keyProvisioner) ||
  !keyProvisioner.includes("inspectLiveConfig(options.config)")
) {
  throw new Error("GitHub App key provisioning must create an undeployed immutable version");
}

const cloudflareObserverProvisioner = readFileSync(
  new URL("./provision-cloudflare-deployment-observer-token.mjs", import.meta.url),
  "utf8",
);
if (
  !cloudflareObserverProvisioner.includes("provider_mutation_performed: false") ||
  !cloudflareObserverProvisioner.includes('status: options.verify ? "READY_FOR_PAIRED_CEREMONY"') ||
  !cloudflareObserverProvisioner.includes('"--verify"') ||
  /"versions"\s*,\s*"(?:upload|secret|deploy|list|view)"/u.test(cloudflareObserverProvisioner) ||
  /(?:spawnSync|fetch\s*\()/u.test(cloudflareObserverProvisioner)
) {
  throw new Error("Cloudflare observer token verification must remain provider-effect-free");
}

const wormRpcKeyCeremonyModules = [
  "provision-worm-rpc-key.mjs",
  "provision-worm-rpc-key-arguments.mjs",
  "provision-worm-rpc-key-ceremony.mjs",
  "provision-worm-rpc-key-constants.mjs",
  "provision-worm-rpc-key-crypto.mjs",
  "provision-worm-rpc-key-inputs.mjs",
  "provision-worm-rpc-key-journal.mjs",
  "provision-worm-rpc-key-provider.mjs",
  "provision-worm-rpc-key-report.mjs",
  "provision-worm-rpc-key-uploads.mjs",
  "provision-worm-rpc-key-validation.mjs",
];
const wormRpcKeyCeremonySources = new Map(
  wormRpcKeyCeremonyModules.map((filename) => [
    filename,
    readFileSync(new URL(`./${filename}`, import.meta.url), "utf8"),
  ]),
);
const actualWormRpcKeyCeremonyModules = readdirSync(new URL(".", import.meta.url)).filter(
  (filename) => /^provision-worm-rpc-key(?:-[a-z-]+)?\.mjs$/u.test(filename),
);
assertClosedModuleInventory({
  actual: actualWormRpcKeyCeremonyModules,
  boundary: /^provision-worm-rpc-key(?:-[a-z-]+)?\.mjs$/u,
  inventory: wormRpcKeyCeremonyModules,
  root: "provision-worm-rpc-key.mjs",
  sources: wormRpcKeyCeremonySources,
});
const wormRpcKeyProvisioner = wormRpcKeyCeremonyModules
  .map((filename) => wormRpcKeyCeremonySources.get(filename))
  .join("\n");
if (
  !/"versions"\s*,\s*"upload"\s*,\s*"--strict"/u.test(wormRpcKeyProvisioner) ||
  /"versions"\s*,\s*"secret"\s*,\s*"put"/u.test(wormRpcKeyProvisioner) ||
  !wormRpcKeyProvisioner.includes(
    "`WORM_EXPECTED_CALLER_SERVICE_IDENTITY:${serviceIdentities.expectedCallerServiceIdentity}`",
  ) ||
  !wormRpcKeyProvisioner.includes(
    "`WORM_EXPECTED_B2_OBSERVER_SERVICE_IDENTITY:${serviceIdentities.expectedB2ObserverServiceIdentity}`",
  ) ||
  !wormRpcKeyProvisioner.includes(
    "worm_expected_b2_observer_service_identity: expectedB2ObserverServiceIdentity",
  ) ||
  !wormRpcKeyProvisioner.includes('"--secrets-file"') ||
  !wormRpcKeyProvisioner.includes('ingress_upload_mode: "final-code-version-upload"') ||
  !wormRpcKeyProvisioner.includes("validateBootstrapProvenance(") ||
  !wormRpcKeyProvisioner.includes("bootstrap_provenance: bootstrapProvenance") ||
  !wormRpcKeyProvisioner.includes('"--bootstrap-report"') ||
  !wormRpcKeyProvisioner.includes('"--observer-secret"') ||
  !wormRpcKeyProvisioner.includes('"--writer-secret"') ||
  !wormRpcKeyProvisioner.includes('"READY_FOR_PRIVATE_PREFLIGHT"') ||
  !wormRpcKeyProvisioner.includes("requeryVersion(") ||
  /(?:^|["'\s])deploy(?:["'\s]|$)/mu.test(wormRpcKeyProvisioner) ||
  !wormRpcKeyProvisioner.includes("inspectConfig(options.ingressConfig)") ||
  !wormRpcKeyProvisioner.includes("inspectConfig(options.wormConfig)")
) {
  throw new Error(
    "WORM RPC key provisioning must upload an undeployed final-code ingress/WORM pair",
  );
}
