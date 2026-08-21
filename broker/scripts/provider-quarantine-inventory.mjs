import { REVIEWED_LOCAL_DATA_FLOW_CAPABILITIES_A } from "./provider-quarantine-reviewed-data-flows-a.mjs";
import { REVIEWED_LOCAL_DATA_FLOW_CAPABILITIES_B } from "./provider-quarantine-reviewed-data-flows-b.mjs";
import { REVIEWED_LOCAL_NODE_DIGESTS_A } from "./provider-quarantine-reviewed-node-digests-a.mjs";
import { REVIEWED_LOCAL_NODE_DIGESTS_B } from "./provider-quarantine-reviewed-node-digests-b.mjs";

export { PROVIDER_EFFECT_DATA_EXPORTS } from "./provider-quarantine-effect-data.mjs";
export { PROVIDER_SIMULATION_PROGRAM_DIGESTS } from "./provider-quarantine-simulation-program.mjs";
export {
  PRODUCTION_EFFECT_MODULE_EXPORTS,
  PRODUCTION_MODULE_EXPORTS,
  PRODUCTION_SCRIPT_INVENTORY,
} from "./provider-quarantine-production-exports.mjs";
export { PRODUCTION_IMPORT_DIGESTS } from "./provider-quarantine-production-imports.mjs";

export const PROVIDER_MUTATION_ENTRYPOINT_INVENTORY = Object.freeze([
  "bootstrap-live-apply",
  "cloudflare-observer-token-verify",
  "github-app-key-apply",
  "version-deploy",
  "version-upload",
  "worm-authority-apply",
]);
export const PROVIDER_BOUNDARY_INVENTORY = Object.freeze([
  item("bootstrap-live-apply", "bootstrap-live-workers-common.mjs", "taggedSha256"),
  item("bootstrap-live-apply", "bootstrap-live-workers-deploy.mjs", "deployBootstrapWorker"),
  item("bootstrap-live-apply", "bootstrap-live-workers-deploy.mjs", "requeryDeployment"),
  item("bootstrap-live-apply", "bootstrap-live-workers-plan.mjs", "buildPlan"),
  item("bootstrap-live-apply", "bootstrap-live-workers-plan.mjs", "materializeBootstrapConfig"),
  item("bootstrap-live-apply", "bootstrap-live-workers-plan.mjs", "assertPlanBytesUnchanged"),
  item("bootstrap-live-apply", "bootstrap-live-workers-plan.mjs", "namedExports"),
  item("bootstrap-live-apply", "bootstrap-live-workers-smoke.mjs", "smokeBootstrap"),
  item("bootstrap-live-apply", "bootstrap-live-workers.mjs", "main"),
  item("bootstrap-live-apply", "bootstrap-live-workers.mjs", "runBootstrapEngine"),
  item("bootstrap-live-apply", "bootstrap-live-workers.mjs", "parseArguments"),
  item("bootstrap-live-apply", "bootstrap-live-workers.mjs", "assertResolvedLiveNetworkSurface"),
  item("bootstrap-live-apply", "bootstrap-worker-config.mjs", "buildBootstrapWorkerConfig"),
  item(
    "bootstrap-live-apply",
    "bootstrap-worker-config.mjs",
    "canonicalBootstrapWorkerConfigBytes",
  ),
  item("bootstrap-live-apply", "bootstrap-worker-config.mjs", "assertBootstrapWorkerConfig"),
  item("version-deploy", "deploy-version.mjs", "main"),
  item("version-deploy", "deploy-version.mjs", "runVersionDeployment"),
  item("version-deploy", "deploy-version.mjs", "parseArguments"),
  item("version-upload", "upload-version.mjs", "main"),
  item("version-upload", "upload-version.mjs", "runVersionUpload"),
  item("version-upload", "upload-version.mjs", "parseArguments"),
  item(
    "cloudflare-observer-token-verify",
    "provision-cloudflare-deployment-observer-token.mjs",
    "main",
  ),
  item(
    "cloudflare-observer-token-verify",
    "provision-cloudflare-deployment-observer-token.mjs",
    "runCloudflareObserverTokenVerification",
  ),
  item(
    "cloudflare-observer-token-verify",
    "provision-cloudflare-deployment-observer-token.mjs",
    "parseArguments",
  ),
  item(
    "cloudflare-observer-token-verify",
    "provision-cloudflare-deployment-observer-token.mjs",
    "readTokenDocument",
  ),
  item(
    "cloudflare-observer-token-verify",
    "provision-cloudflare-deployment-observer-token.mjs",
    "readRestrictionEvidence",
  ),
  item(
    "cloudflare-observer-token-verify",
    "provision-cloudflare-deployment-observer-token.mjs",
    "readProviderPolicyEvidence",
  ),
  item("github-app-key-apply", "provision-github-app-key.mjs", "main"),
  item("github-app-key-apply", "provision-github-app-key.mjs", "runGithubAppKeyProvision"),
  item("github-app-key-apply", "provision-github-app-key.mjs", "parseArguments"),
  item("worm-authority-apply", "provision-worm-rpc-key-arguments.mjs", "parseArguments"),
  item("worm-authority-apply", "provision-worm-rpc-key-ceremony.mjs", "runCeremonyCommand"),
  item("worm-authority-apply", "provision-worm-rpc-key-ceremony.mjs", "runCeremony"),
  item("worm-authority-apply", "provision-worm-rpc-key-ceremony.mjs", "runCeremonyEngine"),
  item("worm-authority-apply", "provision-worm-rpc-key-crypto.mjs", "canonicalBytes"),
  item("worm-authority-apply", "provision-worm-rpc-key-crypto.mjs", "taggedSha256"),
  item("worm-authority-apply", "provision-worm-rpc-key-inputs.mjs", "readB2SecretDocument"),
  item("worm-authority-apply", "provision-worm-rpc-key-inputs.mjs", "readRestrictionEvidence"),
  item("worm-authority-apply", "provision-worm-rpc-key-inputs.mjs", "readPrivateFile"),
  item("worm-authority-apply", "provision-worm-rpc-key-inputs.mjs", "readAdminPrincipalDocument"),
  item("worm-authority-apply", "provision-worm-rpc-key-inputs.mjs", "adminPrincipalDigests"),
  item(
    "worm-authority-apply",
    "provision-worm-rpc-key-inputs.mjs",
    "readCloudflareObserverRestriction",
  ),
  item(
    "worm-authority-apply",
    "provision-worm-rpc-key-inputs.mjs",
    "validateCloudflareObserverConfig",
  ),
  item(
    "worm-authority-apply",
    "provision-worm-rpc-key-inputs.mjs",
    "validateAuthorityNetworkCrossBind",
  ),
  item("worm-authority-apply", "provision-worm-rpc-key-inputs.mjs", "ceremonyVariableOverrides"),
  item("worm-authority-apply", "provision-worm-rpc-key-inputs.mjs", "authoritySecretNames"),
  item("worm-authority-apply", "provision-worm-rpc-key-inputs.mjs", "validateB2Config"),
  item("worm-authority-apply", "provision-worm-rpc-key-journal.mjs", "reserveResult"),
  item("worm-authority-apply", "provision-worm-rpc-key-journal.mjs", "restoreRecoveredState"),
  item("worm-authority-apply", "provision-worm-rpc-key-journal.mjs", "appendJournalEntry"),
  item("worm-authority-apply", "provision-worm-rpc-key-provider.mjs", "uploadFinalVersion"),
  item("worm-authority-apply", "provision-worm-rpc-key-provider.mjs", "requireUnusedVersionTag"),
  item("worm-authority-apply", "provision-worm-rpc-key-provider.mjs", "discoverRecoverableVersion"),
  item("worm-authority-apply", "provision-worm-rpc-key-provider.mjs", "requeryVersion"),
  item("worm-authority-apply", "provision-worm-rpc-key-report.mjs", "initialCeremonyState"),
  item("worm-authority-apply", "provision-worm-rpc-key-report.mjs", "ceremonyReport"),
  item("worm-authority-apply", "provision-worm-rpc-key-report.mjs", "callerIdentity"),
  item("worm-authority-apply", "provision-worm-rpc-key-report.mjs", "serviceIdentity"),
  item("worm-authority-apply", "provision-worm-rpc-key-uploads.mjs", "emitRecoveredTerminal"),
  item("worm-authority-apply", "provision-worm-rpc-key-uploads.mjs", "completeAuthorityUploads"),
  item("worm-authority-apply", "provision-worm-rpc-key-validation.mjs", "validateInspectedConfig"),
  item(
    "worm-authority-apply",
    "provision-worm-rpc-key-validation.mjs",
    "validateBootstrapProvenance",
  ),
  item("worm-authority-apply", "provision-worm-rpc-key.mjs", "appendJournalEntry"),
  item("worm-authority-apply", "provision-worm-rpc-key.mjs", "parseArguments"),
  item("worm-authority-apply", "provision-worm-rpc-key.mjs", "main"),
  item("worm-authority-apply", "worker-version-resource-common.mjs", "compareProjected"),
  item("worm-authority-apply", "worker-version-resource-common.mjs", "compareNamed"),
  item("worm-authority-apply", "worker-version-resource-common.mjs", "exactKeys"),
  item("worm-authority-apply", "worker-version-resource-common.mjs", "allowedKeys"),
  item("worm-authority-apply", "worker-version-resource-common.mjs", "record"),
  item("worm-authority-apply", "worker-version-resource-common.mjs", "canonicalJson"),
  item(
    "worm-authority-apply",
    "worker-version-resource-provider.mjs",
    "projectWorkerVersionResources",
  ),
  item(
    "worm-authority-apply",
    "worker-version-resource-validation.mjs",
    "validateWorkerVersionResourceProjection",
  ),
  item(
    "worm-authority-apply",
    "worker-version-resource-validation.mjs",
    "canonicalWorkerVersionResourceProjectionBytes",
  ),
  item("worm-authority-apply", "worker-version-resources.mjs", "projectWorkerVersionResources"),
  item(
    "worm-authority-apply",
    "worker-version-resources.mjs",
    "canonicalWorkerVersionResourceProjectionBytes",
  ),
  item(
    "worm-authority-apply",
    "worker-version-resources.mjs",
    "validateWorkerVersionResourceProjection",
  ),
]);

export const PROVIDER_SIMULATION_EXPORTS = Object.freeze({
  "test-bootstrap-live-workers-engine.mjs": Object.freeze(["runBootstrapForTest"]),
  "test-provider-trace-simulation.mjs": Object.freeze([
    "parseSimulationInput",
    "simulateBootstrap",
    "simulateCloudflareObserverTokenVerification",
    "simulateGithubAppKeyProvision",
    "simulateVersionDeployment",
    "simulateVersionUpload",
    "simulateWormCeremony",
  ]),
  "test-worm-rpc-key-engine.mjs": Object.freeze(["provisionAuthorityKeysForTest"]),
});
export const PROVIDER_SIMULATION_MODULES = Object.freeze(
  Object.keys(PROVIDER_SIMULATION_EXPORTS).sort(),
);
export const PROVIDER_SIMULATION_DELEGATES = Object.freeze({
  "test-bootstrap-live-workers-engine.mjs": Object.freeze({
    imported: "simulateBootstrap",
    source: "./test-provider-trace-simulation.mjs",
    symbol: "runBootstrapForTest",
  }),
  "test-worm-rpc-key-engine.mjs": Object.freeze({
    imported: "simulateWormCeremony",
    source: "./test-provider-trace-simulation.mjs",
    symbol: "provisionAuthorityKeysForTest",
  }),
});

export const PROVIDER_SIMULATION_IMPORT_DIGESTS = Object.freeze({
  "test-bootstrap-live-workers-engine.mjs":
    "dde0bd7d87f65419f12d759b716e1d951f7cfd6882fa6ad5862e6c884854f3e2",
  "test-provider-trace-simulation.mjs":
    "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
  "test-worm-rpc-key-engine.mjs":
    "4ee4dcc5c7b2bd046dd8b8d2d5712251f6752c267d8a9476a80b6469090558da",
});
export const PROVIDER_SIMULATION_FUNCTION_DIGESTS = Object.freeze({
  "test-bootstrap-live-workers-engine.mjs#runBootstrapForTest":
    "f2a735b00a2ac6e88680b11fe60e1ce4f8df9d7e8dc8456ff60ee50bc0263e4c",
  "test-provider-trace-simulation.mjs#parseSimulationInput":
    "17dbf49ab41a1f533446ce5d322bda6508adbb35df2bb3cbaab75a582e7ac62f",
  "test-provider-trace-simulation.mjs#requireExactRoles":
    "3c6ee27e1fab36271557dbe905a868cd84dd37365318fe391d0359c32966b163",
  "test-provider-trace-simulation.mjs#requireNextRole":
    "844e66ee66543118ef4abcd5fddc7c0d61e50e95c114e0d484daf60fd9077956",
  "test-provider-trace-simulation.mjs#requireRole":
    "8dbcbea1aed08ee0850bcc6469ef2f9e0226bab8377b44645020478e117fc167",
  "test-provider-trace-simulation.mjs#requireVersionMetadata":
    "c7771591b0df01f63cc819060ed5ae9a82486310962473974e3a69a61df04bd2",
  "test-provider-trace-simulation.mjs#simulateBootstrap":
    "db805d2eb9c92a11e617aad50460caa7b6cdad75bd8c233eb55e5fe8efbdcc17",
  "test-provider-trace-simulation.mjs#simulateCloudflareObserverTokenVerification":
    "2158adef57d4011c2c1cefa4b8e3d16542ec4a5506de866d3f5bcbf68deee4fa",
  "test-provider-trace-simulation.mjs#simulateGithubAppKeyProvision":
    "5c3b9e37e121f3011ecac9f4d8027724a76e4a40ea277aa1de164d97f79a6913",
  "test-provider-trace-simulation.mjs#simulateVersionDeployment":
    "34b06fdfcc05b3e95bc2e7cc7de626481388f8ea88c602690b9d9b731dfb2c87",
  "test-provider-trace-simulation.mjs#simulateVersionUpload":
    "be00f202ed48e66172233f4acf1231686928ab32483d370a52a472d9154c3551",
  "test-provider-trace-simulation.mjs#simulateWormCeremony":
    "cdd38733c4700fa3b1a545174a6777d6cb5d44fc8430f79d8badb22a073b9760",
  "test-worm-rpc-key-engine.mjs#provisionAuthorityKeysForTest":
    "f130f5c58883b019f5b0956939d845a81b6afb2ce09b739b18f52c258d225adc",
});
export const LOCAL_CAPABILITY_OWNERS = Object.freeze({
  ...REVIEWED_LOCAL_DATA_FLOW_CAPABILITIES_A,
  ...REVIEWED_LOCAL_DATA_FLOW_CAPABILITIES_B,
});
export const LOCAL_CAPABILITY_OWNER_AST_DIGESTS = Object.freeze({
  ...REVIEWED_LOCAL_NODE_DIGESTS_A,
  ...REVIEWED_LOCAL_NODE_DIGESTS_B,
});

function item(entrypoint, module, symbol) {
  return Object.freeze({ entrypoint, module, symbol });
}
