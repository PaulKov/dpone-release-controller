/**
 * Closed inventory of executable provider-mutation boundaries.
 *
 * Publication review templates are deliberately incapable of authorizing an
 * effect. Lifting this HOLD requires a reviewed source change to this module;
 * environment variables, CLI flags, dependency injection and local files are
 * intentionally not consulted.
 */
export const PROVIDER_MUTATION_ENTRYPOINTS = Object.freeze([
  "bootstrap-live-apply",
  "cloudflare-observer-token-verify",
  "github-app-key-apply",
  "version-deploy",
  "version-upload",
  "worm-authority-apply",
]);
export const PROVIDER_MUTATION_BOUNDARIES = Object.freeze([
  boundary("bootstrap-live-apply", "bootstrap-live-workers-common.mjs", "taggedSha256"),
  boundary("bootstrap-live-apply", "bootstrap-live-workers-deploy.mjs", "deployBootstrapWorker"),
  boundary("bootstrap-live-apply", "bootstrap-live-workers-deploy.mjs", "requeryDeployment"),
  boundary("bootstrap-live-apply", "bootstrap-live-workers-plan.mjs", "buildPlan"),
  boundary("bootstrap-live-apply", "bootstrap-live-workers-plan.mjs", "materializeBootstrapConfig"),
  boundary("bootstrap-live-apply", "bootstrap-live-workers-plan.mjs", "assertPlanBytesUnchanged"),
  boundary("bootstrap-live-apply", "bootstrap-live-workers-plan.mjs", "namedExports"),
  boundary("bootstrap-live-apply", "bootstrap-live-workers-smoke.mjs", "smokeBootstrap"),
  boundary("bootstrap-live-apply", "bootstrap-live-workers.mjs", "main"),
  boundary("bootstrap-live-apply", "bootstrap-live-workers.mjs", "runBootstrapEngine"),
  boundary("bootstrap-live-apply", "bootstrap-live-workers.mjs", "parseArguments"),
  boundary(
    "bootstrap-live-apply",
    "bootstrap-live-workers.mjs",
    "assertResolvedLiveNetworkSurface",
  ),
  boundary("bootstrap-live-apply", "bootstrap-worker-config.mjs", "buildBootstrapWorkerConfig"),
  boundary(
    "bootstrap-live-apply",
    "bootstrap-worker-config.mjs",
    "canonicalBootstrapWorkerConfigBytes",
  ),
  boundary("bootstrap-live-apply", "bootstrap-worker-config.mjs", "assertBootstrapWorkerConfig"),
  boundary("version-deploy", "deploy-version.mjs", "main"),
  boundary("version-deploy", "deploy-version.mjs", "runVersionDeployment"),
  boundary("version-deploy", "deploy-version.mjs", "parseArguments"),
  boundary("version-upload", "upload-version.mjs", "main"),
  boundary("version-upload", "upload-version.mjs", "runVersionUpload"),
  boundary("version-upload", "upload-version.mjs", "parseArguments"),
  boundary(
    "cloudflare-observer-token-verify",
    "provision-cloudflare-deployment-observer-token.mjs",
    "main",
  ),
  boundary(
    "cloudflare-observer-token-verify",
    "provision-cloudflare-deployment-observer-token.mjs",
    "runCloudflareObserverTokenVerification",
  ),
  boundary(
    "cloudflare-observer-token-verify",
    "provision-cloudflare-deployment-observer-token.mjs",
    "parseArguments",
  ),
  boundary(
    "cloudflare-observer-token-verify",
    "provision-cloudflare-deployment-observer-token.mjs",
    "readTokenDocument",
  ),
  boundary(
    "cloudflare-observer-token-verify",
    "provision-cloudflare-deployment-observer-token.mjs",
    "readRestrictionEvidence",
  ),
  boundary(
    "cloudflare-observer-token-verify",
    "provision-cloudflare-deployment-observer-token.mjs",
    "readProviderPolicyEvidence",
  ),
  boundary("github-app-key-apply", "provision-github-app-key.mjs", "main"),
  boundary("github-app-key-apply", "provision-github-app-key.mjs", "runGithubAppKeyProvision"),
  boundary("github-app-key-apply", "provision-github-app-key.mjs", "parseArguments"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-arguments.mjs", "parseArguments"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-ceremony.mjs", "runCeremonyCommand"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-ceremony.mjs", "runCeremony"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-ceremony.mjs", "runCeremonyEngine"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-crypto.mjs", "canonicalBytes"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-crypto.mjs", "taggedSha256"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-inputs.mjs", "readB2SecretDocument"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-inputs.mjs", "readRestrictionEvidence"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-inputs.mjs", "readPrivateFile"),
  boundary(
    "worm-authority-apply",
    "provision-worm-rpc-key-inputs.mjs",
    "readAdminPrincipalDocument",
  ),
  boundary("worm-authority-apply", "provision-worm-rpc-key-inputs.mjs", "adminPrincipalDigests"),
  boundary(
    "worm-authority-apply",
    "provision-worm-rpc-key-inputs.mjs",
    "readCloudflareObserverRestriction",
  ),
  boundary(
    "worm-authority-apply",
    "provision-worm-rpc-key-inputs.mjs",
    "validateCloudflareObserverConfig",
  ),
  boundary(
    "worm-authority-apply",
    "provision-worm-rpc-key-inputs.mjs",
    "validateAuthorityNetworkCrossBind",
  ),
  boundary(
    "worm-authority-apply",
    "provision-worm-rpc-key-inputs.mjs",
    "ceremonyVariableOverrides",
  ),
  boundary("worm-authority-apply", "provision-worm-rpc-key-inputs.mjs", "authoritySecretNames"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-inputs.mjs", "validateB2Config"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-journal.mjs", "reserveResult"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-journal.mjs", "restoreRecoveredState"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-journal.mjs", "appendJournalEntry"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-provider.mjs", "uploadFinalVersion"),
  boundary(
    "worm-authority-apply",
    "provision-worm-rpc-key-provider.mjs",
    "requireUnusedVersionTag",
  ),
  boundary(
    "worm-authority-apply",
    "provision-worm-rpc-key-provider.mjs",
    "discoverRecoverableVersion",
  ),
  boundary("worm-authority-apply", "provision-worm-rpc-key-provider.mjs", "requeryVersion"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-report.mjs", "initialCeremonyState"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-report.mjs", "ceremonyReport"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-report.mjs", "callerIdentity"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-report.mjs", "serviceIdentity"),
  boundary("worm-authority-apply", "provision-worm-rpc-key-uploads.mjs", "emitRecoveredTerminal"),
  boundary(
    "worm-authority-apply",
    "provision-worm-rpc-key-uploads.mjs",
    "completeAuthorityUploads",
  ),
  boundary(
    "worm-authority-apply",
    "provision-worm-rpc-key-validation.mjs",
    "validateInspectedConfig",
  ),
  boundary(
    "worm-authority-apply",
    "provision-worm-rpc-key-validation.mjs",
    "validateBootstrapProvenance",
  ),
  boundary("worm-authority-apply", "provision-worm-rpc-key.mjs", "appendJournalEntry"),
  boundary("worm-authority-apply", "provision-worm-rpc-key.mjs", "parseArguments"),
  boundary("worm-authority-apply", "provision-worm-rpc-key.mjs", "main"),
  boundary("worm-authority-apply", "worker-version-resource-common.mjs", "compareProjected"),
  boundary("worm-authority-apply", "worker-version-resource-common.mjs", "compareNamed"),
  boundary("worm-authority-apply", "worker-version-resource-common.mjs", "exactKeys"),
  boundary("worm-authority-apply", "worker-version-resource-common.mjs", "allowedKeys"),
  boundary("worm-authority-apply", "worker-version-resource-common.mjs", "record"),
  boundary("worm-authority-apply", "worker-version-resource-common.mjs", "canonicalJson"),
  boundary(
    "worm-authority-apply",
    "worker-version-resource-provider.mjs",
    "projectWorkerVersionResources",
  ),
  boundary(
    "worm-authority-apply",
    "worker-version-resource-validation.mjs",
    "validateWorkerVersionResourceProjection",
  ),
  boundary(
    "worm-authority-apply",
    "worker-version-resource-validation.mjs",
    "canonicalWorkerVersionResourceProjectionBytes",
  ),
  boundary("worm-authority-apply", "worker-version-resources.mjs", "projectWorkerVersionResources"),
  boundary(
    "worm-authority-apply",
    "worker-version-resources.mjs",
    "canonicalWorkerVersionResourceProjectionBytes",
  ),
  boundary(
    "worm-authority-apply",
    "worker-version-resources.mjs",
    "validateWorkerVersionResourceProjection",
  ),
]);

export const PROVIDER_MUTATION_HOLD_CODE = "PROVIDER_MUTATION_HOLD";
export const PROVIDER_MUTATION_HOLD_MARKER = "DPONE_PROVIDER_MUTATION_HOLD_V1";

const INVENTORY = new Set(PROVIDER_MUTATION_ENTRYPOINTS);

/** Always reject a provider effect before credentials, temporary state or I/O are touched. */
export function assertProviderMutationReleased(entrypoint) {
  const classified = typeof entrypoint === "string" && INVENTORY.has(entrypoint);
  const label = classified ? entrypoint : "unclassified-provider-mutation";
  const error = new Error(
    `${PROVIDER_MUTATION_HOLD_CODE}: ${label} is disabled by ${PROVIDER_MUTATION_HOLD_MARKER}`,
  );
  error.code = PROVIDER_MUTATION_HOLD_CODE;
  error.entrypoint = label;
  error.marker = PROVIDER_MUTATION_HOLD_MARKER;
  throw error;
}

function boundary(entrypoint, module, symbol) {
  return Object.freeze({ entrypoint, module, symbol });
}
