import { BrokerError } from "./errors";
import { CLOUDFLARE_UUID } from "./cloudflare-ids";
import type {
  ActivationTrust,
  ControllerActivationTrust,
  LiveConfigEnv,
  OidcRouteTrust,
  ReleaseBinding,
  TrustedRuntimeConfig,
} from "./types";
import { validateWormRpcAuthKey } from "./worm-rpc-auth";

export const BROKER_SCHEMA = "dpone.release-authority-broker.v1";
export const RECEIPT_SCHEMA = "dpone.release-receipt-envelope.v2";

export const TRUST = Object.freeze({
  controllerRepository: "PaulKov/dpone-release-controller",
  controllerRepositoryId: 1_305_993_853,
  controllerWorkflowPath: ".github/workflows/release-controller.yml",
  controllerDefaultBranchRef: "refs/heads/master",
  targetRepository: "PaulKov/dpone",
  targetRepositoryId: 1_255_975_556,
  targetDefaultBranchRef: "refs/heads/master",
  runtimeWorkflowPath: ".github/workflows/runtime-image.yml",
  issuer: "https://token.actions.githubusercontent.com",
  jwks: "https://token.actions.githubusercontent.com/.well-known/jwks",
  routes: Object.freeze({
    ledger: Object.freeze({
      audience: "dpone-release-controller-ledger-write",
      environment: "release-attest",
    }),
    candidate: Object.freeze({
      audience: "dpone-release-controller-candidate-read",
      environment: "release-attest",
    }),
    governance: Object.freeze({
      audience: "dpone-release-controller-governance-read",
      environment: "release-attest",
    }),
    attest: Object.freeze({
      audience: "dpone-release-controller-attest",
      environment: "release-attest",
    }),
    github: Object.freeze({
      audience: "dpone-release-controller-github-release",
      environment: "github-release",
    }),
    pypi: Object.freeze({
      audience: "dpone-release-controller-pypi",
      environment: "pypi",
    }),
    runtime: Object.freeze({
      audience: "dpone-runtime-controller-closure-read",
      environment: "ghcr",
    }),
  }),
});

export type ControllerRoute = "attest" | "candidate" | "github" | "governance" | "ledger" | "pypi";

export const LIMITS = Object.freeze({
  bodyBytes: 65_536,
  jsonDepth: 16,
  jsonNodes: 512,
  maxStringBytes: 32_768,
  queueDepth: 32,
  leaseTtlSeconds: 300,
  renewIntervalSeconds: 45,
  renewWithinSeconds: 60,
  capabilityTtlSeconds: 60,
  recoveryTtlSeconds: 900,
  oidcClockToleranceSeconds: 10,
  oidcAcceptedAgeSeconds: 60,
  oidcMaxAgeSeconds: 600,
  outboxBatch: 8,
  outboxRetryMaxSeconds: 60,
});

const SHA1_HEX = /^[0-9a-f]{40}$/u;
const SHA256_HEX = /^[0-9a-f]{64}$/u;
const WORKER_VERSION = CLOUDFLARE_UUID;
const CF_ACCOUNT_ID = /^[0-9a-f]{32}$/u;
const SERVICE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/u;
const ACCESS_ID = /^[0-9a-f](?:[0-9a-f-]{14,126}[0-9a-f])$/u;
const ACCESS_AUDIENCE = /^[A-Za-z0-9_-]{20,128}$/u;
const ACCESS_IDENTITY = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+$/u;
const ACCESS_GROUP = /^[A-Za-z0-9][A-Za-z0-9 ._:-]{1,127}$/u;
const HOSTNAME = /^[a-z0-9](?:[a-z0-9.-]{1,251}[a-z0-9])$/u;
const ACCESS_ISSUER = /^https:\/\/[a-z0-9][a-z0-9-]{1,62}\.cloudflareaccess\.com$/u;

export function requireLiveConfig(env: LiveConfigEnv): TrustedRuntimeConfig {
  if (env.OPERATING_MODE !== "live") {
    throw new BrokerError("BROKER_PROVISIONING", 503, true);
  }

  const adminMtlsCertSha256 = requireMatch(
    env.ADMIN_MTLS_CERT_SHA256,
    SHA256_HEX,
    "ADMIN_MTLS_TRUST_UNAVAILABLE",
  );
  const adminAccessApplicationId = requireMatch(
    env.ADMIN_ACCESS_APPLICATION_ID,
    ACCESS_ID,
    "ADMIN_ACCESS_CONFIGURATION_UNAVAILABLE",
  );
  const adminAccessAudience = requireMatch(
    env.ADMIN_ACCESS_AUDIENCE,
    ACCESS_AUDIENCE,
    "ADMIN_ACCESS_CONFIGURATION_UNAVAILABLE",
  );
  const adminAccessGroup = requireMatch(
    env.ADMIN_ACCESS_GROUP,
    ACCESS_GROUP,
    "ADMIN_ACCESS_CONFIGURATION_UNAVAILABLE",
  );
  const adminAccessIdentity = requireMatch(
    env.ADMIN_ACCESS_IDENTITY,
    ACCESS_IDENTITY,
    "ADMIN_ACCESS_CONFIGURATION_UNAVAILABLE",
  );
  const adminAccessIssuer = requireMatch(
    env.ADMIN_ACCESS_ISSUER,
    ACCESS_ISSUER,
    "ADMIN_ACCESS_CONFIGURATION_UNAVAILABLE",
  );
  const adminAccessPolicyId = requireMatch(
    env.ADMIN_ACCESS_POLICY_ID,
    ACCESS_ID,
    "ADMIN_ACCESS_CONFIGURATION_UNAVAILABLE",
  );
  const adminAccessSubjectId = requireMatch(
    env.ADMIN_ACCESS_SUBJECT_ID,
    ACCESS_ID,
    "ADMIN_ACCESS_CONFIGURATION_UNAVAILABLE",
  );
  const adminHostname = requireMatch(
    env.ADMIN_HOSTNAME,
    HOSTNAME,
    "ADMIN_ACCESS_CONFIGURATION_UNAVAILABLE",
  );
  const workerVersionId = requireMatch(
    env.CF_VERSION_METADATA?.id,
    WORKER_VERSION,
    "WORKER_VERSION_UNAVAILABLE",
  );
  const cloudflareAccountId = requireMatch(
    env.CF_ACCOUNT_ID,
    CF_ACCOUNT_ID,
    "BROKER_SERVICE_IDENTITY_UNAVAILABLE",
  );
  const brokerServiceName = requireMatch(
    env.BROKER_SERVICE_NAME,
    SERVICE_NAME,
    "BROKER_SERVICE_IDENTITY_UNAVAILABLE",
  );
  const wormRpcAuthKey = validateWormRpcAuthKey(env.WORM_RPC_AUTH_KEY);
  const cloudflareObserverRpcAuthKey = validateWormRpcAuthKey(env.CLOUDFLARE_OBSERVER_RPC_AUTH_KEY);

  requireFetcher(env.ATTESTATION_MUTATOR, "ATTESTATION_MUTATOR_UNAVAILABLE");
  requireFetcher(env.CANDIDATE_READER, "CANDIDATE_READER_UNAVAILABLE");
  requireFetcher(env.CLOSED_PROJECTOR, "CLOSED_PROJECTOR_UNAVAILABLE");
  requireFetcher(env.CLOUDFLARE_DEPLOYMENT_OBSERVER, "CLOUDFLARE_DEPLOYMENT_OBSERVER_UNAVAILABLE");
  requireFetcher(env.CONTROLLER_RUN_READER, "CONTROLLER_RUN_READER_UNAVAILABLE");
  requireFetcher(env.GOVERNANCE_READER, "GOVERNANCE_READER_UNAVAILABLE");
  requireFetcher(env.PYPI_DEPLOYMENT_GATE, "PYPI_DEPLOYMENT_GATE_UNAVAILABLE");
  requireFetcher(env.PYPI_READER, "PYPI_READER_UNAVAILABLE");
  requireFetcher(env.RELEASE_MUTATOR, "RELEASE_MUTATOR_UNAVAILABLE");
  requireFetcher(env.RUNTIME_DEPLOYMENT_GATE, "RUNTIME_DEPLOYMENT_GATE_UNAVAILABLE");
  requireFetcher(env.TENANT_SCANNER, "TENANT_SCANNER_UNAVAILABLE");
  requireFetcher(env.WORM_MIRROR, "WORM_MIRROR_UNAVAILABLE");
  requireFetcher(env.WORM_VERSION_OBSERVER, "WORM_VERSION_OBSERVER_UNAVAILABLE");

  return {
    adminAccessApplicationId,
    adminAccessAudience,
    adminAccessGroup,
    adminAccessIdentity,
    adminAccessIssuer,
    adminAccessPolicyId,
    adminAccessSubjectId,
    adminHostname,
    adminMtlsCertSha256,
    cloudflareAccountId,
    cloudflareObserverRpcAuthKey,
    workerVersionId,
    workerServiceIdentity: `cloudflare-worker:${cloudflareAccountId}/${brokerServiceName}@${workerVersionId}`,
    wormRpcAuthKey,
  };
}

export function isSha256(value: string): boolean {
  return /^sha256:[0-9a-f]{64}$/u.test(value);
}

export function isGitSha(value: string): boolean {
  return SHA1_HEX.test(value);
}

export function controllerRouteTrust(
  activation: ControllerActivationTrust,
  route: ControllerRoute,
): OidcRouteTrust {
  return {
    allowedActorIds: activation.controllerActorIds,
    audience: TRUST.routes[route].audience,
    environment: TRUST.routes[route].environment,
    eventName: "workflow_dispatch",
    ref: activation.controllerRef,
    refType: activation.controllerRefType,
    repository: TRUST.controllerRepository,
    repositoryId: TRUST.controllerRepositoryId,
    repositoryOwnerId: activation.repositoryOwnerId,
    repositoryVisibility: "public",
    workflowPath: TRUST.controllerWorkflowPath,
    workflowSha: activation.controllerWorkflowSha,
  };
}

export function runtimeRouteTrust(
  activation: ActivationTrust,
  binding: ReleaseBinding,
): OidcRouteTrust {
  return {
    allowedActorIds: activation.runtimeActorIds,
    audience: TRUST.routes.runtime.audience,
    environment: TRUST.routes.runtime.environment,
    eventName: "push",
    ref: binding.tagRef,
    refType: "tag",
    repository: TRUST.targetRepository,
    repositoryId: TRUST.targetRepositoryId,
    repositoryOwnerId: activation.repositoryOwnerId,
    repositoryVisibility: "public",
    workflowPath: TRUST.runtimeWorkflowPath,
    workflowSha: binding.peeledCommitSha,
  };
}

function requireMatch(value: string | undefined, pattern: RegExp, code: string): string {
  if (value === undefined || !pattern.test(value)) {
    throw new BrokerError(code, 503, false);
  }
  return value;
}

function requireFetcher(value: Fetcher | undefined, code: string): void {
  if (value === undefined || typeof value.fetch !== "function") {
    throw new BrokerError(code, 503, false);
  }
}
