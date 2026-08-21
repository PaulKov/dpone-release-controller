export const CONFIG_SCHEMA = "node_modules/wrangler/config-schema.json";
export const COMPATIBILITY_DATE = "2026-08-15";
export const ACCOUNT_ID = /^[0-9a-f]{32}$/u;
export const POSITIVE_ID = /^[1-9][0-9]{0,15}$/u;
export const SHA256_HEX = /^[0-9a-f]{64}$/u;
export const B2_BUCKET_ID = /^[0-9a-f]{24}$/u;
export const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/u;
export const ACCESS_ID = /^[0-9a-f](?:[0-9a-f-]{14,126}[0-9a-f])$/u;
export const ACCESS_AUDIENCE = /^[A-Za-z0-9_-]{20,128}$/u;
export const ACCESS_ISSUER = /^https:\/\/[a-z0-9][a-z0-9-]{1,62}\.cloudflareaccess\.com$/u;
export const HOSTNAME =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/u;
export const SECRET_NAME =
  /(?:API_TOKEN|PRIVATE_KEY|APPLICATION_KEY|AUTHORIZATION_TOKEN|CLIENT_SECRET|RPC_AUTH_KEY|B2_KEY_ID|ADMIN_ACCESS_GROUP|ADMIN_ACCESS_IDENTITY|ADMIN_ACCESS_SUBJECT_ID)/u;
export const WORM_CALLER_IDENTITY_CEREMONY_SENTINEL = "INJECTED_BY_WORM_RPC_KEY_CEREMONY";
export const AUTHORITY_VERSION_CEREMONY_SENTINEL = "INJECTED_BY_AUTHORITY_VERSION_CEREMONY";

export const EXPECTED_OBSERVABILITY = Object.freeze({
  enabled: false,
  head_sampling_rate: 0,
  traces: Object.freeze({
    destinations: Object.freeze([]),
    enabled: false,
    head_sampling_rate: 0,
    persist: false,
  }),
});

export const LIVE_WORKERS = Object.freeze({
  "wrangler.attestation-mutator.live.jsonc": Object.freeze({
    kind: "deny",
    main: "src/private/fail-closed-worker.ts",
    name: "dpone-release-attestation-mutator",
  }),
  "wrangler.live.jsonc": Object.freeze({
    kind: "ingress",
    main: "src/index.ts",
    name: "dpone-release-authority-broker",
  }),
  "wrangler.candidate-reader.live.jsonc": Object.freeze({
    kind: "candidate",
    main: "src/private/candidate-reader-worker.ts",
    name: "dpone-release-candidate-reader",
  }),
  "wrangler.cloudflare-deployment-observer.live.jsonc": Object.freeze({
    kind: "cloudflare_observer",
    main: "src/private/cloudflare-deployment-observer-worker.ts",
    name: "dpone-release-cloudflare-deployment-observer",
  }),
  "wrangler.closed-projector.live.jsonc": Object.freeze({
    kind: "deny",
    main: "src/private/fail-closed-worker.ts",
    name: "dpone-release-closed-projector",
  }),
  "wrangler.controller-run-reader.live.jsonc": Object.freeze({
    kind: "controller",
    main: "src/private/controller-run-reader-worker.ts",
    name: "dpone-release-controller-run-reader",
  }),
  "wrangler.governance-reader.live.jsonc": Object.freeze({
    kind: "governance",
    main: "src/private/governance-reader-worker.ts",
    name: "dpone-release-governance-reader",
  }),
  "wrangler.pypi-deployment-gate.live.jsonc": Object.freeze({
    kind: "deny",
    main: "src/private/fail-closed-worker.ts",
    name: "dpone-release-pypi-deployment-gate",
  }),
  "wrangler.pypi-reader.live.jsonc": Object.freeze({
    kind: "deny",
    main: "src/private/fail-closed-worker.ts",
    name: "dpone-release-pypi-reader",
  }),
  "wrangler.release-mutator.live.jsonc": Object.freeze({
    kind: "deny",
    main: "src/private/fail-closed-worker.ts",
    name: "dpone-release-mutator",
  }),
  "wrangler.runtime-deployment-gate.live.jsonc": Object.freeze({
    kind: "deny",
    main: "src/private/fail-closed-worker.ts",
    name: "dpone-release-runtime-deployment-gate",
  }),
  "wrangler.tenant-scanner.live.jsonc": Object.freeze({
    kind: "deny",
    main: "src/private/fail-closed-worker.ts",
    name: "dpone-release-tenant-scanner",
  }),
  "wrangler.worm-mirror.live.jsonc": Object.freeze({
    kind: "worm",
    main: "src/private/worm-mirror-worker.ts",
    name: "dpone-release-worm-mirror",
  }),
  "wrangler.worm-version-observer.live.jsonc": Object.freeze({
    kind: "observer",
    main: "src/private/worm-version-observer-worker.ts",
    name: "dpone-release-worm-version-observer",
  }),
});

export const INGRESS_SERVICES = Object.freeze([
  ["ATTESTATION_MUTATOR", "dpone-release-attestation-mutator"],
  ["CANDIDATE_READER", "dpone-release-candidate-reader"],
  ["CLOSED_PROJECTOR", "dpone-release-closed-projector"],
  ["CLOUDFLARE_DEPLOYMENT_OBSERVER", "dpone-release-cloudflare-deployment-observer"],
  ["CONTROLLER_RUN_READER", "dpone-release-controller-run-reader"],
  ["GOVERNANCE_READER", "dpone-release-governance-reader"],
  ["PYPI_DEPLOYMENT_GATE", "dpone-release-pypi-deployment-gate"],
  ["PYPI_READER", "dpone-release-pypi-reader"],
  ["RELEASE_MUTATOR", "dpone-release-mutator"],
  ["RUNTIME_DEPLOYMENT_GATE", "dpone-release-runtime-deployment-gate"],
  ["TENANT_SCANNER", "dpone-release-tenant-scanner"],
  ["WORM_MIRROR", "dpone-release-worm-mirror"],
  ["WORM_VERSION_OBSERVER", "dpone-release-worm-version-observer"],
]);
