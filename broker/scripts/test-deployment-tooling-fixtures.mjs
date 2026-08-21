import { strict as assert } from "node:assert";
import { resolve } from "node:path";

import {
  AUTHORITY_VERSION_CEREMONY_SENTINEL,
  WORM_CALLER_IDENTITY_CEREMONY_SENTINEL,
} from "./live-worker-config.mjs";

const ACCOUNT_ID = "0123456789abcdef0123456789abcdef";
const CONFIG_SCHEMA = "node_modules/wrangler/config-schema.json";
const B2_BUCKET_ID = "0123456789abcdef01234567";
const OBSERVABILITY = {
  enabled: false,
  head_sampling_rate: 0,
  traces: {
    destinations: [],
    enabled: false,
    head_sampling_rate: 0,
    persist: false,
  },
};

export const STABLE = "123e4567-e89b-42d3-a456-426614174000";
export const CANDIDATE = "123e4567-e89b-42d3-a456-426614174001";
export const LIVE_CONFIG = resolve("wrangler.controller-run-reader.live.jsonc");
export const INGRESS_LIVE_CONFIG = resolve("wrangler.live.jsonc");
export const OBSERVER_LIVE_CONFIG = resolve("wrangler.worm-version-observer.live.jsonc");
export const WORM_LIVE_CONFIG = resolve("wrangler.worm-mirror.live.jsonc");
export const PAIRED_AUTHORITY_CONFIGS = new Map([
  [INGRESS_LIVE_CONFIG, "dpone-release-authority-broker"],
  [OBSERVER_LIVE_CONFIG, "dpone-release-worm-version-observer"],
  [WORM_LIVE_CONFIG, "dpone-release-worm-mirror"],
]);

export function privateConfig() {
  return liveConfig("wrangler.controller-run-reader.live.jsonc");
}

export function liveConfig(filename) {
  const definitions = {
    "wrangler.attestation-mutator.live.jsonc": {
      main: "src/private/fail-closed-worker.ts",
      name: "dpone-release-attestation-mutator",
      vars: { OPERATING_MODE: "live", SERVICE_NAME: "dpone-release-attestation-mutator" },
    },
    "wrangler.candidate-reader.live.jsonc": {
      main: "src/private/candidate-reader-worker.ts",
      name: "dpone-release-candidate-reader",
      vars: {
        CANDIDATE_READER_SERVICE_NAME: "dpone-release-candidate-reader",
        CF_ACCOUNT_ID: ACCOUNT_ID,
        GITHUB_APP_ID: "9000000000000001",
        GITHUB_APP_INSTALLATION_ID: "9000000000000002",
        OPERATING_MODE: "live",
      },
    },
    "wrangler.closed-projector.live.jsonc": {
      main: "src/private/fail-closed-worker.ts",
      name: "dpone-release-closed-projector",
      vars: {
        OPERATING_MODE: "live",
        SERVICE_NAME: "dpone-release-closed-projector",
      },
    },
    "wrangler.cloudflare-deployment-observer.live.jsonc": {
      main: "src/private/cloudflare-deployment-observer-worker.ts",
      name: "dpone-release-cloudflare-deployment-observer",
      services: [{ binding: "WORM_MIRROR", service: "dpone-release-worm-mirror" }],
      vars: {
        APPROVED_INGRESS_HOSTNAME: "release.example.test",
        APPROVED_INGRESS_ZONE_ID: ACCOUNT_ID,
        CF_ACCOUNT_ID: ACCOUNT_ID,
        EXPECTED_INGRESS_SERVICE_IDENTITY: AUTHORITY_VERSION_CEREMONY_SENTINEL,
        OPERATING_MODE: "live",
        SERVICE_NAME: "dpone-release-cloudflare-deployment-observer",
      },
    },
    "wrangler.controller-run-reader.live.jsonc": {
      main: "src/private/controller-run-reader-worker.ts",
      name: "dpone-release-controller-run-reader",
      vars: {
        CF_ACCOUNT_ID: ACCOUNT_ID,
        GITHUB_APP_ID: "9000000000000003",
        GITHUB_APP_INSTALLATION_ID: "9000000000000004",
        GITHUB_APP_SLUG: "dpone-release-controller",
        OPERATING_MODE: "live",
        SERVICE_NAME: "dpone-release-controller-run-reader",
      },
    },
    "wrangler.governance-reader.live.jsonc": {
      main: "src/private/governance-reader-worker.ts",
      name: "dpone-release-governance-reader",
      vars: {
        CF_ACCOUNT_ID: ACCOUNT_ID,
        GITHUB_APP_ID: "9000000000000005",
        GITHUB_APP_INSTALLATION_ID: "9000000000000006",
        OPERATING_MODE: "live",
        SERVICE_NAME: "dpone-release-governance-reader",
      },
    },
    "wrangler.pypi-deployment-gate.live.jsonc": {
      main: "src/private/fail-closed-worker.ts",
      name: "dpone-release-pypi-deployment-gate",
      vars: {
        OPERATING_MODE: "live",
        SERVICE_NAME: "dpone-release-pypi-deployment-gate",
      },
    },
    "wrangler.pypi-reader.live.jsonc": {
      main: "src/private/fail-closed-worker.ts",
      name: "dpone-release-pypi-reader",
      vars: { OPERATING_MODE: "live", SERVICE_NAME: "dpone-release-pypi-reader" },
    },
    "wrangler.release-mutator.live.jsonc": {
      main: "src/private/fail-closed-worker.ts",
      name: "dpone-release-mutator",
      vars: {
        OPERATING_MODE: "live",
        SERVICE_NAME: "dpone-release-mutator",
      },
    },
    "wrangler.runtime-deployment-gate.live.jsonc": {
      main: "src/private/fail-closed-worker.ts",
      name: "dpone-release-runtime-deployment-gate",
      vars: {
        OPERATING_MODE: "live",
        SERVICE_NAME: "dpone-release-runtime-deployment-gate",
      },
    },
    "wrangler.tenant-scanner.live.jsonc": {
      main: "src/private/fail-closed-worker.ts",
      name: "dpone-release-tenant-scanner",
      vars: { OPERATING_MODE: "live", SERVICE_NAME: "dpone-release-tenant-scanner" },
    },
    "wrangler.live.jsonc": {
      durable_objects: {
        bindings: [
          { class_name: "ActivationRegistry", name: "ACTIVATION_REGISTRY" },
          { class_name: "AuthReplayLedger", name: "AUTH_REPLAY_LEDGER" },
          {
            class_name: "GlobalActivatedAuthorityHead",
            name: "GLOBAL_ACTIVATED_AUTHORITY_HEAD",
          },
          { class_name: "ReleaseLedger", name: "RELEASE_LEDGERS" },
        ],
      },
      main: "src/index.ts",
      migrations: [
        { new_sqlite_classes: ["AuthReplayLedger", "ReleaseLedger"], tag: "v1" },
        { new_sqlite_classes: ["ActivationRegistry"], tag: "v2" },
        { new_sqlite_classes: ["GlobalActivatedAuthorityHead"], tag: "v3" },
      ],
      name: "dpone-release-authority-broker",
      routes: [{ custom_domain: true, pattern: "release.example.test" }],
      services: [
        { binding: "ATTESTATION_MUTATOR", service: "dpone-release-attestation-mutator" },
        { binding: "CANDIDATE_READER", service: "dpone-release-candidate-reader" },
        { binding: "CLOSED_PROJECTOR", service: "dpone-release-closed-projector" },
        {
          binding: "CLOUDFLARE_DEPLOYMENT_OBSERVER",
          service: "dpone-release-cloudflare-deployment-observer",
        },
        {
          binding: "CONTROLLER_RUN_READER",
          service: "dpone-release-controller-run-reader",
        },
        { binding: "GOVERNANCE_READER", service: "dpone-release-governance-reader" },
        { binding: "PYPI_DEPLOYMENT_GATE", service: "dpone-release-pypi-deployment-gate" },
        { binding: "PYPI_READER", service: "dpone-release-pypi-reader" },
        { binding: "RELEASE_MUTATOR", service: "dpone-release-mutator" },
        {
          binding: "RUNTIME_DEPLOYMENT_GATE",
          service: "dpone-release-runtime-deployment-gate",
        },
        { binding: "TENANT_SCANNER", service: "dpone-release-tenant-scanner" },
        { binding: "WORM_MIRROR", service: "dpone-release-worm-mirror" },
        {
          binding: "WORM_VERSION_OBSERVER",
          service: "dpone-release-worm-version-observer",
        },
      ],
      vars: {
        ADMIN_ACCESS_APPLICATION_ID: "123e4567-e89b-42d3-a456-426614174000",
        ADMIN_ACCESS_AUDIENCE: "review-template-audience-0001",
        ADMIN_ACCESS_ISSUER: "https://review-template.cloudflareaccess.com",
        ADMIN_ACCESS_POLICY_ID: "123e4567-e89b-42d3-a456-426614174002",
        ADMIN_HOSTNAME: "release.example.test",
        ADMIN_MTLS_CERT_SHA256: "a".repeat(64),
        BROKER_SERVICE_NAME: "dpone-release-authority-broker",
        CF_ACCOUNT_ID: ACCOUNT_ID,
        OPERATING_MODE: "live",
      },
    },
    "wrangler.worm-mirror.live.jsonc": {
      durable_objects: {
        bindings: [
          { class_name: "CloudflareEvidenceBatch", name: "CLOUDFLARE_EVIDENCE_BATCHES" },
          { class_name: "WormExactObjectEffect", name: "WORM_EXACT_OBJECT_EFFECTS" },
        ],
      },
      main: "src/private/worm-mirror-worker.ts",
      migrations: [
        { new_sqlite_classes: ["CloudflareEvidenceBatch"], tag: "v1" },
        { new_sqlite_classes: ["WormExactObjectEffect"], tag: "v2" },
      ],
      name: "dpone-release-worm-mirror",
      services: [
        {
          binding: "WORM_VERSION_OBSERVER",
          service: "dpone-release-worm-version-observer",
        },
      ],
      vars: {
        B2_BUCKET_ID,
        B2_BUCKET_NAME: "dpone-release-evidence",
        CF_ACCOUNT_ID: ACCOUNT_ID,
        OPERATING_MODE: "live",
        SERVICE_NAME: "dpone-release-worm-mirror",
        WORM_EXPECTED_B2_OBSERVER_SERVICE_IDENTITY: AUTHORITY_VERSION_CEREMONY_SENTINEL,
        WORM_EXPECTED_CALLER_SERVICE_IDENTITY: WORM_CALLER_IDENTITY_CEREMONY_SENTINEL,
        WORM_EXPECTED_CLOUDFLARE_OBSERVER_SERVICE_IDENTITY: AUTHORITY_VERSION_CEREMONY_SENTINEL,
      },
    },
    "wrangler.worm-version-observer.live.jsonc": {
      main: "src/private/worm-version-observer-worker.ts",
      name: "dpone-release-worm-version-observer",
      vars: {
        B2_BUCKET_ID,
        B2_BUCKET_NAME: "dpone-release-evidence",
        OPERATING_MODE: "live",
      },
    },
  };
  const definition = definitions[filename];
  assert.ok(definition);
  return {
    $schema: CONFIG_SCHEMA,
    account_id: ACCOUNT_ID,
    compatibility_date: "2026-08-15",
    ...definition,
    observability: JSON.parse(JSON.stringify(OBSERVABILITY)),
    preview_urls: false,
    version_metadata: { binding: "CF_VERSION_METADATA" },
    workers_dev: false,
  };
}
