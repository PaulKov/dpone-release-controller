import { PUBLICATION_REVIEW_TEMPLATE_HEADER } from "./reviewed-jsonc.mjs";

export const SYNTHETIC_ACCOUNT_ID = "0".repeat(32);

const SYNTHETIC_IDENTIFIER_VALUES = Object.freeze({
  "wrangler.candidate-reader.live.jsonc": Object.freeze({
    CF_ACCOUNT_ID: SYNTHETIC_ACCOUNT_ID,
    GITHUB_APP_ID: "9000000000000001",
    GITHUB_APP_INSTALLATION_ID: "9000000000000002",
  }),
  "wrangler.cloudflare-deployment-observer.live.jsonc": Object.freeze({
    APPROVED_INGRESS_HOSTNAME: "release-authority.invalid",
    APPROVED_INGRESS_ZONE_ID: SYNTHETIC_ACCOUNT_ID,
    CF_ACCOUNT_ID: SYNTHETIC_ACCOUNT_ID,
    EXPECTED_INGRESS_SERVICE_IDENTITY: "INJECTED_BY_AUTHORITY_VERSION_CEREMONY",
  }),
  "wrangler.controller-run-reader.live.jsonc": Object.freeze({
    CF_ACCOUNT_ID: SYNTHETIC_ACCOUNT_ID,
    GITHUB_APP_ID: "9000000000000003",
    GITHUB_APP_INSTALLATION_ID: "9000000000000004",
  }),
  "wrangler.governance-reader.live.jsonc": Object.freeze({
    CF_ACCOUNT_ID: SYNTHETIC_ACCOUNT_ID,
    GITHUB_APP_ID: "9000000000000005",
    GITHUB_APP_INSTALLATION_ID: "9000000000000006",
  }),
  "wrangler.live.jsonc": Object.freeze({
    ADMIN_ACCESS_APPLICATION_ID: "123e4567-e89b-42d3-a456-426614174000",
    ADMIN_ACCESS_AUDIENCE: "review-template-audience-0001",
    ADMIN_ACCESS_ISSUER: "https://review-template.cloudflareaccess.com",
    ADMIN_ACCESS_POLICY_ID: "123e4567-e89b-42d3-a456-426614174002",
    ADMIN_HOSTNAME: "release-authority.invalid",
    ADMIN_MTLS_CERT_SHA256: "0".repeat(64),
    CF_ACCOUNT_ID: SYNTHETIC_ACCOUNT_ID,
  }),
  "wrangler.worm-mirror.live.jsonc": Object.freeze({
    B2_BUCKET_ID: "0".repeat(24),
    CF_ACCOUNT_ID: SYNTHETIC_ACCOUNT_ID,
    WORM_EXPECTED_B2_OBSERVER_SERVICE_IDENTITY: "INJECTED_BY_AUTHORITY_VERSION_CEREMONY",
    WORM_EXPECTED_CALLER_SERVICE_IDENTITY: "INJECTED_BY_WORM_RPC_KEY_CEREMONY",
    WORM_EXPECTED_CLOUDFLARE_OBSERVER_SERVICE_IDENTITY: "INJECTED_BY_AUTHORITY_VERSION_CEREMONY",
  }),
  "wrangler.worm-version-observer.live.jsonc": Object.freeze({
    B2_BUCKET_ID: "0".repeat(24),
  }),
});

const CLASSIFIED_IDENTIFIER = /(?:_AUDIENCE|_HOSTNAME|_ID|_IDENTITY|_ISSUER|_SHA256)$/u;
const FORBIDDEN_DOCUMENT_CLAIMS = Object.freeze([
  /all checked-in Wrangler files are (?:deliberately )?provisioning-only/iu,
  /live configs therefore remain deliberately absent/iu,
  /no checked-in live Wrangler config exists/iu,
  /until that ledger can requery the terminal C5/iu,
  /until the ledger can prove terminal `CLOSED_CHECK_VERIFIED`/iu,
]);
const CREDENTIAL_PATTERNS = Object.freeze([
  /-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----\r?\n(?:[+/0-9A-Za-z=]{16,}\r?\n){4,}-----END (?:EC |OPENSSH |RSA )?PRIVATE KEY-----/u,
  /\bAKIA[0-9A-Z]{16}\b/u,
  /\bgh[pousr]_[0-9A-Za-z]{30,}\b/u,
  /\bgithub_pat_[0-9A-Za-z_]{30,}\b/u,
  /\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b/u,
  /(?:^|\n)\s*_authToken\s*=/u,
]);

export function assertPublishableLiveConfig(filename, source, config) {
  if (!source.startsWith(`${PUBLICATION_REVIEW_TEMPLATE_HEADER}\n`)) {
    throw new Error(`live review template header missing: ${filename}`);
  }
  if (config.account_id !== SYNTHETIC_ACCOUNT_ID) {
    throw new Error(`live review template contains a real or unclassified account ID: ${filename}`);
  }
  const expected = SYNTHETIC_IDENTIFIER_VALUES[filename] ?? Object.freeze({});
  const vars = requireRecord(config.vars, `${filename} vars`);
  const actualKeys = Object.keys(vars)
    .filter((key) => CLASSIFIED_IDENTIFIER.test(key))
    .sort(asciiCompare);
  const expectedKeys = Object.keys(expected).sort(asciiCompare);
  if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
    throw new Error(`live review template has an unclassified identifier field: ${filename}`);
  }
  for (const key of expectedKeys) {
    if (vars[key] !== expected[key]) {
      throw new Error(
        `live review template identifier is not the classified placeholder: ${filename}:${key}`,
      );
    }
  }
  const accountIds = source.match(/\b[0-9a-f]{32}\b/gu) ?? [];
  if (accountIds.some((value) => value !== SYNTHETIC_ACCOUNT_ID)) {
    throw new Error(`live review template contains a non-synthetic 32-hex identifier: ${filename}`);
  }
}

export function assertPublishableDocument(path, source) {
  if (FORBIDDEN_DOCUMENT_CLAIMS.some((pattern) => pattern.test(source))) {
    throw new Error(`publication document contains a stale live-config claim: ${path}`);
  }
  if (/\b[0-9a-f]{32}\b/iu.test(source)) {
    throw new Error(`publication document contains an unclassified 32-hex identifier: ${path}`);
  }
  if (
    path === "README.md" &&
    (!source.includes("test/fixtures/release-receipt-envelope-v2.schema.json") ||
      !source.includes("exact historical broker receipt pin") ||
      !source.includes("grants no runtime authority"))
  ) {
    throw new Error("README must classify the historical receipt fixture as non-runtime authority");
  }
  assertNoCredentialMaterial(path, source);
}

export function assertNoCredentialMaterial(path, source) {
  if (CREDENTIAL_PATTERNS.some((pattern) => pattern.test(source))) {
    throw new Error(`probable credential material is forbidden in publication: ${path}`);
  }
}

export function isForbiddenSecretArtifact(path) {
  return /(?:^|\/)(?:\.dev\.vars(?:\..*)?|\.env(?:\..*)?|[^/]+\.(?:key|p12|pem|pfx)|[^/]*(?:credential|secret)[^/]*\.(?:json|jsonl))$/iu.test(
    path,
  );
}

function requireRecord(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value;
}

function asciiCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}
