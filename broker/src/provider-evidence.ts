import { canonicalJson, digestObject, sha256Hex } from "./canonical";
import { CLOUDFLARE_UUID } from "./cloudflare-ids";
import { TRUST } from "./config";
import { assert, BrokerError } from "./errors";
import {
  githubRulesetProjectionDigest,
  projectGitHubRuleset,
  validateGitHubRulesetProjection,
} from "./github-ruleset-projection";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export const RAW_PROVIDER_EVIDENCE_KIND = "github_oidc_subject_customization" as const;
export const GITHUB_BRANCH_RULESET_EVIDENCE_KIND = "github_branch_ruleset" as const;
export type RawProviderEvidenceKind =
  | typeof RAW_PROVIDER_EVIDENCE_KIND
  | typeof GITHUB_BRANCH_RULESET_EVIDENCE_KIND;
export const PROVIDER_EVIDENCE_FIELDS = [
  "evidence_kind",
  "http_status",
  "method",
  "observed_at",
  "observation_sha256",
  "observer_role",
  "observer_service_identity",
  "observer_worker_version_id",
  "path",
  "projection",
  "projection_sha256",
  "provider",
  "provider_api_version",
  "query",
  "raw_response_base64url",
  "raw_response_sha256",
  "repository",
  "repository_id",
  "request_id",
  "response_headers",
  "schema",
  "schema_version",
] as const;

/**
 * Security boundary for evidence that may retain raw provider bytes.
 *
 * Only fixed read-only provider responses are admitted: GitHub OIDC subject
 * customization and the target branch ruleset. Cloudflare control-plane
 * responses contain operator identity fields and therefore use a dedicated
 * transient reparse boundary; they are intentionally absent from this union.
 * Credential/capability endpoints (tokens, signed URLs, B2 authorization and
 * upload URLs) likewise have no discriminant and cannot be WORMed.
 */
export async function assertRetainableProviderEvidence(
  value: unknown,
  expectedKind: string,
): Promise<JsonObject> {
  assert(
    expectedKind === RAW_PROVIDER_EVIDENCE_KIND ||
      expectedKind === GITHUB_BRANCH_RULESET_EVIDENCE_KIND,
    "RAW_EVIDENCE_KIND_FORBIDDEN",
    500,
  );
  const evidence = exactObject(value, PROVIDER_EVIDENCE_FIELDS);
  requireLiteral(evidence, "schema", "dpone.release-broker-provider-evidence-entry.v1");
  requireExactInteger(evidence, "schema_version", 1);
  requireLiteral(evidence, "evidence_kind", expectedKind);
  requireLiteral(evidence, "provider", "github");
  requireLiteral(evidence, "provider_api_version", "2026-03-10");
  requireLiteral(evidence, "method", "GET");
  assert(evidence.query === "", "RAW_EVIDENCE_QUERY_FORBIDDEN", 500);
  requireExactInteger(evidence, "http_status", 200);

  const repository = requireString(evidence, "repository", 64);
  const expectedRepositoryId =
    repository === TRUST.controllerRepository
      ? TRUST.controllerRepositoryId
      : repository === TRUST.targetRepository
        ? TRUST.targetRepositoryId
        : 0;
  assert(expectedRepositoryId !== 0, "RAW_EVIDENCE_REPOSITORY_INVALID", 500);
  requireExactInteger(evidence, "repository_id", expectedRepositoryId);
  if (expectedKind === GITHUB_BRANCH_RULESET_EVIDENCE_KIND) {
    requireLiteral(evidence, "repository", TRUST.targetRepository);
    requireLiteral(evidence, "observer_role", "governance_reader");
  } else {
    requireLiteral(evidence, "path", `/repos/${repository}/actions/oidc/customization/sub`);
    requireLiteral(
      evidence,
      "observer_role",
      repository === TRUST.controllerRepository ? "controller_run_reader" : "governance_reader",
    );
  }

  const version = requireString(evidence, "observer_worker_version_id", 128, CLOUDFLARE_UUID);
  const identity = requireString(
    evidence,
    "observer_service_identity",
    512,
    /^cloudflare-worker:[0-9a-f]{32}[/][a-z0-9][a-z0-9-]{1,127}@[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u,
  );
  assert(identity.endsWith(`@${version}`), "RAW_EVIDENCE_OBSERVER_IDENTITY_INVALID", 500);
  requireString(evidence, "observed_at", 32, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u);
  requireString(evidence, "request_id", 128, /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u);
  const headers = exactObject(evidence.response_headers, ["content_type"]);
  requireLiteral(headers, "content_type", "application/json");

  const rawLimit = expectedKind === GITHUB_BRANCH_RULESET_EVIDENCE_KIND ? 32_768 : 4_096;
  const encodedLimit = expectedKind === GITHUB_BRANCH_RULESET_EVIDENCE_KIND ? 43_691 : 8_192;
  const raw = decodeCanonicalBase64url(
    requireString(
      evidence,
      "raw_response_base64url",
      encodedLimit,
      new RegExp(`^[A-Za-z0-9_-]{2,${encodedLimit}}$`, "u"),
    ),
  );
  assert(raw.byteLength <= rawLimit, "RAW_EVIDENCE_BODY_TOO_LARGE", 500);
  requireLiteral(evidence, "raw_response_sha256", `sha256:${await sha256Hex(raw)}`);
  const [rawProjection, projection] =
    expectedKind === GITHUB_BRANCH_RULESET_EVIDENCE_KIND
      ? rulesetProjections(raw, evidence)
      : [decodeSafeOidcProjection(raw), safeOidcProjection(evidence.projection)];
  assert(
    canonicalJson(rawProjection) === canonicalJson(projection),
    "RAW_EVIDENCE_PROJECTION_MISMATCH",
    500,
  );
  if (expectedKind === RAW_PROVIDER_EVIDENCE_KIND) {
    const expectedPrefix = immutableSubjectPrefix(repository, expectedRepositoryId);
    assert(
      projection.use_default === true &&
        projection.use_immutable_subject === true &&
        projection.sub_claim_prefix === expectedPrefix,
      "RAW_EVIDENCE_CONFIGURATION_INVALID",
      500,
    );
  }
  requireLiteral(
    evidence,
    "projection_sha256",
    expectedKind === GITHUB_BRANCH_RULESET_EVIDENCE_KIND
      ? await githubRulesetProjectionDigest(projection)
      : await digestObject(projection),
  );
  const unsigned = { ...evidence };
  delete unsigned.observation_sha256;
  requireLiteral(evidence, "observation_sha256", await digestObject(unsigned));
  return evidence;
}

function rulesetProjections(raw: Uint8Array, evidence: JsonObject): [JsonObject, JsonObject] {
  const supplied = evidence.projection;
  assert(
    supplied !== null && typeof supplied === "object" && !Array.isArray(supplied),
    "RAW_EVIDENCE_BODY_INVALID",
    500,
  );
  const rulesetId = requireInteger(supplied, "id", 1, Number.MAX_SAFE_INTEGER);
  requireLiteral(evidence, "path", `/repos/${TRUST.targetRepository}/rulesets/${rulesetId}`);
  const projection = validateGitHubRulesetProjection(supplied, {
    repository: TRUST.targetRepository,
    repositoryId: TRUST.targetRepositoryId,
    rulesetId,
  });
  const rawObject = decodeProviderObject(raw);
  const rawProjection = projectGitHubRuleset(rawObject, {
    repository: TRUST.targetRepository,
    repositoryId: TRUST.targetRepositoryId,
    rulesetId,
  });
  assert(
    projection.enforcement === "active" &&
      projection.source === TRUST.targetRepository &&
      projection.source_type === "Repository" &&
      JSON.stringify(projection.bypass_actors) === "[]" &&
      JSON.stringify(projection.conditions) ===
        JSON.stringify({ exclude: [], include: [TRUST.targetDefaultBranchRef] }),
    "RAW_EVIDENCE_CONFIGURATION_INVALID",
    500,
  );
  return [rawProjection, projection];
}

function decodeProviderObject(bytes: Uint8Array): JsonObject {
  let decoded: unknown;
  try {
    decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new BrokerError("RAW_EVIDENCE_BODY_INVALID", 500, false);
  }
  assert(
    decoded !== null && typeof decoded === "object" && !Array.isArray(decoded),
    "RAW_EVIDENCE_BODY_INVALID",
    500,
  );
  return decoded as JsonObject;
}

function decodeSafeOidcProjection(bytes: Uint8Array): JsonObject {
  let decoded: unknown;
  try {
    decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new BrokerError("RAW_EVIDENCE_BODY_INVALID", 500, false);
  }
  return safeOidcProjection(decoded);
}

function safeOidcProjection(value: unknown): JsonObject {
  const projection = exactObject(value, [
    "sub_claim_prefix",
    "use_default",
    "use_immutable_subject",
  ]);
  requireString(projection, "sub_claim_prefix", 256);
  assert(typeof projection.use_default === "boolean", "RAW_EVIDENCE_BODY_INVALID", 500);
  assert(typeof projection.use_immutable_subject === "boolean", "RAW_EVIDENCE_BODY_INVALID", 500);
  return projection;
}

function decodeCanonicalBase64url(value: string): Uint8Array {
  if (value.length % 4 === 1) {
    throw new BrokerError("RAW_EVIDENCE_BASE64URL_INVALID", 500, false);
  }
  let binary: string;
  try {
    binary = atob(
      value
        .replaceAll("-", "+")
        .replaceAll("_", "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "="),
    );
  } catch {
    throw new BrokerError("RAW_EVIDENCE_BASE64URL_INVALID", 500, false);
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  assert(encodeBase64url(bytes) === value, "RAW_EVIDENCE_BASE64URL_NONCANONICAL", 500);
  return bytes;
}

function encodeBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function immutableSubjectPrefix(repository: string, repositoryId: number): string {
  return `repo:PaulKov@74862786/${repository.split("/")[1]}@${repositoryId}`;
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, Math.max(1, expected.length)) === expected,
    "RAW_EVIDENCE_CONTRACT_INVALID",
    500,
  );
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "RAW_EVIDENCE_CONTRACT_INVALID",
    500,
  );
}
