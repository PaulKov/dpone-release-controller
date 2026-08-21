import { INTERNAL_RESPONSE_READ_POLICY, readBoundedBytes } from "../bounded";
import { digestObject, sha256Hex } from "../canonical";
import { CLOUDFLARE_UUID } from "../cloudflare-ids";
import { TRUST } from "../config";
import { assert, BrokerError } from "../errors";
import { githubRulesetProjectionDigest, projectGitHubRuleset } from "../github-ruleset-projection";
import {
  assertRetainableProviderEvidence,
  GITHUB_BRANCH_RULESET_EVIDENCE_KIND,
} from "../provider-evidence";
import type { JsonObject } from "../types";
import { exactObject, requireInteger, requireString } from "../validation";
import type { InstallationTokenSource } from "./github-app";
import { githubRequest, requireExactGitHubJsonResponse, requireGitHubOk } from "./github-provider";

export const TARGET_RULESET_RPC_PATH = "/rpc/v1/a0/target-ruleset";
export const TARGET_RULESET_REQUEST_SCHEMA = "dpone.target-ruleset-observation-request.v1";
export const TARGET_RULESET_OBSERVATION_SCHEMA = "dpone.release-broker-provider-evidence-entry.v1";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const POSITIVE_ID = /^[1-9][0-9]{0,15}$/u;
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;
const VERSION = CLOUDFLARE_UUID;
const SERVICE_IDENTITY =
  /^cloudflare-worker:[0-9a-f]{32}\/[a-z0-9][a-z0-9-]{1,127}@[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;
const MAX_RULESET_BYTES = 32_768;

export interface TargetRulesetRequest {
  readonly branchRulesetId: string;
  readonly branchRulesetProjectionSha256: string;
  readonly requestId: string;
}

/** Fresh, read-only A0 ruleset observation with bounded non-secret raw evidence. */
export class TargetRulesetReader {
  public constructor(
    private readonly tokens: InstallationTokenSource,
    private readonly serviceIdentity: string,
    private readonly serviceVersionId: string,
    private readonly providerFetch: typeof fetch = fetch,
    private readonly now: () => number = Date.now,
  ) {}

  public async observe(request: TargetRulesetRequest): Promise<JsonObject> {
    validateRequest(request);
    assert(SERVICE_IDENTITY.test(this.serviceIdentity), "TARGET_RULESET_SERVICE_INVALID", 500);
    assert(VERSION.test(this.serviceVersionId), "TARGET_RULESET_SERVICE_INVALID", 500);
    assert(
      this.serviceIdentity.endsWith(`@${this.serviceVersionId}`),
      "TARGET_RULESET_SERVICE_INVALID",
      500,
    );
    const token = await this.tokens.installationToken();
    const path = `/repos/${TRUST.targetRepository}/rulesets/${request.branchRulesetId}` as const;
    const response = await githubRequest(this.providerFetch, {
      authorization: `Bearer ${token}`,
      method: "GET",
      path,
    });
    await requireGitHubOk(response, "TARGET_RULESET_PROVIDER_FAILED");
    await requireExactGitHubJsonResponse(response, 200, "TARGET_RULESET_PROVIDER_INVALID");
    const raw = await readBoundedBytes(
      response,
      MAX_RULESET_BYTES,
      "TARGET_RULESET_PROVIDER_INVALID",
      INTERNAL_RESPONSE_READ_POLICY,
    );
    const projection = projectGitHubRuleset(decodeProviderJson(raw), {
      repository: TRUST.targetRepository,
      repositoryId: TRUST.targetRepositoryId,
      rulesetId: Number(request.branchRulesetId),
    });
    const projectionSha256 = await githubRulesetProjectionDigest(projection);
    if (projectionSha256 !== request.branchRulesetProjectionSha256) {
      throw new BrokerError("TARGET_RULESET_PROVIDER_DRIFT", 503, false);
    }
    const body: JsonObject = {
      evidence_kind: GITHUB_BRANCH_RULESET_EVIDENCE_KIND,
      http_status: 200,
      method: "GET",
      observed_at: canonicalUtcSeconds(this.now()),
      observer_role: "governance_reader",
      observer_service_identity: this.serviceIdentity,
      observer_worker_version_id: this.serviceVersionId,
      path,
      projection,
      projection_sha256: projectionSha256,
      provider: "github",
      provider_api_version: "2026-03-10",
      query: "",
      raw_response_base64url: encodeBase64url(raw),
      raw_response_sha256: `sha256:${await sha256Hex(raw)}`,
      repository: TRUST.targetRepository,
      repository_id: TRUST.targetRepositoryId,
      request_id: request.requestId,
      response_headers: { content_type: "application/json" },
      schema: TARGET_RULESET_OBSERVATION_SCHEMA,
      schema_version: 1,
    };
    const evidence = { ...body, observation_sha256: await digestObject(body) };
    await assertRetainableProviderEvidence(evidence, GITHUB_BRANCH_RULESET_EVIDENCE_KIND);
    return evidence;
  }
}

function decodeProviderJson(bytes: Uint8Array): JsonObject {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new BrokerError("TARGET_RULESET_PROVIDER_INVALID", 503, false);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("TARGET_RULESET_PROVIDER_INVALID", 503, false);
  }
  return value as JsonObject;
}

function encodeBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function parseTargetRulesetRequest(value: unknown): TargetRulesetRequest {
  const body = exactObject(value, [
    "branch_ruleset_id",
    "branch_ruleset_projection_sha256",
    "repository_id",
    "request_id",
    "schema",
    "schema_version",
  ]);
  requireLiteral(body, "schema", TARGET_RULESET_REQUEST_SCHEMA);
  requireExactInteger(body, "schema_version", 1);
  requireExactInteger(body, "repository_id", TRUST.targetRepositoryId);
  const request = {
    branchRulesetId: requireString(body, "branch_ruleset_id", 16, POSITIVE_ID),
    branchRulesetProjectionSha256: requireString(
      body,
      "branch_ruleset_projection_sha256",
      71,
      DIGEST,
    ),
    requestId: requireString(body, "request_id", 128, REQUEST_ID),
  };
  validateRequest(request);
  return request;
}

function validateRequest(request: TargetRulesetRequest): void {
  const id = Number(request.branchRulesetId);
  if (
    !POSITIVE_ID.test(request.branchRulesetId) ||
    !Number.isSafeInteger(id) ||
    !DIGEST.test(request.branchRulesetProjectionSha256) ||
    !REQUEST_ID.test(request.requestId)
  ) {
    throw new BrokerError("TARGET_RULESET_REQUEST_INVALID", 400, false);
  }
}

function canonicalUtcSeconds(value: number): string {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new BrokerError("TARGET_RULESET_TIME_INVALID", 500, false);
  }
  return new Date(Math.floor(value / 1000) * 1000).toISOString().replace(".000Z", "Z");
}

function requireLiteral(value: JsonObject, key: string, expected: string): void {
  assert(requireString(value, key, expected.length) === expected, "TARGET_RULESET_REQUEST_INVALID");
}

function requireExactInteger(value: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(value, key, expected, expected) === expected,
    "TARGET_RULESET_REQUEST_INVALID",
  );
}
