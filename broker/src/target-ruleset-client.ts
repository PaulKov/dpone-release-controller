import { INTERNAL_RESPONSE_READ_POLICY, readBoundedBytes } from "./bounded";
import { canonicalBytes, canonicalJson, digestObject, sha256Hex } from "./canonical";
import { TRUST } from "./config";
import { assert, BrokerError } from "./errors";
import {
  githubRulesetProjectionDigest,
  validateGitHubRulesetProjection,
} from "./github-ruleset-projection";
import {
  assertRetainableProviderEvidence,
  GITHUB_BRANCH_RULESET_EVIDENCE_KIND,
  PROVIDER_EVIDENCE_FIELDS,
} from "./provider-evidence";
import {
  TARGET_RULESET_OBSERVATION_SCHEMA,
  TARGET_RULESET_REQUEST_SCHEMA,
  TARGET_RULESET_RPC_PATH,
} from "./private/target-ruleset-reader";
import { assertPinnedServiceVersion, callPinnedService } from "./service-version";
import type { JsonObject, JsonValue, PrivateServicePin } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;
const MAX_RESPONSE_BYTES = 1_048_576;

export interface TargetRulesetObservation {
  readonly evidence: JsonObject;
  readonly evidenceCanonicalSha256: string;
  readonly projection: JsonObject;
  readonly projectionSha256: string;
  readonly summary: JsonObject;
  readonly summarySha256: string;
}

/** Pinned ingress adapter for the independently observed A0 ruleset. */
export class TargetRulesetClient {
  public constructor(
    private readonly service: Fetcher,
    private readonly pin: PrivateServicePin,
    private readonly now: () => number = Date.now,
  ) {}

  public async observe(
    branchRulesetId: string,
    expectedProjection: JsonObject,
    expectedProjectionSha256: string,
    requestId: string,
  ): Promise<TargetRulesetObservation> {
    const bytes = buildTargetRulesetObservationRequest(
      branchRulesetId,
      expectedProjectionSha256,
      requestId,
    );
    const response = await callPinnedService(this.service, this.pin, {
      body: Uint8Array.from(bytes).buffer,
      headers: {
        "content-length": String(bytes.byteLength),
        "content-type": "application/json",
        "x-request-id": requestId,
      },
      method: "POST",
      path: TARGET_RULESET_RPC_PATH,
    });
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new BrokerError(
        "TARGET_RULESET_OBSERVATION_FAILED",
        503,
        response.status === 429 || response.status >= 500,
      );
    }
    if (
      response.headers.get("content-type")?.split(";", 1)[0]?.trim() !== "application/json" ||
      response.headers.get("x-request-id") !== requestId ||
      response.headers.has("content-encoding") ||
      response.headers.has("content-range") ||
      response.headers.has("location") ||
      response.headers.has("set-cookie") ||
      response.headers.has("transfer-encoding")
    ) {
      await response.body?.cancel().catch(() => undefined);
      throw new BrokerError("TARGET_RULESET_OBSERVATION_INVALID", 503, false);
    }
    const responseBytes = await readBoundedBytes(
      response,
      MAX_RESPONSE_BYTES,
      "TARGET_RULESET_OBSERVATION_TOO_LARGE",
      INTERNAL_RESPONSE_READ_POLICY,
    );
    let text: string;
    let decoded: unknown;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(responseBytes);
      decoded = JSON.parse(text);
    } catch {
      throw new BrokerError("TARGET_RULESET_OBSERVATION_INVALID", 503, false);
    }
    const observation = exactObject(decoded, PROVIDER_EVIDENCE_FIELDS);
    assert(text === canonicalJson(observation), "TARGET_RULESET_OBSERVATION_NONCANONICAL", 503);
    const parsed = await parseTargetRulesetObservation(observation, {
      branchRulesetId,
      expectedProjection,
      expectedProjectionSha256,
      pin: this.pin,
      requestId,
    });
    const freshness =
      this.now() - Date.parse(requireString(parsed.evidence, "observed_at", 32, TIMESTAMP));
    assert(freshness >= -30_000 && freshness <= 60_000, "TARGET_RULESET_OBSERVATION_STALE", 503);
    return parsed;
  }
}

/** Build the exact request bytes that must be journaled before provider I/O. */
export function buildTargetRulesetObservationRequest(
  branchRulesetId: string,
  expectedProjectionSha256: string,
  requestId: string,
): Uint8Array {
  return canonicalBytes({
    branch_ruleset_id: branchRulesetId,
    branch_ruleset_projection_sha256: expectedProjectionSha256,
    repository_id: TRUST.targetRepositoryId,
    request_id: requestId,
    schema: TARGET_RULESET_REQUEST_SCHEMA,
    schema_version: 1,
  });
}

/** Re-validate one frozen canonical ruleset response without a freshness clock. */
export async function parseTargetRulesetObservation(
  value: unknown,
  expected: {
    readonly branchRulesetId: string;
    readonly expectedProjection: JsonObject;
    readonly expectedProjectionSha256: string;
    readonly pin: PrivateServicePin;
    readonly requestId: string;
  },
): Promise<TargetRulesetObservation> {
  const observation = await assertRetainableProviderEvidence(
    value,
    GITHUB_BRANCH_RULESET_EVIDENCE_KIND,
  );
  requireLiteral(observation, "schema", TARGET_RULESET_OBSERVATION_SCHEMA);
  requireExactInteger(observation, "schema_version", 1);
  requireLiteral(observation, "evidence_kind", GITHUB_BRANCH_RULESET_EVIDENCE_KIND);
  requireLiteral(observation, "repository", TRUST.targetRepository);
  requireExactInteger(observation, "repository_id", TRUST.targetRepositoryId);
  requireLiteral(observation, "request_id", expected.requestId);
  requireLiteral(observation, "provider_api_version", "2026-03-10");
  requireLiteral(observation, "observer_role", "governance_reader");
  requireLiteral(observation, "observer_service_identity", expected.pin.serviceIdentity);
  assertPinnedServiceVersion(
    requireString(observation, "observer_worker_version_id", 128),
    expected.pin,
  );
  requireString(observation, "raw_response_sha256", 71, DIGEST);
  requireString(observation, "observed_at", 32, TIMESTAMP);
  const projection = validateGitHubRulesetProjection(observation.projection, {
    repository: TRUST.targetRepository,
    repositoryId: TRUST.targetRepositoryId,
    rulesetId: Number(expected.branchRulesetId),
  });
  const projectionSha256 = requireString(observation, "projection_sha256", 71, DIGEST);
  assert(
    canonicalJson(projection) === canonicalJson(expected.expectedProjection) &&
      projectionSha256 === expected.expectedProjectionSha256 &&
      projectionSha256 === (await githubRulesetProjectionDigest(projection)),
    "TARGET_RULESET_OBSERVATION_MISMATCH",
    503,
  );
  const summary: JsonObject = {
    evidence_kind: requiredJsonValue(observation, "evidence_kind"),
    http_status: requiredJsonValue(observation, "http_status"),
    method: requiredJsonValue(observation, "method"),
    observation_sha256: requiredJsonValue(observation, "observation_sha256"),
    observed_at: requiredJsonValue(observation, "observed_at"),
    observer_role: requiredJsonValue(observation, "observer_role"),
    observer_service_identity: requiredJsonValue(observation, "observer_service_identity"),
    observer_worker_version_id: requiredJsonValue(observation, "observer_worker_version_id"),
    path: requiredJsonValue(observation, "path"),
    projection_sha256: requiredJsonValue(observation, "projection_sha256"),
    provider: requiredJsonValue(observation, "provider"),
    provider_api_version: requiredJsonValue(observation, "provider_api_version"),
    query: requiredJsonValue(observation, "query"),
    raw_response_sha256: requiredJsonValue(observation, "raw_response_sha256"),
    repository: requiredJsonValue(observation, "repository"),
    repository_id: requiredJsonValue(observation, "repository_id"),
    request_id: requiredJsonValue(observation, "request_id"),
    response_headers: requiredJsonValue(observation, "response_headers"),
    schema: "dpone.target-ruleset-observation-summary.v1",
    schema_version: 1,
  };
  return {
    evidence: observation,
    evidenceCanonicalSha256: `sha256:${await sha256Hex(canonicalBytes(observation))}`,
    projection,
    projectionSha256,
    summary,
    summarySha256: await digestObject(summary),
  };
}

function requiredJsonValue(value: JsonObject, key: string): JsonValue {
  const candidate = value[key];
  assert(candidate !== undefined, "TARGET_RULESET_OBSERVATION_MISMATCH", 503);
  return candidate;
}

function requireLiteral(value: JsonObject, key: string, expected: string): void {
  assert(
    requireString(value, key, Math.max(1, expected.length)) === expected,
    "TARGET_RULESET_OBSERVATION_MISMATCH",
    503,
  );
}

function requireExactInteger(value: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(value, key, expected, expected) === expected,
    "TARGET_RULESET_OBSERVATION_MISMATCH",
    503,
  );
}
