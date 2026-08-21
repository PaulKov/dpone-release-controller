import { TRUST } from "../config";
import { BrokerError } from "../errors";
import { githubRulesetProjectionDigest, projectGitHubRuleset } from "../github-ruleset-projection";
import { validateTargetLineage, type TargetLineageAuthority } from "../target-lineage";
import type { JsonObject } from "../types";
import { exactObject, requireInteger, requireString } from "../validation";
import {
  githubJsonWithDigest,
  githubRequest,
  providerObject,
  providerString,
  requireGitHubOk,
  requireProviderLiteral,
} from "./github-provider";
import type { InstallationTokenSource } from "./github-app";

export const TARGET_LINEAGE_RPC_PATH = "/rpc/v1/target-lineage";
export const TARGET_LINEAGE_RPC_REQUEST_SCHEMA = "dpone.target-lineage-request.v1";
export const TARGET_LINEAGE_RPC_RESPONSE_SCHEMA = "dpone.target-lineage-observation.v1";

const SHA1 = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;
const POSITIVE_ID = /^[1-9][0-9]{0,31}$/u;
const MAX_COMPARE_BYTES = 4 * 1024 * 1024;
const MAX_REF_BYTES = 65_536;
const MAX_RULESET_BYTES = 1_048_576;

export interface TargetLineageRequest {
  readonly authority: TargetLineageAuthority;
  readonly releaseCommitSha: string;
  readonly requestId: string;
}

/** Read-only GitHub adapter that materializes every lineage field from fresh calls. */
export class TargetLineageReader {
  public constructor(
    private readonly tokens: InstallationTokenSource,
    private readonly providerFetch: typeof fetch = fetch,
    private readonly now: () => number = Date.now,
  ) {}

  public async observe(request: TargetLineageRequest): Promise<JsonObject> {
    validateRequest(request);
    const token = await this.tokens.installationToken();
    const authorization = `Bearer ${token}`;

    const defaultRefPath = `${repositoryPath()}/git/ref/heads/master` as const;
    const defaultRef = await this.read(defaultRefPath, authorization, MAX_REF_BYTES);
    const defaultHead = verifyDefaultBranch(defaultRef.value, request.authority.defaultBranchRef);

    const baselinePath = comparePath(request.authority.baselineCommitSha, request.releaseCommitSha);
    const baseline = await this.read(baselinePath, authorization, MAX_COMPARE_BYTES);

    const releasePath = comparePath(request.releaseCommitSha, defaultHead);
    const release = await this.read(releasePath, authorization, MAX_COMPARE_BYTES);

    const rulesetPath =
      `${repositoryPath()}/rulesets/${request.authority.branchRulesetId}` as const;
    const ruleset = await this.read(rulesetPath, authorization, MAX_RULESET_BYTES);
    const rulesetProjection = projectGitHubRuleset(ruleset.value, {
      repository: TRUST.targetRepository,
      repositoryId: TRUST.targetRepositoryId,
      rulesetId: Number(request.authority.branchRulesetId),
    });
    const rulesetProjectionSha256 = await githubRulesetProjectionDigest(rulesetProjection);
    if (rulesetProjectionSha256 !== request.authority.branchRulesetProjectionSha256) {
      throw new BrokerError("TARGET_LINEAGE_PROVIDER_INVALID", 503, false);
    }

    const observedAt = canonicalUtcSeconds(this.now());
    const lineage: JsonObject = {
      ...comparisonProjection(
        "baseline",
        baseline.value,
        baselinePath,
        request.authority.baselineCommitSha,
        request.releaseCommitSha,
      ),
      baseline_compare_provider_response_sha256: baseline.providerResponseSha256,
      branch_ruleset_evidence_sha256: request.authority.branchRulesetEvidenceSha256,
      branch_ruleset_id: request.authority.branchRulesetId,
      branch_ruleset_projection_sha256: rulesetProjectionSha256,
      branch_ruleset_provider_response_sha256: ruleset.providerResponseSha256,
      default_branch_head_sha: defaultHead,
      default_branch_provider_response_sha256: defaultRef.providerResponseSha256,
      default_branch_ref: request.authority.defaultBranchRef,
      observed_at: observedAt,
      ...comparisonProjection(
        "release",
        release.value,
        releasePath,
        request.releaseCommitSha,
        defaultHead,
      ),
      release_compare_provider_response_sha256: release.providerResponseSha256,
    };
    validateTargetLineage(lineage, request.authority, request.releaseCommitSha, observedAt);
    return lineage;
  }

  private async read(path: `/${string}`, authorization: string, maximumBytes: number) {
    const response = await githubRequest(this.providerFetch, {
      authorization,
      method: "GET",
      path,
    });
    await requireGitHubOk(response, "TARGET_LINEAGE_PROVIDER_FAILED");
    return githubJsonWithDigest(response, maximumBytes, "TARGET_LINEAGE_PROVIDER_INVALID");
  }
}

export function buildTargetLineageRpcRequest(request: TargetLineageRequest): JsonObject {
  validateRequest(request);
  return {
    baseline_commit_sha: request.authority.baselineCommitSha,
    branch_ruleset_evidence_sha256: request.authority.branchRulesetEvidenceSha256,
    branch_ruleset_id: request.authority.branchRulesetId,
    branch_ruleset_projection_sha256: request.authority.branchRulesetProjectionSha256,
    default_branch_ref: request.authority.defaultBranchRef,
    release_commit_sha: request.releaseCommitSha,
    request_id: request.requestId,
    schema: TARGET_LINEAGE_RPC_REQUEST_SCHEMA,
    schema_version: 1,
  };
}

export function parseTargetLineageRpcRequest(value: unknown): TargetLineageRequest {
  const body = exactObject(value, [
    "baseline_commit_sha",
    "branch_ruleset_evidence_sha256",
    "branch_ruleset_id",
    "branch_ruleset_projection_sha256",
    "default_branch_ref",
    "release_commit_sha",
    "request_id",
    "schema",
    "schema_version",
  ]);
  requireLiteral(body, "schema", TARGET_LINEAGE_RPC_REQUEST_SCHEMA);
  requireExactInteger(body, "schema_version", 1);
  const request = {
    authority: {
      baselineCommitSha: requireString(body, "baseline_commit_sha", 40, SHA1),
      branchRulesetEvidenceSha256: requireString(
        body,
        "branch_ruleset_evidence_sha256",
        71,
        DIGEST,
      ),
      branchRulesetId: requireString(body, "branch_ruleset_id", 32, POSITIVE_ID),
      branchRulesetProjectionSha256: requireString(
        body,
        "branch_ruleset_projection_sha256",
        71,
        DIGEST,
      ),
      defaultBranchRef: requireString(body, "default_branch_ref", 64),
    },
    releaseCommitSha: requireString(body, "release_commit_sha", 40, SHA1),
    requestId: requireString(body, "request_id", 128, REQUEST_ID),
  };
  validateRequest(request);
  return request;
}

function comparisonProjection(
  prefix: "baseline" | "release",
  value: JsonObject,
  path: string,
  expectedBaseSha: string,
  expectedHeadSha: string,
): JsonObject {
  const aheadBy = providerNonnegativeInteger(value, "ahead_by");
  const behindBy = providerNonnegativeInteger(value, "behind_by");
  const totalCommits = providerNonnegativeInteger(value, "total_commits");
  const base = providerObject(value.base_commit, "TARGET_LINEAGE_PROVIDER_INVALID");
  const head = providerObject(value.head_commit, "TARGET_LINEAGE_PROVIDER_INVALID");
  const mergeBase = providerObject(value.merge_base_commit, "TARGET_LINEAGE_PROVIDER_INVALID");
  requireProviderLiteral(base, "sha", expectedBaseSha, "TARGET_LINEAGE_PROVIDER_INVALID");
  requireProviderLiteral(head, "sha", expectedHeadSha, "TARGET_LINEAGE_PROVIDER_INVALID");
  return {
    [`${prefix}_ahead_by`]: aheadBy,
    [`${prefix}_behind_by`]: behindBy,
    [`${prefix}_commit_sha`]: providerString(base, "sha", 40, "TARGET_LINEAGE_PROVIDER_INVALID"),
    [`${prefix}_compare_path`]: path,
    [`${prefix}_merge_base_commit_sha`]: providerString(
      mergeBase,
      "sha",
      40,
      "TARGET_LINEAGE_PROVIDER_INVALID",
    ),
    [`${prefix}_status`]: providerString(value, "status", 16, "TARGET_LINEAGE_PROVIDER_INVALID"),
    [`${prefix}_total_commits`]: totalCommits,
  };
}

function verifyDefaultBranch(value: JsonObject, expectedRef: string): string {
  requireProviderLiteral(value, "ref", expectedRef, "TARGET_LINEAGE_PROVIDER_INVALID");
  const object = providerObject(value.object, "TARGET_LINEAGE_PROVIDER_INVALID");
  requireProviderLiteral(object, "type", "commit", "TARGET_LINEAGE_PROVIDER_INVALID");
  const sha = providerString(object, "sha", 40, "TARGET_LINEAGE_PROVIDER_INVALID");
  if (!SHA1.test(sha)) throw new BrokerError("TARGET_LINEAGE_PROVIDER_INVALID", 503, false);
  return sha;
}

function providerNonnegativeInteger(value: JsonObject, key: string): number {
  const candidate = value[key];
  if (typeof candidate !== "number" || !Number.isSafeInteger(candidate) || candidate < 0) {
    throw new BrokerError("TARGET_LINEAGE_PROVIDER_INVALID", 503, false);
  }
  return candidate;
}

function validateRequest(request: TargetLineageRequest): void {
  if (
    !SHA1.test(request.releaseCommitSha) ||
    !SHA1.test(request.authority.baselineCommitSha) ||
    !DIGEST.test(request.authority.branchRulesetEvidenceSha256) ||
    !DIGEST.test(request.authority.branchRulesetProjectionSha256) ||
    !POSITIVE_ID.test(request.authority.branchRulesetId) ||
    request.authority.defaultBranchRef !== TRUST.targetDefaultBranchRef ||
    !REQUEST_ID.test(request.requestId)
  ) {
    throw new BrokerError("TARGET_LINEAGE_REQUEST_INVALID", 400, false);
  }
}

function repositoryPath(): `/repos/${string}` {
  return `/repos/${TRUST.targetRepository}`;
}

function comparePath(base: string, head: string): `/${string}` {
  return `${repositoryPath()}/compare/${base}...${head}`;
}

function canonicalUtcSeconds(value: number): string {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new BrokerError("TARGET_LINEAGE_TIME_INVALID", 500, false);
  }
  return new Date(Math.floor(value / 1000) * 1000).toISOString().replace(".000Z", "Z");
}

function requireLiteral(value: JsonObject, key: string, expected: string): void {
  if (requireString(value, key, Math.max(1, expected.length)) !== expected) {
    throw new BrokerError("TARGET_LINEAGE_REQUEST_INVALID", 400, false);
  }
}

function requireExactInteger(value: JsonObject, key: string, expected: number): void {
  if (requireInteger(value, key, expected, expected) !== expected) {
    throw new BrokerError("TARGET_LINEAGE_REQUEST_INVALID", 400, false);
  }
}
