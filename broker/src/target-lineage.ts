import { TRUST } from "./config";
import { assert } from "./errors";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

const SHA1 = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const POSITIVE_ID = /^[1-9][0-9]{0,31}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;

export const TARGET_LINEAGE_KEYS = Object.freeze([
  "baseline_ahead_by",
  "baseline_behind_by",
  "baseline_commit_sha",
  "baseline_compare_path",
  "baseline_compare_provider_response_sha256",
  "baseline_merge_base_commit_sha",
  "baseline_status",
  "baseline_total_commits",
  "branch_ruleset_evidence_sha256",
  "branch_ruleset_id",
  "branch_ruleset_projection_sha256",
  "branch_ruleset_provider_response_sha256",
  "default_branch_head_sha",
  "default_branch_provider_response_sha256",
  "default_branch_ref",
  "observed_at",
  "release_ahead_by",
  "release_behind_by",
  "release_commit_sha",
  "release_compare_path",
  "release_compare_provider_response_sha256",
  "release_merge_base_commit_sha",
  "release_status",
  "release_total_commits",
] as const);

export interface TargetLineageAuthority {
  readonly baselineCommitSha: string;
  readonly branchRulesetEvidenceSha256: string;
  readonly branchRulesetId: string;
  readonly branchRulesetProjectionSha256: string;
  readonly defaultBranchRef: string;
}

/**
 * Validate the shared candidate/runtime protected-lineage projection.
 *
 * The first comparison proves that the release descends from the activated
 * epoch baseline. The second proves that the release is already contained in
 * the current protected default branch, rejecting an unmerged tag even when
 * its policy/workflow bytes were copied unchanged.
 */
export function validateTargetLineage(
  value: unknown,
  authority: TargetLineageAuthority,
  releaseCommitSha: string,
  brokerAcceptedAt: string,
): JsonObject {
  assert(
    SHA1.test(releaseCommitSha) && TIMESTAMP.test(brokerAcceptedAt),
    "TARGET_LINEAGE_RELEASE_INVALID",
    503,
  );
  assert(
    SHA1.test(authority.baselineCommitSha) &&
      POSITIVE_ID.test(authority.branchRulesetId) &&
      DIGEST.test(authority.branchRulesetEvidenceSha256) &&
      DIGEST.test(authority.branchRulesetProjectionSha256) &&
      authority.defaultBranchRef === TRUST.targetDefaultBranchRef,
    "TARGET_LINEAGE_AUTHORITY_INVALID",
    503,
  );
  const lineage = exactObject(value, TARGET_LINEAGE_KEYS);
  requireLiteral(lineage, "baseline_commit_sha", authority.baselineCommitSha);
  requireLiteral(lineage, "release_commit_sha", releaseCommitSha);
  requireLiteral(lineage, "branch_ruleset_id", authority.branchRulesetId);
  requireLiteral(lineage, "branch_ruleset_evidence_sha256", authority.branchRulesetEvidenceSha256);
  requireLiteral(
    lineage,
    "branch_ruleset_projection_sha256",
    authority.branchRulesetProjectionSha256,
  );
  requireLiteral(lineage, "default_branch_ref", authority.defaultBranchRef);
  requireDigest(lineage, "baseline_compare_provider_response_sha256");
  requireDigest(lineage, "branch_ruleset_provider_response_sha256");
  requireDigest(lineage, "default_branch_provider_response_sha256");
  requireDigest(lineage, "release_compare_provider_response_sha256");
  const observedAt = requireString(lineage, "observed_at", 32, TIMESTAMP);
  const freshnessMs = Date.parse(brokerAcceptedAt) - Date.parse(observedAt);
  assert(freshnessMs >= 0 && freshnessMs <= 60_000, "TARGET_LINEAGE_INVALID", 503);

  const defaultHead = requireString(lineage, "default_branch_head_sha", 40, SHA1);
  validateComparison(lineage, {
    baseCommitSha: authority.baselineCommitSha,
    headCommitSha: releaseCommitSha,
    prefix: "baseline",
  });
  validateComparison(lineage, {
    baseCommitSha: releaseCommitSha,
    headCommitSha: defaultHead,
    prefix: "release",
  });
  return lineage;
}

function validateComparison(
  lineage: JsonObject,
  input: {
    readonly baseCommitSha: string;
    readonly headCommitSha: string;
    readonly prefix: "baseline" | "release";
  },
): void {
  const { baseCommitSha, headCommitSha, prefix } = input;
  requireLiteral(lineage, `${prefix}_merge_base_commit_sha`, baseCommitSha);
  requireLiteral(
    lineage,
    `${prefix}_compare_path`,
    `/repos/${TRUST.targetRepository}/compare/${baseCommitSha}...${headCommitSha}`,
  );
  const aheadBy = requireInteger(lineage, `${prefix}_ahead_by`, 0, Number.MAX_SAFE_INTEGER);
  requireExactInteger(lineage, `${prefix}_behind_by`, 0);
  requireExactInteger(lineage, `${prefix}_total_commits`, aheadBy);
  const identical = baseCommitSha === headCommitSha;
  requireLiteral(lineage, `${prefix}_status`, identical ? "identical" : "ahead");
  assert(
    (identical && aheadBy === 0) || (!identical && aheadBy >= 1),
    "TARGET_LINEAGE_INVALID",
    503,
  );
}

function requireDigest(value: JsonObject, key: string): void {
  requireString(value, key, 71, DIGEST);
}

function requireLiteral(value: JsonObject, key: string, expected: string): void {
  assert(
    requireString(value, key, Math.max(1, expected.length)) === expected,
    "TARGET_LINEAGE_INVALID",
    503,
  );
}

function requireExactInteger(value: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(value, key, expected, expected) === expected,
    "TARGET_LINEAGE_INVALID",
    503,
  );
}
