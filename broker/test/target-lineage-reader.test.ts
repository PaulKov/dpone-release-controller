import { describe, expect, it, vi } from "vitest";

import { validateTargetLineage, type TargetLineageAuthority } from "../src/target-lineage";
import type { JsonObject } from "../src/types";
import { TargetLineageReader } from "../src/private/target-lineage-reader";

const SHA = (character: string): string => character.repeat(40);
const DIGEST = (character: string): string => `sha256:${character.repeat(64)}`;
const BASELINE = SHA("9");
const RELEASE = SHA("a");
const DEFAULT_HEAD = SHA("f");
const AUTHORITY: TargetLineageAuthority = {
  baselineCommitSha: BASELINE,
  branchRulesetEvidenceSha256: DIGEST("1"),
  branchRulesetId: "18806829",
  branchRulesetProjectionSha256:
    "sha256:e2f8ec4f9677839da2ccd1644d543d17c41446dc8305dd9529ca8c8f5484fe39",
  defaultBranchRef: "refs/heads/master",
};

describe("fresh protected target lineage reader", () => {
  it("performs all four ordered provider reads and emits a closed projection", async () => {
    const provider = providerSequence();
    const reader = new TargetLineageReader(tokens(), provider.fetch, () => 1_787_054_400_000);
    const lineage = await reader.observe(request());

    expect(provider.paths).toEqual([
      "/repos/PaulKov/dpone/git/ref/heads/master",
      `/repos/PaulKov/dpone/compare/${BASELINE}...${RELEASE}`,
      `/repos/PaulKov/dpone/compare/${RELEASE}...${DEFAULT_HEAD}`,
      "/repos/PaulKov/dpone/rulesets/18806829",
    ]);
    expect(lineage).toMatchObject({
      baseline_commit_sha: BASELINE,
      branch_ruleset_evidence_sha256: AUTHORITY.branchRulesetEvidenceSha256,
      branch_ruleset_projection_sha256: AUTHORITY.branchRulesetProjectionSha256,
      default_branch_head_sha: DEFAULT_HEAD,
      observed_at: "2026-08-18T12:00:00Z",
      release_commit_sha: RELEASE,
    });
    expect(lineage.branch_ruleset_provider_response_sha256).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(Object.keys(lineage)).toHaveLength(24);
    expect(() =>
      validateTargetLineage(
        { ...lineage, unexpected_raw_field: "forbidden" },
        AUTHORITY,
        RELEASE,
        "2026-08-18T12:00:01Z",
      ),
    ).toThrow("UNKNOWN_FIELD");
  });

  it("cannot pass by copying A0 evidence without a fresh ruleset GET", async () => {
    const provider = providerSequence();
    provider.responses.pop();
    const reader = new TargetLineageReader(tokens(), provider.fetch, () => 1_787_054_400_000);
    await expect(reader.observe(request())).rejects.toThrow("GITHUB_PROVIDER_UNAVAILABLE");
    expect(provider.paths).toHaveLength(4);
    expect(provider.paths.at(-1)).toBe("/repos/PaulKov/dpone/rulesets/18806829");
  });

  it("rejects a bypassable or inactive branch ruleset", async () => {
    for (const drift of [
      { bypass_actors: [{ actor_id: 1, actor_type: "User", bypass_mode: "always" }] },
      { enforcement: "evaluate" },
    ]) {
      const provider = providerSequence();
      provider.responses[3] = json({ ...ruleset(), ...drift });
      const reader = new TargetLineageReader(tokens(), provider.fetch, () => 1_787_054_400_000);
      await expect(reader.observe(request())).rejects.toThrow("TARGET_LINEAGE_PROVIDER_INVALID");
    }
  });

  it("binds both provider comparison head commits to the requested lineage", async () => {
    for (const [responseIndex, wrongHead] of [
      [1, DEFAULT_HEAD],
      [2, BASELINE],
    ] as const) {
      const provider = providerSequence();
      provider.responses[responseIndex] = json(
        compare(responseIndex === 1 ? BASELINE : RELEASE, wrongHead, 1),
      );
      const reader = new TargetLineageReader(tokens(), provider.fetch, () => 1_787_054_400_000);
      await expect(reader.observe(request())).rejects.toThrow("TARGET_LINEAGE_PROVIDER_INVALID");
    }
  });
});

function request() {
  return {
    authority: AUTHORITY,
    releaseCommitSha: RELEASE,
    requestId: "target-lineage-request-0001",
  };
}

function tokens() {
  return { installationToken: vi.fn(async () => `ghs_${"a".repeat(36)}`) };
}

function providerSequence() {
  const paths: string[] = [];
  const responses = [
    json({
      object: { sha: DEFAULT_HEAD, type: "commit" },
      ref: "refs/heads/master",
    }),
    json(compare(BASELINE, RELEASE, 5)),
    json(compare(RELEASE, DEFAULT_HEAD, 2)),
    json(ruleset()),
  ];
  return {
    fetch: vi.fn(async (input: RequestInfo | URL) => {
      const href =
        typeof input === "string" ? input : input instanceof Request ? input.url : input.href;
      paths.push(new URL(href).pathname);
      const response = responses.shift();
      if (response === undefined) throw new Error("missing fresh provider response");
      return response;
    }),
    paths,
    responses,
  };
}

function compare(base: string, head: string, aheadBy: number): JsonObject {
  return {
    ahead_by: aheadBy,
    base_commit: { sha: base },
    behind_by: 0,
    head_commit: { sha: head },
    merge_base_commit: { sha: base },
    status: base === head ? "identical" : "ahead",
    total_commits: aheadBy,
  };
}

function ruleset(): JsonObject {
  return {
    _links: {},
    bypass_actors: [],
    conditions: {
      ref_name: {
        exclude: [],
        include: ["refs/heads/master"],
      },
    },
    created_at: "2026-07-11T14:17:56.651Z",
    enforcement: "active",
    id: 18806829,
    name: "protect-master",
    node_id: "RRS_fixture",
    rules: [
      { type: "deletion" },
      { type: "non_fast_forward" },
      {
        parameters: {
          allowed_merge_methods: ["merge", "squash"],
          dismiss_stale_reviews_on_push: true,
          require_code_owner_review: false,
          require_last_push_approval: false,
          required_approving_review_count: 0,
          required_review_thread_resolution: true,
          required_reviewers: [],
        },
        type: "pull_request",
      },
      {
        parameters: {
          do_not_enforce_on_create: false,
          required_status_checks: [
            { context: "Agent PR receipt", integration_id: 15368 },
            { context: "Analyze Python", integration_id: 15368 },
          ],
          strict_required_status_checks_policy: true,
        },
        type: "required_status_checks",
      },
    ],
    source: "PaulKov/dpone",
    source_type: "Repository",
    target: "branch",
    updated_at: "2026-07-19T18:37:47.596Z",
  };
}

function json(value: JsonObject): Response {
  return new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json" },
  });
}
