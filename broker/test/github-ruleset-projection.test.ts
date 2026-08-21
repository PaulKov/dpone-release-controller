import { describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical";
import {
  githubRulesetProjectionDigest,
  projectGitHubRuleset,
} from "../src/github-ruleset-projection";
import type { JsonObject, JsonValue } from "../src/types";
import goldenFixture from "./fixtures/github-ruleset-projection-v1-golden.json";

const GOLDEN = goldenFixture as JsonObject;
const EXPECTED_DIGEST = "sha256:e2f8ec4f9677839da2ccd1644d543d17c41446dc8305dd9529ca8c8f5484fe39";

describe("GitHub ruleset projection v1", () => {
  it("matches the target Python canonical golden bytes and digest", async () => {
    const projection = projectGitHubRuleset(providerPayload(), {
      repository: "PaulKov/dpone",
      repositoryId: 1_255_975_556,
      rulesetId: 18_806_829,
    });

    expect(canonicalJson(projection)).toBe(canonicalJson(GOLDEN));
    await expect(githubRulesetProjectionDigest(projection)).resolves.toBe(EXPECTED_DIGEST);
  });

  it("treats unobservable bypass actors as unavailable evidence", () => {
    const payload = providerPayload();
    delete payload.bypass_actors;
    expect(() => project(payload)).toThrow("GITHUB_RULESET_PROJECTION_INVALID");
  });

  it("fails closed on unknown semantics, rule drift, and duplicate checks", () => {
    const unknown = providerPayload();
    unknown.version_id = 1;
    expect(() => project(unknown)).toThrow("GITHUB_RULESET_PROJECTION_INVALID");

    const removedRule = providerPayload();
    (removedRule.rules as JsonObject[]).shift();
    expect(() => project(removedRule)).toThrow("GITHUB_RULESET_PROJECTION_INVALID");

    const changedRule = providerPayload();
    const pullRequest = objectAt(changedRule.rules, 2);
    (pullRequest.parameters as JsonObject).required_reviewers = [{ type: "Team" }];
    expect(() => project(changedRule)).toThrow("GITHUB_RULESET_PROJECTION_INVALID");

    const duplicate = providerPayload();
    const checks = (objectAt(duplicate.rules, 3).parameters as JsonObject)
      .required_status_checks as JsonObject[];
    const firstCheck = checks[0];
    if (firstCheck === undefined) throw new Error("missing check fixture");
    checks.push({ ...firstCheck });
    expect(() => project(duplicate)).toThrow("GITHUB_RULESET_PROJECTION_INVALID");
  });
});

function project(value: JsonObject): JsonObject {
  return projectGitHubRuleset(value, {
    repository: "PaulKov/dpone",
    repositoryId: 1_255_975_556,
    rulesetId: 18_806_829,
  });
}

function objectAt(value: unknown, index: number): JsonObject {
  if (!Array.isArray(value)) throw new Error("missing object fixture array");
  const item: unknown = value[index];
  if (item === null || typeof item !== "object" || Array.isArray(item)) {
    throw new Error("missing object fixture");
  }
  return item as JsonObject;
}

function providerPayload(): JsonObject {
  return {
    _links: {},
    bypass_actors: golden("bypass_actors"),
    conditions: { ref_name: golden("conditions") },
    created_at: "2026-07-11T14:17:56.651Z",
    enforcement: golden("enforcement"),
    id: golden("id"),
    name: golden("name"),
    node_id: "RRS_fixture",
    rules: golden("rules"),
    source: golden("source"),
    source_type: golden("source_type"),
    target: golden("target"),
    updated_at: "2026-07-19T18:37:47.596Z",
  };
}

function golden(key: string): JsonValue {
  const value = GOLDEN[key];
  if (value === undefined) throw new Error(`golden fixture field missing: ${key}`);
  return structuredClone(value);
}
