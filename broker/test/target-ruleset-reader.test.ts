import { describe, expect, it, vi } from "vitest";

import { canonicalJson } from "../src/canonical";
import { githubRulesetProjectionDigest } from "../src/github-ruleset-projection";
import {
  parseTargetRulesetRequest,
  TargetRulesetReader,
} from "../src/private/target-ruleset-reader";
import { TargetRulesetClient } from "../src/target-ruleset-client";
import type { JsonObject, JsonValue, PrivateServicePin } from "../src/types";
import goldenFixture from "./fixtures/github-ruleset-projection-v1-golden.json";

const PROJECTION = goldenFixture as JsonObject;
const PROJECTION_SHA256 = "sha256:e2f8ec4f9677839da2ccd1644d543d17c41446dc8305dd9529ca8c8f5484fe39";
const REQUEST_ID = "target-ruleset-request-0001";
const NOW = Date.parse("2026-08-18T12:00:00Z");
const VERSION = "00000000-0000-0000-0000-000000000001";
const PIN: PrivateServicePin = {
  serviceIdentity:
    `cloudflare-worker:${"a".repeat(32)}/dpone-release-governance-reader` + `@${VERSION}`,
  serviceName: "dpone-release-governance-reader",
  versionId: VERSION,
};

describe("fresh A0 target ruleset observation", () => {
  it("requires a fresh provider GET and accepts only the pinned canonical projection", async () => {
    const providerPaths: string[] = [];
    const providerFetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(
        typeof input === "string" ? input : input instanceof Request ? input.url : input.href,
      );
      providerPaths.push(url.pathname);
      return json(providerPayload());
    });
    let privateRequest: Request | undefined;
    const service = fetcher(async (request) => {
      privateRequest = request;
      const parsed = parseTargetRulesetRequest(await request.json());
      const observation = await new TargetRulesetReader(
        tokens(),
        PIN.serviceIdentity,
        PIN.versionId,
        providerFetch,
        () => NOW,
      ).observe(parsed);
      return new Response(canonicalJson(observation), {
        headers: { "content-type": "application/json", "x-request-id": REQUEST_ID },
      });
    });

    const result = await new TargetRulesetClient(service, PIN, () => NOW + 1_000).observe(
      "18806829",
      PROJECTION,
      PROJECTION_SHA256,
      REQUEST_ID,
    );

    expect(providerPaths).toEqual(["/repos/PaulKov/dpone/rulesets/18806829"]);
    expect(result.projection).toEqual(PROJECTION);
    expect(result.projectionSha256).toBe(PROJECTION_SHA256);
    expect(await githubRulesetProjectionDigest(result.projection)).toBe(PROJECTION_SHA256);
    expect(privateRequest?.headers.get("cloudflare-workers-version-overrides")).toBe(
      `dpone-release-governance-reader="${VERSION}"`,
    );
    expect(privateRequest?.headers.get("authorization")).toBeNull();
  });

  it("rejects a response that cannot prove the bypass actor set", async () => {
    const payload = providerPayload();
    delete payload.bypass_actors;
    const reader = new TargetRulesetReader(
      tokens(),
      PIN.serviceIdentity,
      PIN.versionId,
      vi.fn(async () => json(payload)),
      () => NOW,
    );
    await expect(reader.observe(readerRequest())).rejects.toThrow(
      "GITHUB_RULESET_PROJECTION_INVALID",
    );
  });

  it("rejects semantic drift and stale private observations", async () => {
    const drift = providerPayload();
    const status = objectAt(drift.rules, 3);
    (status.parameters as JsonObject).strict_required_status_checks_policy = false;
    const reader = new TargetRulesetReader(
      tokens(),
      PIN.serviceIdentity,
      PIN.versionId,
      vi.fn(async () => json(drift)),
      () => NOW,
    );
    await expect(reader.observe(readerRequest())).rejects.toThrow("TARGET_RULESET_PROVIDER_DRIFT");

    const validReader = new TargetRulesetReader(
      tokens(),
      PIN.serviceIdentity,
      PIN.versionId,
      vi.fn(async () => json(providerPayload())),
      () => NOW,
    );
    const observation = await validReader.observe(readerRequest());
    const staleService = fetcher(
      async () =>
        new Response(canonicalJson(observation), {
          headers: { "content-type": "application/json", "x-request-id": REQUEST_ID },
        }),
    );
    await expect(
      new TargetRulesetClient(staleService, PIN, () => NOW + 60_001).observe(
        "18806829",
        PROJECTION,
        PROJECTION_SHA256,
        REQUEST_ID,
      ),
    ).rejects.toThrow("TARGET_RULESET_OBSERVATION_STALE");
  });
});

function readerRequest() {
  return {
    branchRulesetId: "18806829",
    branchRulesetProjectionSha256: PROJECTION_SHA256,
    requestId: REQUEST_ID,
  };
}

function objectAt(value: unknown, index: number): JsonObject {
  if (!Array.isArray(value)) throw new Error("missing object fixture array");
  const item: unknown = value[index];
  if (item === null || typeof item !== "object" || Array.isArray(item)) {
    throw new Error("missing object fixture");
  }
  return item as JsonObject;
}

function tokens() {
  return { installationToken: vi.fn(async () => `ghs_${"a".repeat(36)}`) };
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
  const value = PROJECTION[key];
  if (value === undefined) throw new Error(`missing golden ${key}`);
  return structuredClone(value);
}

function json(value: JsonObject): Response {
  return new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json" },
  });
}

function fetcher(callback: (request: Request) => Promise<Response>): Fetcher {
  return { fetch: callback } as unknown as Fetcher;
}
