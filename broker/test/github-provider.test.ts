import { describe, expect, it } from "vitest";

import {
  githubJsonWithDigest,
  requireExactGitHubJsonResponse,
  requireGitHubOk,
} from "../src/private/github-provider";

describe("closed GitHub JSON transport", () => {
  it("accepts only the exact status/media contract while tolerating platform metadata", async () => {
    const response = responseWithBody({
      "cf-ray": "provider-platform-metadata",
      "content-type": "Application/JSON; charset=utf-8",
      date: "Wed, 19 Aug 2026 00:00:00 GMT",
      server: "github.com",
      "x-github-request-id": "provider-request-0001",
    });

    await expect(
      requireExactGitHubJsonResponse(response.response, 200, "GITHUB_JSON_INVALID"),
    ).resolves.toBeUndefined();
    expect(response.canceled()).toBe(false);
    await response.response.body?.cancel();
  });

  it("cancels before rejecting every forbidden transport header", async () => {
    const forbidden = [
      ["content-encoding", "gzip"],
      ["content-range", "bytes 0-1/2"],
      ["location", "https://attacker.invalid"],
      ["set-cookie", "authority=leak"],
      ["transfer-encoding", "chunked"],
    ] as const;

    for (const [name, value] of forbidden) {
      const candidate = responseWithBody({ "content-type": "application/json", [name]: value });
      await expect(
        githubJsonWithDigest(candidate.response, 64, "GITHUB_JSON_INVALID"),
      ).rejects.toThrow("GITHUB_JSON_INVALID");
      expect(candidate.canceled(), name).toBe(true);
    }
  });

  it("cancels before rejecting status/media drift and failed provider requests", async () => {
    for (const candidate of [
      responseWithBody({ "content-type": "text/plain" }),
      responseWithBody({ "content-type": "application/json" }, 202),
    ]) {
      await expect(
        githubJsonWithDigest(candidate.response, 64, "GITHUB_JSON_INVALID"),
      ).rejects.toThrow("GITHUB_JSON_INVALID");
      expect(candidate.canceled()).toBe(true);
    }

    const failed = responseWithBody({ "content-type": "application/json" }, 503);
    await expect(requireGitHubOk(failed.response, "GITHUB_PROVIDER_FAILED")).rejects.toThrow(
      "GITHUB_PROVIDER_FAILED",
    );
    expect(failed.canceled()).toBe(true);
  });
});

function responseWithBody(
  headers: Record<string, string>,
  status = 200,
): { readonly canceled: () => boolean; readonly response: Response } {
  let canceled = false;
  const body = new ReadableStream<Uint8Array>({
    cancel() {
      canceled = true;
    },
    start(controller) {
      controller.enqueue(new TextEncoder().encode("{}"));
    },
  });
  return {
    canceled: () => canceled,
    response: new Response(body, { headers, status }),
  };
}
