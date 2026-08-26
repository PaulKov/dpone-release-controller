import { describe, expect, it } from "vitest";

import { TRUST } from "../src/config";
import { CandidateProviderReader } from "../src/private/candidate-provider";
import {
  CANDIDATE_COMMIT,
  CANDIDATE_TAG_OBJECT,
  CANDIDATE_VERSION,
  CANDIDATE_ZIP,
  candidateHarness,
  signedUrl,
} from "./support/candidate-provider-fixture";

describe("private candidate provider reader", () => {
  it("binds the completed target run, exact artifact, annotated tag and A1 policy", async () => {
    const harness = await candidateHarness();
    const result = await harness.reader.authorize(harness.input, harness.authority);
    const body = await result.source.open();

    expect(new Uint8Array(await body.arrayBuffer())).toEqual(CANDIDATE_ZIP);
    expect(result.workerVersionId).toBe(CANDIDATE_VERSION);
    expect(result.observation).toMatchObject({
      artifact_digest: harness.input.artifactDigest,
      artifact_expired: false,
      artifact_id: 456,
      artifact_name: "release-candidates",
      artifact_size_bytes: CANDIDATE_ZIP.byteLength,
      broker_request_id: "request-candidate-0001",
      conclusion: "success",
      event: "push",
      head_branch: "v0.74.0",
      head_sha: CANDIDATE_COMMIT,
      policy_sha256: harness.authority.policySha256,
      release: "v0.74.0",
      repository: TRUST.targetRepository,
      repository_id: TRUST.targetRepositoryId,
      run_attempt: 2,
      run_id: 123,
      run_status: "completed",
      schema: "dpone.github-actions-artifact-observation.v1",
      schema_version: 1,
      tag_object_sha: CANDIDATE_TAG_OBJECT,
      tag_object_type: "tag",
      tag_ref: "refs/tags/v0.74.0",
      workflow_path: ".github/workflows/release.yml",
    });
    expect(result.observation.source_url_sha256).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(result.observation.provider_response_sha256).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(JSON.stringify(result)).not.toContain("blob.core.windows.net");
    expect(harness.tokenCalls.count).toBe(1);

    const providerCalls = harness.calls.filter((call) =>
      call.url.startsWith("https://api.github.com/"),
    );
    expect(providerCalls).toHaveLength(7);
    expect(providerCalls.every((call) => call.authorization?.startsWith("Bearer ghs_"))).toBe(true);
    expect(providerCalls.every((call) => call.method === "GET")).toBe(true);
    expect(providerCalls.filter((call) => call.redirect === "manual")).toHaveLength(1);
    const sourceCall = harness.calls.find((call) => call.url === signedUrl());
    expect(sourceCall).toMatchObject({
      authorization: null,
      method: "GET",
      redirect: "error",
    });
  });

  it("derives the tag object from the provider ref rather than caller input", async () => {
    const harness = await candidateHarness();
    expect(Object.keys(harness.input).sort()).toEqual([
      "artifactDigest",
      "artifactId",
      "peeledCommitSha",
      "release",
      "requestId",
      "runAttempt",
      "runId",
    ]);
    await expect(harness.reader.authorize(harness.input, harness.authority)).resolves.toMatchObject(
      {
        observation: { tag_object_sha: CANDIDATE_TAG_OBJECT },
      },
    );
  });

  it("refreshes once when GitHub returns a signed URL with under ten seconds remaining", async () => {
    const harness = await candidateHarness({
      redirectLocations: [signedUrl("2026-08-15T12:00:05Z"), signedUrl()],
    });
    const result = await harness.reader.authorize(harness.input, harness.authority);
    const redirects = harness.calls.filter((call) => call.redirect === "manual");
    expect(redirects).toHaveLength(2);
    expect(result.observation.source_url_expires_at).toBe("2026-08-15T12:00:45Z");
  });

  it("rejects caller selector or activated-policy drift before provider mutation", async () => {
    const harness = await candidateHarness();
    await expect(
      harness.reader.authorize(
        { ...harness.input, runId: Number.MAX_SAFE_INTEGER + 1 },
        harness.authority,
      ),
    ).rejects.toThrow("CANDIDATE_BINDING_INVALID");
    expect(harness.calls).toHaveLength(0);

    await expect(
      harness.reader.authorize(harness.input, {
        ...harness.authority,
        policySha256: "sha256:" + "0".repeat(64),
      }),
    ).rejects.toThrow("CANDIDATE_POLICY_DIGEST_MISMATCH");
    expect(harness.calls.some((call) => call.redirect === "manual")).toBe(false);
  });

  it("rejects invalid private service configuration before token access", () => {
    expect(
      () =>
        new CandidateProviderReader(
          { workerVersionId: "../latest" },
          {
            async installationToken() {
              throw new Error("must not be called");
            },
          },
        ),
    ).toThrow("CANDIDATE_READER_CONFIGURATION_INVALID");
  });
});
