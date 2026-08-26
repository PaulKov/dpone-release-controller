import { describe, expect, it } from "vitest";

import { TRUST } from "../src/config";
import type { JsonObject } from "../src/types";
import {
  CANDIDATE_COMMIT,
  CANDIDATE_TAG_OBJECT,
  candidateHarness,
  signedUrl,
} from "./support/candidate-provider-fixture";

describe("candidate provider fault matrix", () => {
  it("rejects nonterminal, failed, mismatched and forked workflow runs", async () => {
    const cases: readonly Readonly<JsonObject>[] = [
      { conclusion: null, status: "in_progress" },
      { conclusion: "failure", status: "completed" },
      { event: "workflow_dispatch" },
      { path: ".github/workflows/other.yml" },
      { run_attempt: 3 },
      { head_sha: "c".repeat(40) },
      { repository: { id: TRUST.controllerRepositoryId } },
      { head_repository: { id: TRUST.controllerRepositoryId } },
    ];
    for (const run of cases) {
      const harness = await candidateHarness({ run });
      await expect(harness.reader.authorize(harness.input, harness.authority)).rejects.toThrow(
        "CANDIDATE_RUN_INVALID",
      );
      expect(harness.calls.some((call) => call.redirect === "manual")).toBe(false);
    }
  });

  it("rejects artifact identity, digest, state, bounds and workflow binding drift", async () => {
    const cases: readonly Readonly<JsonObject>[] = [
      { id: 457 },
      { name: "release-candidates-copy" },
      { digest: "sha256:" + "0".repeat(64) },
      { expired: true },
      { size_in_bytes: 805_306_369 },
      { archive_download_url: "https://evil.invalid/artifact.zip" },
      { workflow_run: exactWorkflowRun({ id: 124 }) },
      { workflow_run: exactWorkflowRun({ repository_id: TRUST.controllerRepositoryId }) },
      { workflow_run: exactWorkflowRun({ head_repository_id: TRUST.controllerRepositoryId }) },
      { workflow_run: exactWorkflowRun({ head_sha: "c".repeat(40) }) },
      { expires_at: "2026-08-15T11:59:59Z" },
      { created_at: "2026-08-15T12:00:31Z" },
    ];
    for (const artifact of cases) {
      const harness = await candidateHarness({ artifact });
      await expect(harness.reader.authorize(harness.input, harness.authority)).rejects.toThrow(
        /CANDIDATE_ARTIFACT_/u,
      );
      expect(harness.calls.some((call) => call.redirect === "manual")).toBe(false);
    }
  });

  it("rejects pagination, duplicates and disagreement between exact artifact endpoints", async () => {
    const paginated = await candidateHarness({ artifactsLink: true });
    await expect(paginated.reader.authorize(paginated.input, paginated.authority)).rejects.toThrow(
      "CANDIDATE_ARTIFACT_SET_AMBIGUOUS",
    );

    const mismatched = await candidateHarness({ listedArtifact: { size_in_bytes: 5 } });
    await expect(
      mismatched.reader.authorize(mismatched.input, mismatched.authority),
    ).rejects.toThrow("CANDIDATE_ARTIFACT_LIST_MISMATCH");
  });

  it("requires an annotated provider tag peeled to the exact release commit", async () => {
    const lightweight = await candidateHarness({
      reference: { object: { sha: CANDIDATE_COMMIT, type: "commit" } },
    });
    await expect(
      lightweight.reader.authorize(lightweight.input, lightweight.authority),
    ).rejects.toThrow("CANDIDATE_TAG_INVALID");

    const wrongPeeled = await candidateHarness({
      tag: {
        object: { sha: "c".repeat(40), type: "commit" },
        sha: CANDIDATE_TAG_OBJECT,
      },
    });
    await expect(
      wrongPeeled.reader.authorize(wrongPeeled.input, wrongPeeled.authority),
    ).rejects.toThrow("CANDIDATE_TAG_INVALID");
  });

  it("requires exact A1 policy bytes, Git blob identity and bounded encoding", async () => {
    const invalidEncoding = await candidateHarness({ policy: { content: "!!!!" } });
    await expect(
      invalidEncoding.reader.authorize(invalidEncoding.input, invalidEncoding.authority),
    ).rejects.toThrow("CANDIDATE_POLICY_ENCODING_INVALID");

    const wrongBlob = await candidateHarness({ policy: { sha: "0".repeat(40) } });
    await expect(wrongBlob.reader.authorize(wrongBlob.input, wrongBlob.authority)).rejects.toThrow(
      "CANDIDATE_POLICY_BLOB_INVALID",
    );

    const wrongAuthority = await candidateHarness();
    await expect(
      wrongAuthority.reader.authorize(wrongAuthority.input, {
        ...wrongAuthority.authority,
        policySha256: "sha256:" + "0".repeat(64),
      }),
    ).rejects.toThrow("CANDIDATE_POLICY_DIGEST_MISMATCH");

    await expect(
      wrongAuthority.reader.authorize(wrongAuthority.input, {
        ...wrongAuthority.authority,
        policyBlobSha: "0".repeat(40),
      }),
    ).rejects.toThrow("CANDIDATE_POLICY_BLOB_MISMATCH");
  });

  it("rejects redirect, host and repeated near-expiry provider capabilities", async () => {
    const noRedirect = await candidateHarness({ redirectStatus: 200 });
    await expect(
      noRedirect.reader.authorize(noRedirect.input, noRedirect.authority),
    ).rejects.toThrow("CANDIDATE_SOURCE_REDIRECT_INVALID");

    const hostile = await candidateHarness({
      redirectLocations: ["https://evil.invalid/actions-results/artifact.zip"],
    });
    await expect(hostile.reader.authorize(hostile.input, hostile.authority)).rejects.toThrow(
      "CANDIDATE_SOURCE_URL_INVALID",
    );

    const stale = await candidateHarness({
      redirectLocations: [signedUrl("2026-08-15T12:00:05Z"), signedUrl("2026-08-15T12:00:06Z")],
    });
    await expect(stale.reader.authorize(stale.input, stale.authority)).rejects.toThrow(
      "CANDIDATE_SOURCE_REFRESH_REQUIRED",
    );
    expect(stale.calls.filter((call) => call.redirect === "manual")).toHaveLength(2);
  });
});

function exactWorkflowRun(overrides: Readonly<JsonObject>): JsonObject {
  return {
    head_branch: "v0.74.0",
    head_repository_id: TRUST.targetRepositoryId,
    head_sha: CANDIDATE_COMMIT,
    id: 123,
    repository_id: TRUST.targetRepositoryId,
    ...overrides,
  };
}
