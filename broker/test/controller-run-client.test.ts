import { describe, expect, it } from "vitest";

import { canonicalJson, digestObject } from "../src/canonical";
import { ControllerRunClient } from "../src/controller-run-client";
import type { AuthenticatedWorkflow, JsonObject, PrivateServicePin } from "../src/types";

const PIN: PrivateServicePin = {
  serviceIdentity:
    "cloudflare-worker:test-account/controller-run-reader-private@controller-reader-version-0001",
  serviceName: "controller-run-reader-private",
  versionId: "controller-reader-version-0001",
};
const REQUEST_ID = "controller-run-request-0001";

describe("controller run provider cross-check", () => {
  it("accepts only the active expected job and exact A0 workflow id", async () => {
    const client = new ControllerRunClient(service(), PIN, expectation());
    await expect(client.verify(authentication(), REQUEST_ID)).resolves.toMatchObject({
      jobName: "admit",
    });

    await expect(
      new ControllerRunClient(service({ job_name: "publish" }), PIN, expectation()).verify(
        authentication(),
        REQUEST_ID,
      ),
    ).rejects.toThrow("CONTROLLER_RUN_JOB_MISMATCH");

    await expect(
      new ControllerRunClient(service({ workflow_id: 987_654_322 }), PIN, expectation()).verify(
        authentication(),
        REQUEST_ID,
      ),
    ).rejects.toThrow("FIELD_INVALID");
  });

  it("rejects a token after the provider job has completed", async () => {
    await expect(
      new ControllerRunClient(
        service({ conclusion: "success", status: "completed" }),
        PIN,
        expectation(),
      ).verify(authentication(), REQUEST_ID),
    ).rejects.toThrow("CONTROLLER_RUN_RESPONSE_MISMATCH");
  });

  it("fails closed when the workflow path is missing from the current default branch", async () => {
    await expect(
      new ControllerRunClient(
        service({ default_branch_workflow_blob_sha: undefined }),
        PIN,
        expectation(),
      ).verify(authentication(), REQUEST_ID),
    ).rejects.toThrow();
  });

  it("fails closed when the current default-branch workflow blob drifts from A0", async () => {
    await expect(
      new ControllerRunClient(
        service({ default_branch_workflow_blob_sha: "e".repeat(40) }),
        PIN,
        expectation(),
      ).verify(authentication(), REQUEST_ID),
    ).rejects.toThrow("CONTROLLER_DEFAULT_BRANCH_WORKFLOW_DRIFT");
  });
});

function service(overrides: Record<string, unknown> = {}): Fetcher {
  return {
    async fetch(): Promise<Response> {
      const value: JsonObject = {
        app_id: "101",
        app_slug: "controller-reader",
        check_run_id: 456,
        conclusion: null,
        controller_peeled_commit_sha: "c".repeat(40),
        controller_ref: "refs/tags/v1.0.0",
        controller_tag_object_sha: "a".repeat(40),
        default_branch_ref: "refs/heads/master",
        default_branch_workflow_blob_sha: "f".repeat(40),
        default_branch_workflow_observation_sha256: tagged("9"),
        event: "workflow_dispatch",
        head_sha: "c".repeat(40),
        installation_id: "202",
        job_name: "admit",
        repository_id: 1_305_993_853,
        request_id: REQUEST_ID,
        run_attempt: 2,
        run_id: 123,
        schema: "dpone.release-controller-run-observation.v1",
        schema_version: 1,
        status: "in_progress",
        workflow_id: 987_654_321,
        workflow_path: ".github/workflows/release-controller.yml",
        workflow_sha: "c".repeat(40),
        worker_version_id: PIN.versionId,
        ...overrides,
      };
      if (value.default_branch_workflow_blob_sha === undefined) {
        delete value.default_branch_workflow_blob_sha;
      }
      value.observation_sha256 = await digestObject(value);
      return new Response(canonicalJson(value), {
        headers: { "content-type": "application/json" },
        status: 200,
      });
    },
  } as unknown as Fetcher;
}

function authentication(): AuthenticatedWorkflow {
  return {
    actorId: "74862786",
    audience: "dpone-release-controller-ledger-write",
    checkRunId: "456",
    environment: "release-attest",
    expiresAt: 2_000_000_300,
    issuedAt: 2_000_000_000,
    jti: "oidc-jti-0000000000000001",
    notBefore: 1_999_999_999,
    ref: "refs/tags/v1.0.0",
    repository: "PaulKov/dpone-release-controller",
    repositoryId: 1_305_993_853,
    repositoryOwnerId: "74862786",
    runAttempt: 2,
    runId: "123",
    sha: "c".repeat(40),
    subject: "test-subject",
    workflowRef:
      "PaulKov/dpone-release-controller/.github/workflows/release-controller.yml@refs/tags/v1.0.0",
    workflowSha: "c".repeat(40),
  };
}

function expectation() {
  return {
    app: {
      appId: "101",
      appSlug: "controller-reader",
      installationId: "202",
    },
    defaultBranchWorkflowBlobSha: "f".repeat(40),
    jobName: "admit",
    peeledCommitSha: "c".repeat(40),
    ref: "refs/tags/v1.0.0",
    tagObjectSha: "a".repeat(40),
    workflowId: 987_654_321,
    workflowRef:
      "PaulKov/dpone-release-controller/.github/workflows/release-controller.yml@refs/tags/v1.0.0",
  };
}

function tagged(character: string): string {
  return `sha256:${character.repeat(64)}`;
}
