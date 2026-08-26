import { describe, expect, it } from "vitest";

import { digestObject } from "../src/canonical";
import { TRUST } from "../src/config";
import {
  ControllerRunReader,
  type ControllerRunRequest,
  parseControllerRunRequest,
} from "../src/private/controller-run-reader";
import type { ProviderFetch } from "../src/private/github-provider";
import type { JsonObject } from "../src/types";

const API = `https://api.github.com/repos/${TRUST.controllerRepository}`;
const COMMIT = "c".repeat(40);
const TAG_OBJECT = "a".repeat(40);
const BLOB = "f".repeat(40);
const VERSION = "controller-reader-version-0001";

describe("private controller run reader", () => {
  it("cross-binds one active job, immutable tag and current default-branch workflow", async () => {
    const calls: string[] = [];
    const reader = new ControllerRunReader(config(), tokenSource(), provider(calls));
    const result = await reader.verify(input());

    expect(result).toMatchObject({
      app_id: "101",
      check_run_id: 456,
      controller_peeled_commit_sha: COMMIT,
      default_branch_workflow_blob_sha: BLOB,
      job_name: "admit",
      status: "in_progress",
      worker_version_id: VERSION,
    });
    const unsigned = { ...result };
    delete unsigned.observation_sha256;
    expect(result.observation_sha256).toBe(await digestObject(unsigned));
    expect(calls.sort()).toEqual(expectedPaths().sort());
  });

  it("accepts historical P after master advances but rejects a missing workflow identity", async () => {
    const advanced = provider([], {
      contents: { sha: "e".repeat(40) },
    });
    await expect(
      new ControllerRunReader(config(), tokenSource(), advanced).verify(input()),
    ).resolves.toMatchObject({ default_branch_workflow_blob_sha: "e".repeat(40) });

    const replaced = provider([], {
      workflow: { id: 999 },
    });
    await expect(
      new ControllerRunReader(config(), tokenSource(), replaced).verify(input()),
    ).rejects.toThrow("CONTROLLER_WORKFLOW_INVALID");
  });

  it("rejects another job, completed state, wrong check app and ambiguous pagination", async () => {
    await expect(
      new ControllerRunReader(
        config(),
        tokenSource(),
        provider([], { job: { name: "publish" } }),
      ).verify(input()),
    ).rejects.toThrow("CONTROLLER_RUN_JOB_INVALID");

    await expect(
      new ControllerRunReader(
        config(),
        tokenSource(),
        provider([], { run: { conclusion: "success", status: "completed" } }),
      ).verify(input()),
    ).rejects.toThrow("CONTROLLER_RUN_INVALID");

    await expect(
      new ControllerRunReader(
        config(),
        tokenSource(),
        provider([], { checkAppSlug: "untrusted-check-app" }),
      ).verify(input()),
    ).rejects.toThrow("CONTROLLER_CHECK_RUN_INVALID");

    await expect(
      new ControllerRunReader(config(), tokenSource(), provider([], { jobsLink: true })).verify(
        input(),
      ),
    ).rejects.toThrow("CONTROLLER_RUN_JOB_SET_AMBIGUOUS");
  });

  it("fails before provider access on A0 App binding or request-shape drift", async () => {
    let accessed = false;
    const fetcher: ProviderFetch = async () => {
      accessed = true;
      throw new Error("must not be called");
    };
    await expect(
      new ControllerRunReader(config(), tokenSource(), fetcher).verify({
        ...input(),
        appId: "102",
      }),
    ).rejects.toThrow("CONTROLLER_RUN_APP_BINDING_MISMATCH");
    expect(accessed).toBe(false);

    expect(() =>
      parseControllerRunRequest({ ...requestBody(), controller_ref: "refs/heads/master" }),
    ).toThrow("FIELD_INVALID");
    expect(() => parseControllerRunRequest({ ...requestBody(), check_run_id: false })).toThrow(
      "FIELD_INVALID",
    );
    expect(() =>
      parseControllerRunRequest({
        ...requestBody(),
        check_run_id: Number.MAX_SAFE_INTEGER + 1,
      }),
    ).toThrow("FIELD_INVALID");
    expect(() =>
      parseControllerRunRequest({ ...requestBody(), url: "https://evil.invalid" }),
    ).toThrow("UNKNOWN_FIELD");
  });
});

interface Overrides {
  readonly checkAppSlug?: string;
  readonly contents?: Readonly<JsonObject>;
  readonly job?: Readonly<JsonObject>;
  readonly jobsLink?: boolean;
  readonly run?: Readonly<JsonObject>;
  readonly workflow?: Readonly<JsonObject>;
}

function provider(calls: string[], overrides: Overrides = {}): ProviderFetch {
  return async (target, init) => {
    const url = providerTargetUrl(target);
    calls.push(url);
    expect(init?.method).toBe("GET");
    expect(init?.redirect).toBe("error");
    const headers = new Headers(init?.headers);
    expect(headers.get("authorization")).toBe("Bearer ghs_TestInstallationToken1234");
    expect(headers.get("x-github-api-version")).toBe("2026-03-10");

    if (url === API) return response(repository());
    if (url === `${API}/actions/workflows/987654321`) {
      return response({ ...workflow(), ...overrides.workflow });
    }
    if (url === `${API}/actions/runs/123`) {
      return response({ ...run(), ...overrides.run });
    }
    if (url === `${API}/actions/runs/123/attempts/2/jobs?per_page=100&page=1`) {
      return response(
        { jobs: [{ ...job(), ...overrides.job }], total_count: 1 },
        overrides.jobsLink ? { link: `<${url}&page=2>; rel="next"` } : {},
      );
    }
    if (url === `${API}/check-runs/456`) {
      return response(checkRun(overrides.checkAppSlug));
    }
    if (url === `${API}/contents/.github/workflows/release-controller.yml?ref=master`) {
      return response({ ...contents(), ...overrides.contents });
    }
    if (url === `${API}/git/ref/tags/v1.0.0`) return response(tagRef());
    if (url === `${API}/git/tags/${TAG_OBJECT}`) return response(tagObject());
    return new Response("not found", { status: 404 });
  };
}

function providerTargetUrl(target: RequestInfo | URL): string {
  if (typeof target === "string") return target;
  return target instanceof URL ? target.toString() : target.url;
}

function repository(): JsonObject {
  return {
    default_branch: "master",
    full_name: TRUST.controllerRepository,
    id: TRUST.controllerRepositoryId,
    private: false,
  };
}

function workflow(): JsonObject {
  return {
    id: 987_654_321,
    path: TRUST.controllerWorkflowPath,
    state: "active",
  };
}

function run(): JsonObject {
  return {
    conclusion: null,
    event: "workflow_dispatch",
    head_branch: "v1.0.0",
    head_sha: COMMIT,
    id: 123,
    path: TRUST.controllerWorkflowPath,
    repository: { id: TRUST.controllerRepositoryId },
    run_attempt: 2,
    status: "in_progress",
    workflow_id: 987_654_321,
  };
}

function job(): JsonObject {
  return {
    check_run_url: `${API}/check-runs/456`,
    conclusion: null,
    head_sha: COMMIT,
    id: 456,
    name: "admit",
    run_id: 123,
    run_url: `${API}/actions/runs/123`,
    status: "in_progress",
  };
}

function checkRun(appSlug = "github-actions"): JsonObject {
  return {
    app: { slug: appSlug },
    check_suite: { head_sha: COMMIT },
    conclusion: null,
    details_url: `https://github.com/${TRUST.controllerRepository}/actions/runs/123/job/456`,
    head_sha: COMMIT,
    id: 456,
    name: "admit",
    status: "in_progress",
  };
}

function contents(): JsonObject {
  return {
    name: "release-controller.yml",
    path: TRUST.controllerWorkflowPath,
    sha: BLOB,
    size: 4096,
    type: "file",
  };
}

function tagRef(): JsonObject {
  return {
    object: { sha: TAG_OBJECT, type: "tag" },
    ref: "refs/tags/v1.0.0",
  };
}

function tagObject(): JsonObject {
  return {
    object: { sha: COMMIT, type: "commit" },
    sha: TAG_OBJECT,
    tag: "v1.0.0",
  };
}

function input(): ControllerRunRequest {
  return {
    appId: "101",
    appSlug: "controller-reader",
    checkRunId: 456,
    expectedJobName: "admit",
    installationId: "202",
    peeledCommitSha: COMMIT,
    ref: "refs/tags/v1.0.0",
    requestId: "request-00000001",
    runAttempt: 2,
    runId: 123,
    tagObjectSha: TAG_OBJECT,
    workflowId: 987_654_321,
    workflowPath: TRUST.controllerWorkflowPath,
    workflowRef: `${TRUST.controllerRepository}/${TRUST.controllerWorkflowPath}@refs/tags/v1.0.0`,
    workflowSha: COMMIT,
  };
}

function requestBody(): JsonObject {
  const value = input();
  return {
    app_id: value.appId,
    app_slug: value.appSlug,
    check_run_id: value.checkRunId,
    controller_peeled_commit_sha: value.peeledCommitSha,
    controller_ref: value.ref,
    controller_ref_type: "tag",
    controller_tag_object_sha: value.tagObjectSha,
    expected_job_name: value.expectedJobName,
    installation_id: value.installationId,
    repository_id: TRUST.controllerRepositoryId,
    request_id: value.requestId,
    run_attempt: value.runAttempt,
    run_id: value.runId,
    schema: "dpone.release-controller-run-observation-request.v1",
    schema_version: 1,
    workflow_id: value.workflowId,
    workflow_path: value.workflowPath,
    workflow_ref: value.workflowRef,
    workflow_sha: value.workflowSha,
  };
}

function config() {
  return {
    appId: "101",
    appSlug: "controller-reader",
    installationId: "202",
    workerVersionId: VERSION,
  };
}

function tokenSource() {
  return {
    installationToken: async () => "ghs_TestInstallationToken1234",
  };
}

function response(body: JsonObject, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json", ...headers },
    status: 200,
  });
}

function expectedPaths(): string[] {
  return [
    API,
    `${API}/actions/workflows/987654321`,
    `${API}/actions/runs/123`,
    `${API}/actions/runs/123/attempts/2/jobs?per_page=100&page=1`,
    `${API}/check-runs/456`,
    `${API}/contents/.github/workflows/release-controller.yml?ref=master`,
    `${API}/git/ref/tags/v1.0.0`,
    `${API}/git/tags/${TAG_OBJECT}`,
  ];
}
