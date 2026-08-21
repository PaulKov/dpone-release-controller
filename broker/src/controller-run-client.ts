import { canonicalBytes, canonicalJson, digestObject } from "./canonical";
import { INTERNAL_RESPONSE_READ_POLICY, readBoundedBytes } from "./bounded";
import { TRUST } from "./config";
import { assert, BrokerError } from "./errors";
import { assertPinnedServiceVersion, callPinnedService } from "./service-version";
import type { AuthenticatedWorkflow, GitHubAppPin, JsonObject, PrivateServicePin } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export interface ControllerJobObservation {
  readonly defaultBranchRef: "refs/heads/master";
  readonly defaultBranchWorkflowBlobSha: string;
  readonly defaultBranchWorkflowObservationSha256: string;
  readonly digest: string;
  readonly jobName: string;
}

export interface ControllerRunExpectation {
  readonly app: GitHubAppPin;
  readonly defaultBranchWorkflowBlobSha: string;
  readonly jobName: string;
  readonly peeledCommitSha: string;
  readonly ref: string;
  readonly tagObjectSha: string;
  readonly workflowId: number;
  readonly workflowRef: string;
}

/**
 * Closed client for the controller-run-reader private Worker. That adapter may
 * execute only the exact GitHub GETs needed to cross-bind one check run.
 */
export class ControllerRunClient {
  public constructor(
    private readonly service: Fetcher,
    private readonly pin: PrivateServicePin,
    private readonly expected: ControllerRunExpectation,
  ) {}

  public async verify(
    auth: AuthenticatedWorkflow,
    requestId: string,
  ): Promise<ControllerJobObservation> {
    assert(/^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u.test(requestId), "REQUEST_ID_INVALID", 500);
    assert(
      auth.ref === this.expected.ref &&
        auth.sha === this.expected.peeledCommitSha &&
        auth.workflowRef === this.expected.workflowRef &&
        auth.workflowSha === this.expected.peeledCommitSha,
      "CONTROLLER_RUN_EXPECTATION_MISMATCH",
      500,
    );
    const body: JsonObject = {
      app_id: this.expected.app.appId,
      app_slug: this.expected.app.appSlug,
      check_run_id: positiveInteger(auth.checkRunId, "OIDC_CHECK_RUN_ID_INVALID"),
      controller_peeled_commit_sha: this.expected.peeledCommitSha,
      controller_ref: this.expected.ref,
      controller_ref_type: "tag",
      controller_tag_object_sha: this.expected.tagObjectSha,
      expected_job_name: this.expected.jobName,
      installation_id: this.expected.app.installationId,
      repository_id: auth.repositoryId,
      request_id: requestId,
      run_attempt: auth.runAttempt,
      run_id: positiveInteger(auth.runId, "OIDC_RUN_ID_INVALID"),
      schema: "dpone.release-controller-run-observation-request.v1",
      schema_version: 1,
      workflow_id: this.expected.workflowId,
      workflow_path: TRUST.controllerWorkflowPath,
      workflow_ref: this.expected.workflowRef,
      workflow_sha: auth.workflowSha,
    };
    const bytes = canonicalBytes(body);
    const response = await callPinnedService(this.service, this.pin, {
      body: Uint8Array.from(bytes).buffer,
      headers: {
        "content-length": String(bytes.byteLength),
        "content-type": "application/json",
        "x-request-id": requestId,
      },
      method: "POST",
      path: "/rpc/v1/verify-check-run",
    });
    if (!response.ok) {
      throw new BrokerError(
        "CONTROLLER_RUN_CROSSCHECK_FAILED",
        503,
        response.status >= 500 || response.status === 429,
      );
    }
    const responseBytes = await readBoundedBytes(
      response,
      8192,
      "CONTROLLER_RUN_RESPONSE_TOO_LARGE",
      INTERNAL_RESPONSE_READ_POLICY,
    );
    const text = new TextDecoder("utf-8", { fatal: true }).decode(responseBytes);
    let decoded: unknown;
    try {
      decoded = JSON.parse(text);
    } catch {
      throw new BrokerError("CONTROLLER_RUN_RESPONSE_INVALID", 503, false);
    }
    const observation = exactObject(decoded, [
      "app_id",
      "app_slug",
      "check_run_id",
      "conclusion",
      "controller_peeled_commit_sha",
      "controller_ref",
      "controller_tag_object_sha",
      "default_branch_ref",
      "default_branch_workflow_blob_sha",
      "default_branch_workflow_observation_sha256",
      "event",
      "head_sha",
      "installation_id",
      "job_name",
      "observation_sha256",
      "repository_id",
      "request_id",
      "run_attempt",
      "run_id",
      "schema",
      "schema_version",
      "status",
      "workflow_id",
      "workflow_path",
      "workflow_sha",
      "worker_version_id",
    ]);
    assert(text === canonicalJson(observation), "CONTROLLER_RUN_RESPONSE_NONCANONICAL", 503);
    requireLiteral(observation, "schema", "dpone.release-controller-run-observation.v1");
    assertPinnedServiceVersion(requireString(observation, "worker_version_id", 128), this.pin);
    requireExactInteger(observation, "schema_version", 1);
    requireExactInteger(observation, "repository_id", auth.repositoryId);
    requireLiteral(observation, "request_id", requestId);
    requireExactInteger(observation, "workflow_id", this.expected.workflowId);
    requireLiteral(observation, "workflow_path", TRUST.controllerWorkflowPath);
    requireLiteral(observation, "workflow_sha", auth.workflowSha);
    requireLiteral(observation, "head_sha", auth.sha);
    requireLiteral(observation, "app_id", this.expected.app.appId);
    requireLiteral(observation, "app_slug", this.expected.app.appSlug);
    requireLiteral(observation, "installation_id", this.expected.app.installationId);
    requireLiteral(observation, "controller_ref", this.expected.ref);
    requireLiteral(observation, "controller_tag_object_sha", this.expected.tagObjectSha);
    requireLiteral(observation, "controller_peeled_commit_sha", this.expected.peeledCommitSha);
    requireExactInteger(observation, "run_id", positiveInteger(auth.runId, "OIDC_RUN_ID_INVALID"));
    requireExactInteger(observation, "run_attempt", auth.runAttempt);
    requireExactInteger(
      observation,
      "check_run_id",
      positiveInteger(auth.checkRunId, "OIDC_CHECK_RUN_ID_INVALID"),
    );
    requireLiteral(observation, "event", "workflow_dispatch");
    requireLiteral(observation, "default_branch_ref", TRUST.controllerDefaultBranchRef);
    const defaultBranchWorkflowBlobSha = requireString(
      observation,
      "default_branch_workflow_blob_sha",
      40,
      /^[0-9a-f]{40}$/u,
    );
    assert(
      defaultBranchWorkflowBlobSha === this.expected.defaultBranchWorkflowBlobSha,
      "CONTROLLER_DEFAULT_BRANCH_WORKFLOW_DRIFT",
      503,
    );
    const defaultBranchWorkflowObservationSha256 = requireString(
      observation,
      "default_branch_workflow_observation_sha256",
      71,
      /^sha256:[0-9a-f]{64}$/u,
    );
    requireLiteral(observation, "status", "in_progress");
    assert(observation.conclusion === null, "CONTROLLER_RUN_CONCLUSION_INVALID", 503);
    const jobName = requireString(observation, "job_name", 128);
    assert(jobName === this.expected.jobName, "CONTROLLER_RUN_JOB_MISMATCH", 503);
    const digest = requireString(observation, "observation_sha256", 71, /^sha256:[0-9a-f]{64}$/u);
    const unsigned = { ...observation };
    delete unsigned.observation_sha256;
    assert((await digestObject(unsigned)) === digest, "CONTROLLER_RUN_DIGEST_MISMATCH", 503);
    return {
      defaultBranchRef: TRUST.controllerDefaultBranchRef,
      defaultBranchWorkflowBlobSha,
      defaultBranchWorkflowObservationSha256,
      digest,
      jobName,
    };
  }
}

function positiveInteger(value: string, code: string): number {
  assert(/^[1-9][0-9]{0,15}$/u.test(value), code, 401);
  const parsed = Number(value);
  assert(Number.isSafeInteger(parsed), code, 401);
  return parsed;
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, Math.max(1, expected.length)) === expected,
    "CONTROLLER_RUN_RESPONSE_MISMATCH",
    503,
  );
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "CONTROLLER_RUN_RESPONSE_MISMATCH",
    503,
  );
}
