import { digestObject } from "../canonical";
import { TRUST } from "../config";
import { BrokerError } from "../errors";
import type { JsonObject } from "../types";
import { exactObject, requireInteger, requireString } from "../validation";
import type { InstallationTokenSource } from "./github-app";
import { githubJson, githubRequest, type ProviderFetch, requireGitHubOk } from "./github-provider";
import {
  verifyAnnotatedTag,
  verifyCheckRun,
  verifyDefaultBranchWorkflow,
  verifyJob,
  verifyRepository,
  verifyRun,
  verifyTagReference,
  verifyWorkflow,
} from "./controller-run-reader-provider";

const API_REPOSITORY = `/repos/${TRUST.controllerRepository}` as const;
const POSITIVE_ID = /^[1-9][0-9]{0,31}$/u;
const SHA1 = /^[0-9a-f]{40}$/u;
const TAG_REF = /^refs\/tags\/v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/u;
const JOB_NAME = /^[A-Za-z0-9][A-Za-z0-9 ._/:()-]{0,127}$/u;
const PROVIDER_JSON_LIMIT = 262_144;

export interface ControllerRunReaderConfig {
  readonly appId: string;
  readonly appSlug: string;
  readonly installationId: string;
  readonly workerVersionId: string;
}

export interface ControllerRunRequest {
  readonly appId: string;
  readonly appSlug: string;
  readonly checkRunId: number;
  readonly expectedJobName: string;
  readonly installationId: string;
  readonly peeledCommitSha: string;
  readonly ref: string;
  readonly requestId: string;
  readonly runAttempt: number;
  readonly runId: number;
  readonly tagObjectSha: string;
  readonly workflowId: number;
  readonly workflowPath: string;
  readonly workflowRef: string;
  readonly workflowSha: string;
}

/**
 * Closed controller metadata reader. Its public surface is one semantic
 * operation; arbitrary GitHub methods, repositories, paths and URLs are not
 * representable by the request type.
 */
export class ControllerRunReader {
  public constructor(
    private readonly config: ControllerRunReaderConfig,
    private readonly tokens: InstallationTokenSource,
    private readonly providerFetch: ProviderFetch = fetch,
  ) {
    validateConfig(config);
  }

  public async verify(input: ControllerRunRequest): Promise<JsonObject> {
    this.assertCredentialBinding(input);
    const token = await this.tokens.installationToken();
    const authorization = `Bearer ${token}`;
    const tag = input.ref.slice("refs/tags/".length);
    const [repository, workflow, run, jobsResponse, checkRun, contents, tagRef, tagObject] =
      await Promise.all([
        this.get(authorization, API_REPOSITORY),
        this.get(authorization, `${API_REPOSITORY}/actions/workflows/${input.workflowId}`),
        this.get(authorization, `${API_REPOSITORY}/actions/runs/${input.runId}`),
        this.getResponse(
          authorization,
          `${API_REPOSITORY}/actions/runs/${input.runId}/attempts/${input.runAttempt}/jobs?per_page=100&page=1`,
        ),
        this.get(authorization, `${API_REPOSITORY}/check-runs/${input.checkRunId}`),
        this.get(
          authorization,
          `${API_REPOSITORY}/contents/${TRUST.controllerWorkflowPath}?ref=master`,
        ),
        this.get(authorization, `${API_REPOSITORY}/git/ref/tags/${tag}`),
        this.get(authorization, `${API_REPOSITORY}/git/tags/${input.tagObjectSha}`),
      ]);
    if (jobsResponse.headers.has("link")) {
      await jobsResponse.body?.cancel("CONTROLLER_RUN_JOB_SET_AMBIGUOUS").catch(() => undefined);
      throw new BrokerError("CONTROLLER_RUN_JOB_SET_AMBIGUOUS", 503, false);
    }
    const jobs = await githubJson(jobsResponse, PROVIDER_JSON_LIMIT, "CONTROLLER_RUN_JOBS_INVALID");
    verifyRepository(repository);
    verifyWorkflow(workflow, input);
    verifyRun(run, input);
    verifyJob(jobs, input);
    verifyCheckRun(checkRun, input);
    const workflowBlobSha = verifyDefaultBranchWorkflow(contents, input);
    verifyTagReference(tagRef, input);
    verifyAnnotatedTag(tagObject, tag, input);
    const defaultBranchObservation = await digestObject({
      default_branch_ref: TRUST.controllerDefaultBranchRef,
      repository_id: TRUST.controllerRepositoryId,
      request_id: input.requestId,
      workflow_blob_sha: workflowBlobSha,
      workflow_id: input.workflowId,
      workflow_path: input.workflowPath,
    });
    const observation: JsonObject = {
      app_id: this.config.appId,
      app_slug: this.config.appSlug,
      check_run_id: input.checkRunId,
      conclusion: null,
      controller_peeled_commit_sha: input.peeledCommitSha,
      controller_ref: input.ref,
      controller_tag_object_sha: input.tagObjectSha,
      default_branch_ref: TRUST.controllerDefaultBranchRef,
      default_branch_workflow_blob_sha: workflowBlobSha,
      default_branch_workflow_observation_sha256: defaultBranchObservation,
      event: "workflow_dispatch",
      head_sha: input.workflowSha,
      installation_id: this.config.installationId,
      job_name: input.expectedJobName,
      repository_id: TRUST.controllerRepositoryId,
      request_id: input.requestId,
      run_attempt: input.runAttempt,
      run_id: input.runId,
      schema: "dpone.release-controller-run-observation.v1",
      schema_version: 1,
      status: "in_progress",
      worker_version_id: this.config.workerVersionId,
      workflow_id: input.workflowId,
      workflow_path: input.workflowPath,
      workflow_sha: input.workflowSha,
    };
    return { ...observation, observation_sha256: await digestObject(observation) };
  }

  private assertCredentialBinding(input: ControllerRunRequest): void {
    if (
      input.appId !== this.config.appId ||
      input.appSlug !== this.config.appSlug ||
      input.installationId !== this.config.installationId
    ) {
      throw new BrokerError("CONTROLLER_RUN_APP_BINDING_MISMATCH", 503, false);
    }
  }

  private async get(authorization: string, path: `/${string}`): Promise<JsonObject> {
    const response = await this.getResponse(authorization, path);
    return githubJson(response, PROVIDER_JSON_LIMIT, "CONTROLLER_RUN_PROVIDER_RESPONSE_INVALID");
  }

  private async getResponse(authorization: string, path: `/${string}`): Promise<Response> {
    const response = await githubRequest(this.providerFetch, {
      authorization,
      method: "GET",
      path,
    });
    await requireGitHubOk(response, "CONTROLLER_RUN_PROVIDER_REQUEST_FAILED");
    return response;
  }
}

export function parseControllerRunRequest(value: unknown): ControllerRunRequest {
  const body = exactObject(value, [
    "app_id",
    "app_slug",
    "check_run_id",
    "controller_peeled_commit_sha",
    "controller_ref",
    "controller_ref_type",
    "controller_tag_object_sha",
    "expected_job_name",
    "installation_id",
    "repository_id",
    "request_id",
    "run_attempt",
    "run_id",
    "schema",
    "schema_version",
    "workflow_id",
    "workflow_path",
    "workflow_ref",
    "workflow_sha",
  ]);
  requireLiteral(body, "schema", "dpone.release-controller-run-observation-request.v1");
  requireExactInteger(body, "schema_version", 1);
  requireExactInteger(body, "repository_id", TRUST.controllerRepositoryId);
  requireLiteral(body, "controller_ref_type", "tag");
  requireLiteral(body, "workflow_path", TRUST.controllerWorkflowPath);
  const ref = requireString(body, "controller_ref", 80, TAG_REF);
  const workflowRef = requireString(body, "workflow_ref", 256);
  if (workflowRef !== `${TRUST.controllerRepository}/${TRUST.controllerWorkflowPath}@${ref}`) {
    throw new BrokerError("CONTROLLER_RUN_WORKFLOW_REF_INVALID", 400, false);
  }
  const peeledCommitSha = requireString(body, "controller_peeled_commit_sha", 40, SHA1);
  const workflowSha = requireString(body, "workflow_sha", 40, SHA1);
  if (peeledCommitSha !== workflowSha) {
    throw new BrokerError("CONTROLLER_RUN_WORKFLOW_SHA_INVALID", 400, false);
  }
  const tagObjectSha = requireString(body, "controller_tag_object_sha", 40, SHA1);
  if (tagObjectSha === peeledCommitSha) {
    throw new BrokerError("CONTROLLER_RUN_TAG_NOT_ANNOTATED", 400, false);
  }
  return {
    appId: requireString(body, "app_id", 32, POSITIVE_ID),
    appSlug: requireString(body, "app_slug", 128, SAFE_NAME),
    checkRunId: requireInteger(body, "check_run_id", 1),
    expectedJobName: requireString(body, "expected_job_name", 128, JOB_NAME),
    installationId: requireString(body, "installation_id", 32, POSITIVE_ID),
    peeledCommitSha,
    ref,
    requestId: requireString(body, "request_id", 128, /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u),
    runAttempt: requireInteger(body, "run_attempt", 1, 1000),
    runId: requireInteger(body, "run_id", 1),
    tagObjectSha,
    workflowId: requireInteger(body, "workflow_id", 1),
    workflowPath: TRUST.controllerWorkflowPath,
    workflowRef,
    workflowSha,
  };
}

function validateConfig(config: ControllerRunReaderConfig): void {
  if (
    !POSITIVE_ID.test(config.appId) ||
    !POSITIVE_ID.test(config.installationId) ||
    !SAFE_NAME.test(config.appSlug) ||
    !SAFE_NAME.test(config.workerVersionId)
  ) {
    throw new BrokerError("CONTROLLER_RUN_READER_CONFIGURATION_INVALID", 503, false);
  }
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  if (requireString(object, key, Math.max(1, expected.length)) !== expected) {
    throw new BrokerError("CONTROLLER_RUN_REQUEST_INVALID", 400, false);
  }
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  if (requireInteger(object, key, expected, expected) !== expected) {
    throw new BrokerError("CONTROLLER_RUN_REQUEST_INVALID", 400, false);
  }
}
