import { TRUST } from "../config";
import { BrokerError } from "../errors";
import type { JsonObject } from "../types";
import type { ControllerRunRequest } from "./controller-run-reader";
import {
  providerArray,
  providerInteger,
  providerObject,
  providerString,
  requireProviderLiteral,
} from "./github-provider";

const API_REPOSITORY = `/repos/${TRUST.controllerRepository}` as const;

export function verifyRepository(repository: JsonObject): void {
  requireProviderInteger(
    repository,
    "id",
    TRUST.controllerRepositoryId,
    "CONTROLLER_REPOSITORY_INVALID",
  );
  requireProviderLiteral(
    repository,
    "full_name",
    TRUST.controllerRepository,
    "CONTROLLER_REPOSITORY_INVALID",
  );
  requireProviderLiteral(repository, "default_branch", "master", "CONTROLLER_REPOSITORY_INVALID");
  requireProviderLiteral(repository, "private", false, "CONTROLLER_REPOSITORY_INVALID");
}

export function verifyWorkflow(workflow: JsonObject, input: ControllerRunRequest): void {
  requireProviderInteger(workflow, "id", input.workflowId, "CONTROLLER_WORKFLOW_INVALID");
  requireProviderLiteral(workflow, "path", input.workflowPath, "CONTROLLER_WORKFLOW_INVALID");
  requireProviderLiteral(workflow, "state", "active", "CONTROLLER_WORKFLOW_INVALID");
}

export function verifyRun(run: JsonObject, input: ControllerRunRequest): void {
  requireProviderInteger(run, "id", input.runId, "CONTROLLER_RUN_INVALID");
  requireProviderInteger(run, "run_attempt", input.runAttempt, "CONTROLLER_RUN_INVALID");
  requireProviderInteger(run, "workflow_id", input.workflowId, "CONTROLLER_RUN_INVALID");
  requireProviderLiteral(run, "path", input.workflowPath, "CONTROLLER_RUN_INVALID");
  requireProviderLiteral(run, "event", "workflow_dispatch", "CONTROLLER_RUN_INVALID");
  requireProviderLiteral(run, "head_sha", input.workflowSha, "CONTROLLER_RUN_INVALID");
  requireProviderLiteral(
    run,
    "head_branch",
    input.ref.slice("refs/tags/".length),
    "CONTROLLER_RUN_INVALID",
  );
  requireProviderLiteral(run, "status", "in_progress", "CONTROLLER_RUN_INVALID");
  requireProviderLiteral(run, "conclusion", null, "CONTROLLER_RUN_INVALID");
  const repository = providerObject(run.repository, "CONTROLLER_RUN_INVALID");
  requireProviderInteger(repository, "id", TRUST.controllerRepositoryId, "CONTROLLER_RUN_INVALID");
}

export function verifyJob(jobs: JsonObject, input: ControllerRunRequest): void {
  const values = providerArray(jobs, "jobs", "CONTROLLER_RUN_JOBS_INVALID");
  const total = jobs.total_count;
  if (
    typeof total !== "number" ||
    !Number.isSafeInteger(total) ||
    total !== values.length ||
    total > 100
  ) {
    throw new BrokerError("CONTROLLER_RUN_JOB_SET_AMBIGUOUS", 503, false);
  }
  const matches = values
    .map((value) => providerObject(value, "CONTROLLER_RUN_JOBS_INVALID"))
    .filter((job) => job.id === input.checkRunId);
  const [job] = matches;
  if (matches.length !== 1 || job === undefined) {
    throw new BrokerError("CONTROLLER_RUN_JOB_NOT_FOUND", 503, false);
  }
  requireProviderInteger(job, "id", input.checkRunId, "CONTROLLER_RUN_JOB_INVALID");
  requireProviderInteger(job, "run_id", input.runId, "CONTROLLER_RUN_JOB_INVALID");
  requireProviderLiteral(job, "name", input.expectedJobName, "CONTROLLER_RUN_JOB_INVALID");
  requireProviderLiteral(job, "head_sha", input.workflowSha, "CONTROLLER_RUN_JOB_INVALID");
  requireProviderLiteral(job, "status", "in_progress", "CONTROLLER_RUN_JOB_INVALID");
  requireProviderLiteral(job, "conclusion", null, "CONTROLLER_RUN_JOB_INVALID");
  requireProviderLiteral(
    job,
    "run_url",
    `${API_REPOSITORY}/actions/runs/${input.runId}`.replace(
      API_REPOSITORY,
      `https://api.github.com${API_REPOSITORY}`,
    ),
    "CONTROLLER_RUN_JOB_INVALID",
  );
  requireProviderLiteral(
    job,
    "check_run_url",
    `https://api.github.com${API_REPOSITORY}/check-runs/${input.checkRunId}`,
    "CONTROLLER_RUN_JOB_INVALID",
  );
}

export function verifyCheckRun(check: JsonObject, input: ControllerRunRequest): void {
  requireProviderInteger(check, "id", input.checkRunId, "CONTROLLER_CHECK_RUN_INVALID");
  requireProviderLiteral(check, "name", input.expectedJobName, "CONTROLLER_CHECK_RUN_INVALID");
  requireProviderLiteral(check, "head_sha", input.workflowSha, "CONTROLLER_CHECK_RUN_INVALID");
  requireProviderLiteral(check, "status", "in_progress", "CONTROLLER_CHECK_RUN_INVALID");
  requireProviderLiteral(check, "conclusion", null, "CONTROLLER_CHECK_RUN_INVALID");
  requireProviderLiteral(
    check,
    "details_url",
    `https://github.com/${TRUST.controllerRepository}/actions/runs/${input.runId}/job/${input.checkRunId}`,
    "CONTROLLER_CHECK_RUN_INVALID",
  );
  const app = providerObject(check.app, "CONTROLLER_CHECK_RUN_INVALID");
  requireProviderLiteral(app, "slug", "github-actions", "CONTROLLER_CHECK_RUN_INVALID");
  const suite = providerObject(check.check_suite, "CONTROLLER_CHECK_RUN_INVALID");
  requireProviderLiteral(suite, "head_sha", input.workflowSha, "CONTROLLER_CHECK_RUN_INVALID");
}

export function verifyDefaultBranchWorkflow(
  contents: JsonObject,
  input: ControllerRunRequest,
): string {
  requireProviderLiteral(contents, "type", "file", "CONTROLLER_DEFAULT_BRANCH_WORKFLOW_INVALID");
  requireProviderLiteral(
    contents,
    "path",
    input.workflowPath,
    "CONTROLLER_DEFAULT_BRANCH_WORKFLOW_INVALID",
  );
  requireProviderLiteral(
    contents,
    "name",
    "release-controller.yml",
    "CONTROLLER_DEFAULT_BRANCH_WORKFLOW_INVALID",
  );
  const size = providerInteger(contents, "size", "CONTROLLER_DEFAULT_BRANCH_WORKFLOW_INVALID");
  if (size > 1_048_576) {
    throw new BrokerError("CONTROLLER_DEFAULT_BRANCH_WORKFLOW_INVALID", 503, false);
  }
  return providerString(contents, "sha", 40, "CONTROLLER_DEFAULT_BRANCH_WORKFLOW_INVALID");
}

export function verifyTagReference(reference: JsonObject, input: ControllerRunRequest): void {
  requireProviderLiteral(reference, "ref", input.ref, "CONTROLLER_TAG_REF_INVALID");
  const object = providerObject(reference.object, "CONTROLLER_TAG_REF_INVALID");
  requireProviderLiteral(object, "type", "tag", "CONTROLLER_TAG_REF_INVALID");
  requireProviderLiteral(object, "sha", input.tagObjectSha, "CONTROLLER_TAG_REF_INVALID");
}

export function verifyAnnotatedTag(
  tagObject: JsonObject,
  tag: string,
  input: ControllerRunRequest,
): void {
  requireProviderLiteral(tagObject, "sha", input.tagObjectSha, "CONTROLLER_TAG_OBJECT_INVALID");
  requireProviderLiteral(tagObject, "tag", tag, "CONTROLLER_TAG_OBJECT_INVALID");
  const object = providerObject(tagObject.object, "CONTROLLER_TAG_OBJECT_INVALID");
  requireProviderLiteral(object, "type", "commit", "CONTROLLER_TAG_OBJECT_INVALID");
  requireProviderLiteral(object, "sha", input.peeledCommitSha, "CONTROLLER_TAG_OBJECT_INVALID");
}

function requireProviderInteger(
  object: JsonObject,
  key: string,
  expected: number,
  code: string,
): void {
  if (providerInteger(object, key, code) !== expected) {
    throw new BrokerError(code, 503, false);
  }
}
