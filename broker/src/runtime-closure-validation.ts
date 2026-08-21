import { TRUST } from "./config";
import { assert } from "./errors";
import {
  ACTIVATION_KEYS,
  ARCHIVE_SOURCE_KEYS,
  ARTIFACT_KEYS,
  CLOSED_CHECK_KEYS,
  CONTROLLER_RUN_KEYS,
  DIGEST,
  LEDGER_KEYS,
  OBSERVATION_KEYS,
  REQUEST_ID,
  RUNTIME_CLOSURE_MAX_RAW_BYTES,
  RUNTIME_CLOSURE_OBSERVATION_SCHEMA,
  RUNTIME_KEYS,
  SAFE_NAME,
  SHA1,
  TAG,
  TIMESTAMP,
  VERSION,
} from "./runtime-closure-contract";
import {
  requireExactInteger,
  requireLiteral,
  requireTimestamp,
  serviceObject,
  targetLineageAuthority,
  validateService,
} from "./runtime-closure-fields";
import { validateTargetLineage } from "./target-lineage";
import type { JsonObject } from "./types";
import { exactObject, requireBoolean, requireInteger, requireString } from "./validation";

/** Validate every exact field in the cross-repository provider observation. */
export function validateRuntimeClosureObservation(value: unknown): JsonObject {
  const observation = exactObject(value, OBSERVATION_KEYS);
  requireLiteral(observation, "schema", RUNTIME_CLOSURE_OBSERVATION_SCHEMA);
  requireExactInteger(observation, "schema_version", 1);
  requireString(observation, "broker_request_id", 128, REQUEST_ID);
  requireLiteral(observation, "provider_api_version", "2026-03-10");
  requireString(observation, "provider_response_sha256", 71, DIGEST);
  const activation = exactObject(observation.activation, ACTIVATION_KEYS);
  validateActivation(activation);
  validateLedger(exactObject(observation.ledger, LEDGER_KEYS));
  const runtime = exactObject(observation.runtime, RUNTIME_KEYS);
  validateRuntime(runtime);
  validateClosedCheck(exactObject(observation.closed_check, CLOSED_CHECK_KEYS));
  const controllerRun = exactObject(observation.controller_run, CONTROLLER_RUN_KEYS);
  validateControllerRun(controllerRun);
  validateArtifact(exactObject(observation.closure_artifact, ARTIFACT_KEYS), controllerRun);
  validateArchiveSource(
    exactObject(observation.archive_source, ARCHIVE_SOURCE_KEYS),
    requireTimestamp(observation, "broker_accepted_at"),
  );
  validateTargetLineage(
    observation.target_lineage,
    targetLineageAuthority(activation),
    requireString(runtime, "peeled_commit_sha", 40, SHA1),
    requireTimestamp(observation, "broker_accepted_at"),
  );
  const services = exactObject(observation.services, [
    "controller_run_reader",
    "governance_reader",
  ]);
  validateService(serviceObject(services, "controller_run_reader"));
  validateService(serviceObject(services, "governance_reader"));
  return observation;
}

function validateActivation(value: JsonObject): void {
  for (const key of [
    "activated_record_id",
    "activated_record_sha256",
    "controller_action_bundle_sha256",
    "provisioned_record_id",
    "provisioned_record_sha256",
    "target_branch_ruleset_evidence_sha256",
    "target_branch_ruleset_projection_sha256",
    "target_policy_sha256",
    "target_runtime_workflow_sha256",
  ]) {
    requireString(value, key, 71, DIGEST);
  }
  requireString(value, "target_policy_blob_sha", 40, SHA1);
  requireString(value, "target_policy_commit_sha", 40, SHA1);
  requireString(value, "target_branch_ruleset_id", 32, /^[1-9][0-9]{0,31}$/u);
  requireLiteral(value, "target_default_branch_ref", TRUST.targetDefaultBranchRef);
  requireString(value, "target_runtime_workflow_blob_sha", 40, SHA1);
  requireString(value, "controller_action_commit_sha", 40, SHA1);
  requireString(value, "controller_action_metadata_blob_sha", 40, SHA1);
  requireString(value, "worker_version_id", 128, VERSION);
  requireInteger(value, "closed_projector_app_id", 1, Number.MAX_SAFE_INTEGER);
  requireInteger(value, "closed_projector_installation_id", 1, Number.MAX_SAFE_INTEGER);
  requireString(value, "closed_projector_app_slug", 128, SAFE_NAME);
}

function validateLedger(value: JsonObject): void {
  requireLiteral(value, "phase", "TERMINAL");
  requireLiteral(value, "head_receipt_type", "LEASE_RELEASED");
  for (const key of [
    "closed_check_verified_receipt_id",
    "closed_check_verified_receipt_sha256",
    "head_receipt_id",
    "head_receipt_sha256",
    "release_identity_id",
  ]) {
    requireString(value, key, 71, DIGEST);
  }
  const closedSequence = requireInteger(
    value,
    "closed_check_verified_sequence",
    0,
    Number.MAX_SAFE_INTEGER - 1,
  );
  assert(
    requireInteger(value, "head_sequence", 1, Number.MAX_SAFE_INTEGER) === closedSequence + 1,
    "RUNTIME_CLOSURE_OBSERVATION_INVALID",
    503,
  );
}

function validateRuntime(value: JsonObject): void {
  requireString(value, "actor_id", 32, /^[1-9][0-9]{0,31}$/u);
  requireLiteral(value, "repository", TRUST.targetRepository);
  requireExactInteger(value, "repository_id", TRUST.targetRepositoryId);
  requireLiteral(value, "environment", "ghcr");
  requireLiteral(value, "event", "push");
  const tag = requireString(value, "tag", 64, TAG);
  requireLiteral(value, "tag_ref", `refs/tags/${tag}`);
  const tagObjectSha = requireString(value, "tag_object_sha", 40, SHA1);
  const peeled = requireString(value, "peeled_commit_sha", 40, SHA1);
  assert(tagObjectSha !== peeled, "RUNTIME_CLOSURE_OBSERVATION_INVALID", 503);
  requireLiteral(value, "workflow_path", TRUST.runtimeWorkflowPath);
  requireLiteral(
    value,
    "workflow_ref",
    `${TRUST.targetRepository}/${TRUST.runtimeWorkflowPath}@refs/tags/${tag}`,
  );
  requireLiteral(value, "workflow_sha", peeled);
  requireString(value, "policy_blob_sha", 40, SHA1);
  requireString(value, "policy_sha256", 71, DIGEST);
  requireString(value, "policy_source_commit_sha", 40, SHA1);
  requireString(value, "workflow_blob_sha", 40, SHA1);
  requireString(value, "workflow_sha256", 71, DIGEST);
  requireString(value, "workflow_source_commit_sha", 40, SHA1);
  requireInteger(value, "run_id", 1, Number.MAX_SAFE_INTEGER);
  requireInteger(value, "run_attempt", 1, 1000);
  requireLiteral(value, "run_status", "in_progress");
  requireInteger(value, "check_run_id", 1, Number.MAX_SAFE_INTEGER);
  requireLiteral(value, "check_name", "Promote certified runtime image aliases");
  requireLiteral(value, "check_status", "in_progress");
  requireExactInteger(value, "check_app_id", 15_368);
  requireLiteral(value, "check_app_slug", "github-actions");
  requireLiteral(value, "head_branch", tag);
  requireString(value, "provider_response_sha256", 71, DIGEST);
}

function validateClosedCheck(value: JsonObject): void {
  requireInteger(value, "app_id", 1, Number.MAX_SAFE_INTEGER);
  requireString(value, "app_slug", 128, SAFE_NAME);
  requireInteger(value, "check_run_id", 1, Number.MAX_SAFE_INTEGER);
  requireLiteral(value, "name", "Release controller CLOSED");
  requireString(value, "external_id", 512);
  requireString(value, "head_sha", 40, SHA1);
  requireLiteral(value, "status", "completed");
  requireLiteral(value, "conclusion", "success");
  requireTimestamp(value, "started_at");
  const completedAt = requireTimestamp(value, "completed_at");
  assert(
    Date.parse(completedAt) >= Date.parse(requireString(value, "started_at", 32, TIMESTAMP)),
    "RUNTIME_CLOSURE_OBSERVATION_INVALID",
    503,
  );
  requireLiteral(value, "output_title", "dpone release controller CLOSED / PASS / GO");
  const summary = requireString(value, "output_summary", 8192);
  assert(
    summary.startsWith("DPONE_RELEASE_CONTROLLER_CLOSED_V1 ") && !summary.includes("\n"),
    "RUNTIME_CLOSURE_OBSERVATION_INVALID",
    503,
  );
  requireString(value, "output_marker_sha256", 71, DIGEST);
  requireString(value, "provider_response_sha256", 71, DIGEST);
}

function validateControllerRun(value: JsonObject): void {
  requireLiteral(value, "repository", TRUST.controllerRepository);
  requireExactInteger(value, "repository_id", TRUST.controllerRepositoryId);
  requireInteger(value, "run_id", 1, Number.MAX_SAFE_INTEGER);
  requireInteger(value, "run_attempt", 1, 1000);
  requireInteger(value, "workflow_id", 1, Number.MAX_SAFE_INTEGER);
  requireLiteral(value, "workflow_path", TRUST.controllerWorkflowPath);
  requireString(value, "workflow_sha", 40, SHA1);
  requireLiteral(value, "event", "workflow_dispatch");
  requireLiteral(value, "status", "completed");
  requireLiteral(value, "conclusion", "success");
  requireString(value, "head_branch", 128, SAFE_NAME);
  requireString(value, "head_sha", 40, SHA1);
  requireString(value, "provider_response_sha256", 71, DIGEST);
}

function validateArtifact(value: JsonObject, controllerRun: JsonObject): void {
  const runId = requireInteger(value, "workflow_run_id", 1, Number.MAX_SAFE_INTEGER);
  assert(
    runId === requireInteger(controllerRun, "run_id", 1, Number.MAX_SAFE_INTEGER),
    "RUNTIME_CLOSURE_OBSERVATION_INVALID",
    503,
  );
  requireLiteral(
    value,
    "workflow_run_head_sha",
    requireString(controllerRun, "head_sha", 40, SHA1),
  );
  requireInteger(value, "id", 1, Number.MAX_SAFE_INTEGER);
  const attempt = requireInteger(controllerRun, "run_attempt", 1, 1000);
  requireLiteral(value, "name", `release-controller-closure-${runId}-${attempt}`);
  requireString(value, "digest", 71, DIGEST);
  requireInteger(value, "size_bytes", 1, RUNTIME_CLOSURE_MAX_RAW_BYTES);
  const createdAt = requireTimestamp(value, "created_at");
  const expiresAt = requireTimestamp(value, "expires_at");
  assert(Date.parse(createdAt) < Date.parse(expiresAt), "RUNTIME_CLOSURE_OBSERVATION_INVALID", 503);
  assert(!requireBoolean(value, "expired"), "RUNTIME_CLOSURE_OBSERVATION_INVALID", 503);
  requireString(value, "provider_response_sha256", 71, DIGEST);
}

function validateArchiveSource(value: JsonObject, brokerAcceptedAt: string): void {
  const expiresAt = requireTimestamp(value, "expires_at");
  const validityMs = Date.parse(expiresAt) - Date.parse(brokerAcceptedAt);
  assert(validityMs >= 0 && validityMs <= 60_000, "RUNTIME_CLOSURE_OBSERVATION_INVALID", 503);
  requireString(value, "url_sha256", 71, DIGEST);
  assert(!requireBoolean(value, "raw_url_retained"), "RUNTIME_CLOSURE_OBSERVATION_INVALID", 503);
}
