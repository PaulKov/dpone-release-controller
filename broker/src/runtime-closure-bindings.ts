import { canonicalBytes, canonicalJson, sha256Hex } from "./canonical";
import { TRUST } from "./config";
import { assert, BrokerError } from "./errors";
import { digestDomain } from "./identity";
import {
  ACTIVATION_KEYS,
  ARCHIVE_SOURCE_KEYS,
  ARTIFACT_KEYS,
  CLOSED_CHECK_KEYS,
  CLOSED_MARKER_KEYS,
  CONTROLLER_RUN_KEYS,
  DIGEST,
  LEDGER_KEYS,
  RUNTIME_KEYS,
  SAFE_NAME,
  SHA1,
  TAG,
} from "./runtime-closure-contract";
import {
  decodeBase64url,
  requireExactInteger,
  requireLiteral,
  requireTimestamp,
  targetLineageAuthority,
} from "./runtime-closure-fields";
import { validateRuntimeClosureObservation } from "./runtime-closure-validation";
import { validateTargetLineage } from "./target-lineage";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

/** Cross-bind provider projections and the canonical CLOSED check marker. */
export async function verifyRuntimeClosureObservationBindings(
  observation: JsonObject,
): Promise<void> {
  validateRuntimeClosureObservation(observation);
  const activation = exactObject(observation.activation, ACTIVATION_KEYS);
  const ledger = exactObject(observation.ledger, LEDGER_KEYS);
  const runtime = exactObject(observation.runtime, RUNTIME_KEYS);
  const closedCheck = exactObject(observation.closed_check, CLOSED_CHECK_KEYS);
  const controllerRun = exactObject(observation.controller_run, CONTROLLER_RUN_KEYS);
  const artifact = exactObject(observation.closure_artifact, ARTIFACT_KEYS);
  const archiveSource = exactObject(observation.archive_source, ARCHIVE_SOURCE_KEYS);
  const targetLineage = validateTargetLineage(
    observation.target_lineage,
    targetLineageAuthority(activation),
    requireString(runtime, "peeled_commit_sha", 40, SHA1),
    requireTimestamp(observation, "broker_accepted_at"),
  );
  const marker = decodeClosedMarker(requireString(closedCheck, "output_summary", 8192));
  const tag = requireString(runtime, "tag", 64, TAG);
  const tagObjectSha = requireString(runtime, "tag_object_sha", 40, SHA1);
  const peeledCommitSha = requireString(runtime, "peeled_commit_sha", 40, SHA1);
  const controllerActionCommitSha = requireString(
    activation,
    "controller_action_commit_sha",
    40,
    SHA1,
  );
  const releaseIdentityId = await digestDomain("dpone.release.identity.v2", {
    projects: [
      "apache-airflow-providers-dpone",
      "dpone",
      "dpone-airflow-pack",
      "dpone-native-accel",
    ],
    release: tag,
    repository_id: TRUST.targetRepositoryId,
  });
  requireLiteral(ledger, "release_identity_id", releaseIdentityId);
  requireLiteral(runtime, "policy_source_commit_sha", peeledCommitSha);
  requireLiteral(runtime, "workflow_source_commit_sha", peeledCommitSha);
  requireLiteral(
    runtime,
    "policy_blob_sha",
    requireString(activation, "target_policy_blob_sha", 40, SHA1),
  );
  requireLiteral(
    runtime,
    "policy_sha256",
    requireString(activation, "target_policy_sha256", 71, DIGEST),
  );
  requireLiteral(
    runtime,
    "workflow_blob_sha",
    requireString(activation, "target_runtime_workflow_blob_sha", 40, SHA1),
  );
  requireLiteral(
    runtime,
    "workflow_sha256",
    requireString(activation, "target_runtime_workflow_sha256", 71, DIGEST),
  );
  const releaseAuthorityId = await digestDomain("dpone.release.authority.v2", {
    peeled_commit_sha: peeledCommitSha,
    policy_sha256: requireString(activation, "target_policy_sha256", 71, DIGEST),
    protected_base_ref: TRUST.controllerDefaultBranchRef,
    release_identity_id: releaseIdentityId,
    tag_object_sha: tagObjectSha,
  });
  const markerDigest = `sha256:${await sha256Hex(canonicalBytes(marker))}`;
  requireLiteral(closedCheck, "output_marker_sha256", markerDigest);
  requireLiteral(marker, "release_identity_id", releaseIdentityId);
  requireLiteral(marker, "release_authority_id", releaseAuthorityId);
  requireLiteral(marker, "controller_action_commit_sha", controllerActionCommitSha);
  requireLiteral(
    marker,
    "controller_action_metadata_blob_sha",
    requireString(activation, "controller_action_metadata_blob_sha", 40, SHA1),
  );
  requireLiteral(
    marker,
    "controller_action_bundle_sha256",
    requireString(activation, "controller_action_bundle_sha256", 71, DIGEST),
  );
  requireExactInteger(marker, "target_repository_id", TRUST.targetRepositoryId);
  requireLiteral(marker, "tag", tag);
  requireLiteral(marker, "tag_object_sha", tagObjectSha);
  requireLiteral(marker, "peeled_commit_sha", peeledCommitSha);
  requireLiteral(closedCheck, "head_sha", peeledCommitSha);
  requireExactInteger(
    closedCheck,
    "app_id",
    requireInteger(activation, "closed_projector_app_id", 1, Number.MAX_SAFE_INTEGER),
  );
  requireLiteral(
    closedCheck,
    "app_slug",
    requireString(activation, "closed_projector_app_slug", 128, SAFE_NAME),
  );
  const markerRunId = requireInteger(marker, "controller_run_id", 1, Number.MAX_SAFE_INTEGER);
  const markerRunAttempt = requireInteger(marker, "controller_run_attempt", 1, 1000);
  requireLiteral(
    closedCheck,
    "external_id",
    `dpone-release-controller.closed.v1|${releaseIdentityId}|${markerRunId}|${markerRunAttempt}`,
  );
  requireExactInteger(marker, "controller_repository_id", TRUST.controllerRepositoryId);
  for (const key of ["controller_run_id", "controller_run_attempt", "controller_workflow_id"]) {
    assert(
      requireInteger(marker, key, 1, Number.MAX_SAFE_INTEGER) ===
        requireInteger(controllerRun, key.replace("controller_", ""), 1, Number.MAX_SAFE_INTEGER),
      "RUNTIME_CLOSURE_OBSERVATION_INVALID",
      503,
    );
  }
  requireLiteral(
    marker,
    "controller_workflow_sha",
    requireString(controllerRun, "workflow_sha", 40),
  );
  assert(
    controllerActionCommitSha !== requireString(controllerRun, "workflow_sha", 40, SHA1),
    "RUNTIME_CLOSURE_OBSERVATION_INVALID",
    503,
  );
  requireLiteral(controllerRun, "head_sha", requireString(controllerRun, "workflow_sha", 40, SHA1));
  requireExactInteger(marker, "evidence_artifact_id", requireInteger(artifact, "id", 1));
  requireLiteral(marker, "evidence_artifact_name", requireString(artifact, "name", 256));
  requireLiteral(marker, "evidence_artifact_digest", requireString(artifact, "digest", 71));
  requireExactInteger(
    artifact,
    "workflow_run_id",
    requireInteger(marker, "controller_run_id", 1, Number.MAX_SAFE_INTEGER),
  );
  const aggregate = `sha256:${await sha256Hex(
    canonicalBytes({
      archive_source: archiveSource,
      closed_check: closedCheck,
      closure_artifact: artifact,
      controller_run: controllerRun,
      runtime,
      target_lineage: targetLineage,
    }),
  )}`;
  requireLiteral(observation, "provider_response_sha256", aggregate);
}

function decodeClosedMarker(summary: string): JsonObject {
  const prefix = "DPONE_RELEASE_CONTROLLER_CLOSED_V1 ";
  assert(
    summary.startsWith(prefix) && !summary.includes("\n"),
    "RUNTIME_CLOSURE_OBSERVATION_INVALID",
    503,
  );
  const encoded = summary.slice(prefix.length);
  assert(/^[A-Za-z0-9_-]{1,10923}$/u.test(encoded), "RUNTIME_CLOSURE_OBSERVATION_INVALID", 503);
  const bytes = decodeBase64url(encoded);
  let text: string;
  let decoded: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    decoded = JSON.parse(text);
  } catch {
    throw new BrokerError("RUNTIME_CLOSURE_OBSERVATION_INVALID", 503, false);
  }
  const marker = exactObject(decoded, CLOSED_MARKER_KEYS);
  assert(text === canonicalJson(marker), "RUNTIME_CLOSURE_OBSERVATION_NONCANONICAL", 503);
  requireLiteral(marker, "schema", "dpone.release-controller-closed-check.v1");
  requireExactInteger(marker, "schema_version", 1);
  requireExactInteger(marker, "target_repository_id", TRUST.targetRepositoryId);
  requireExactInteger(marker, "controller_repository_id", TRUST.controllerRepositoryId);
  requireString(marker, "tag", 64, TAG);
  const tagObject = requireString(marker, "tag_object_sha", 40, SHA1);
  const peeled = requireString(marker, "peeled_commit_sha", 40, SHA1);
  assert(tagObject !== peeled, "RUNTIME_CLOSURE_OBSERVATION_INVALID", 503);
  for (const key of [
    "candidate_id",
    "closed_receipt_id",
    "closed_receipt_sha256",
    "closure_manifest_sha256",
    "evidence_artifact_digest",
    "evidence_artifact_member_inventory_sha256",
    "receipt_chain_sha256",
    "release_authority_id",
    "release_evidence_sha256",
    "release_identity_id",
  ]) {
    requireString(marker, key, 71, DIGEST);
  }
  for (const key of [
    "controller_run_attempt",
    "controller_run_id",
    "controller_workflow_id",
    "evidence_artifact_id",
  ]) {
    requireInteger(marker, key, 1, Number.MAX_SAFE_INTEGER);
  }
  requireString(marker, "controller_workflow_sha", 40, SHA1);
  const runId = requireInteger(marker, "controller_run_id", 1, Number.MAX_SAFE_INTEGER);
  const attempt = requireInteger(marker, "controller_run_attempt", 1, 1000);
  requireLiteral(
    marker,
    "evidence_artifact_name",
    `release-controller-closure-${runId}-${attempt}`,
  );
  return marker;
}
