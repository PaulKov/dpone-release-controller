import { canonicalBytes, sha256Hex } from "../src/canonical";
import type { JsonObject, PrivateServicePin } from "../src/types";

export const DIGEST = (character: string): string => `sha256:${character.repeat(64)}`;
export const SHA = (character: string): string => character.repeat(40);
export const REQUEST_ID = "runtime-closure-request-0001";
export const RELEASE_IDENTITY_ID =
  "sha256:3d52af3a2bc6eb185a48465c8680d988a57f7fecf668313673ded1aaed3a59ab";
const CONTROLLER_VERSION = "00000000-0000-0000-0000-000000000001";
const GOVERNANCE_VERSION = "00000000-0000-0000-0000-000000000002";
const INGRESS_VERSION = "00000000-0000-0000-0000-000000000003";
export const CONTROLLER_PIN: PrivateServicePin = {
  serviceIdentity: `cloudflare-worker:0123456789abcdef0123456789abcdef/dpone-release-controller-run-reader@${CONTROLLER_VERSION}`,
  serviceName: "dpone-release-controller-run-reader",
  versionId: CONTROLLER_VERSION,
};
export const GOVERNANCE_PIN: PrivateServicePin = {
  serviceIdentity: `cloudflare-worker:0123456789abcdef0123456789abcdef/dpone-release-governance-reader@${GOVERNANCE_VERSION}`,
  serviceName: "dpone-release-governance-reader",
  versionId: GOVERNANCE_VERSION,
};

export async function validObservation(
  sizeBytes = 4,
  controllerActionCommit = SHA("d"),
  brokerAcceptedAt = "2026-08-15T12:00:00Z",
  archiveExpiresAt = "2026-08-15T12:00:30Z",
): Promise<JsonObject> {
  const controllerRunId = 123_456_789;
  const controllerRunAttempt = 2;
  const controllerWorkflowId = 316_322_127;
  const peeled = SHA("a");
  const controllerActionMetadataBlob = SHA("e");
  const controllerActionBundle = DIGEST("f");
  const artifactDigest = DIGEST("2");
  const marker: JsonObject = {
    candidate_id: DIGEST("3"),
    closed_receipt_id: DIGEST("4"),
    closed_receipt_sha256: DIGEST("5"),
    closure_manifest_sha256: DIGEST("6"),
    controller_action_bundle_sha256: controllerActionBundle,
    controller_action_commit_sha: controllerActionCommit,
    controller_action_metadata_blob_sha: controllerActionMetadataBlob,
    controller_repository_id: 1_305_993_853,
    controller_run_attempt: controllerRunAttempt,
    controller_run_id: controllerRunId,
    controller_workflow_id: controllerWorkflowId,
    controller_workflow_sha: SHA("b"),
    evidence_artifact_digest: artifactDigest,
    evidence_artifact_id: 9_500_000_001,
    evidence_artifact_member_inventory_sha256: DIGEST("7"),
    evidence_artifact_name: `release-controller-closure-${controllerRunId}-${controllerRunAttempt}`,
    peeled_commit_sha: peeled,
    receipt_chain_sha256: DIGEST("8"),
    release_authority_id: "sha256:1aaff56fda58ad91d139f5f2c76dd3efc9a3f69f94b74ee7d944cb3aa3da6e95",
    release_evidence_sha256: DIGEST("a"),
    release_identity_id: RELEASE_IDENTITY_ID,
    schema: "dpone.release-controller-closed-check.v1",
    schema_version: 1,
    tag: "v0.74.0",
    tag_object_sha: SHA("c"),
    target_repository_id: 1_255_975_556,
  };
  const markerBytes = canonicalBytes(marker);
  const outputSummary = `DPONE_RELEASE_CONTROLLER_CLOSED_V1 ${base64url(markerBytes)}`;
  const runtime: JsonObject = {
    actor_id: "74862786",
    check_app_id: 15_368,
    check_app_slug: "github-actions",
    check_name: "Promote certified runtime image aliases",
    check_run_id: 14_000_001,
    check_status: "in_progress",
    environment: "ghcr",
    event: "push",
    head_branch: "v0.74.0",
    peeled_commit_sha: peeled,
    policy_blob_sha: SHA("d"),
    policy_sha256: DIGEST("5"),
    policy_source_commit_sha: peeled,
    provider_response_sha256: DIGEST("b"),
    repository: "PaulKov/dpone",
    repository_id: 1_255_975_556,
    run_attempt: 1,
    run_id: 15_000_001,
    run_status: "in_progress",
    tag: "v0.74.0",
    tag_object_sha: SHA("c"),
    tag_ref: "refs/tags/v0.74.0",
    workflow_path: ".github/workflows/runtime-image.yml",
    workflow_ref: "PaulKov/dpone/.github/workflows/runtime-image.yml@refs/tags/v0.74.0",
    workflow_blob_sha: SHA("e"),
    workflow_sha: peeled,
    workflow_sha256: DIGEST("0"),
    workflow_source_commit_sha: peeled,
  };
  const closedCheck: JsonObject = {
    app_id: 4_341_356,
    app_slug: "dpone-release-closed-projector",
    check_run_id: 13_000_001,
    completed_at: "2026-08-15T12:01:00Z",
    conclusion: "success",
    external_id:
      `dpone-release-controller.closed.v1|${RELEASE_IDENTITY_ID}|` +
      `${controllerRunId}|${controllerRunAttempt}`,
    head_sha: peeled,
    name: "Release controller CLOSED",
    output_marker_sha256: `sha256:${await sha256Hex(markerBytes)}`,
    output_summary: outputSummary,
    output_title: "dpone release controller CLOSED / PASS / GO",
    provider_response_sha256: DIGEST("c"),
    started_at: "2026-08-15T12:00:00Z",
    status: "completed",
  };
  const controllerRun: JsonObject = {
    conclusion: "success",
    event: "workflow_dispatch",
    head_branch: "controller-v2.0.0",
    head_sha: SHA("b"),
    provider_response_sha256: DIGEST("d"),
    repository: "PaulKov/dpone-release-controller",
    repository_id: 1_305_993_853,
    run_attempt: controllerRunAttempt,
    run_id: controllerRunId,
    status: "completed",
    workflow_id: controllerWorkflowId,
    workflow_path: ".github/workflows/release-controller.yml",
    workflow_sha: SHA("b"),
  };
  const closureArtifact: JsonObject = {
    created_at: "2026-08-15T12:00:00Z",
    digest: artifactDigest,
    expired: false,
    expires_at: "2026-11-13T12:00:00Z",
    id: 9_500_000_001,
    name: `release-controller-closure-${controllerRunId}-${controllerRunAttempt}`,
    provider_response_sha256: DIGEST("e"),
    size_bytes: sizeBytes,
    workflow_run_head_sha: SHA("b"),
    workflow_run_id: controllerRunId,
  };
  const archiveSource: JsonObject = {
    expires_at: archiveExpiresAt,
    raw_url_retained: false,
    url_sha256: DIGEST("f"),
  };
  const targetLineage: JsonObject = {
    baseline_ahead_by: 5,
    baseline_behind_by: 0,
    baseline_commit_sha: SHA("9"),
    baseline_compare_path: `/repos/PaulKov/dpone/compare/${SHA("9")}...${peeled}`,
    baseline_compare_provider_response_sha256: DIGEST("1"),
    baseline_merge_base_commit_sha: SHA("9"),
    baseline_status: "ahead",
    baseline_total_commits: 5,
    branch_ruleset_evidence_sha256: DIGEST("2"),
    branch_ruleset_id: "987654321",
    branch_ruleset_projection_sha256: DIGEST("7"),
    branch_ruleset_provider_response_sha256: DIGEST("6"),
    default_branch_head_sha: SHA("f"),
    default_branch_provider_response_sha256: DIGEST("3"),
    default_branch_ref: "refs/heads/master",
    observed_at: brokerAcceptedAt,
    release_ahead_by: 2,
    release_behind_by: 0,
    release_commit_sha: peeled,
    release_compare_path: `/repos/PaulKov/dpone/compare/${peeled}...${SHA("f")}`,
    release_compare_provider_response_sha256: DIGEST("4"),
    release_merge_base_commit_sha: peeled,
    release_status: "ahead",
    release_total_commits: 2,
  };
  return {
    activation: {
      activated_record_id: DIGEST("1"),
      activated_record_sha256: DIGEST("2"),
      closed_projector_app_id: 4_341_356,
      closed_projector_app_slug: "dpone-release-closed-projector",
      closed_projector_installation_id: 85_000_001,
      controller_action_bundle_sha256: controllerActionBundle,
      controller_action_commit_sha: controllerActionCommit,
      controller_action_metadata_blob_sha: controllerActionMetadataBlob,
      provisioned_record_id: DIGEST("3"),
      provisioned_record_sha256: DIGEST("4"),
      target_branch_ruleset_evidence_sha256: DIGEST("2"),
      target_branch_ruleset_id: "987654321",
      target_branch_ruleset_projection_sha256: DIGEST("7"),
      target_default_branch_ref: "refs/heads/master",
      target_policy_blob_sha: SHA("d"),
      target_policy_commit_sha: SHA("9"),
      target_policy_sha256: DIGEST("5"),
      target_runtime_workflow_blob_sha: SHA("e"),
      target_runtime_workflow_sha256: DIGEST("0"),
      worker_version_id: INGRESS_VERSION,
    },
    archive_source: archiveSource,
    broker_accepted_at: brokerAcceptedAt,
    broker_request_id: REQUEST_ID,
    closed_check: closedCheck,
    closure_artifact: closureArtifact,
    controller_run: controllerRun,
    ledger: {
      closed_check_verified_receipt_id: DIGEST("6"),
      closed_check_verified_receipt_sha256: DIGEST("7"),
      closed_check_verified_sequence: 113,
      head_receipt_id: DIGEST("8"),
      head_receipt_sha256: DIGEST("9"),
      head_receipt_type: "LEASE_RELEASED",
      head_sequence: 114,
      phase: "TERMINAL",
      release_identity_id: RELEASE_IDENTITY_ID,
    },
    provider_api_version: "2026-03-10",
    provider_response_sha256: `sha256:${await sha256Hex(
      canonicalBytes({
        archive_source: archiveSource,
        closed_check: closedCheck,
        closure_artifact: closureArtifact,
        controller_run: controllerRun,
        runtime,
        target_lineage: targetLineage,
      }),
    )}`,
    runtime,
    schema: "dpone.release-runtime-closure-provider-observation.v1",
    schema_version: 1,
    services: {
      controller_run_reader: {
        service_identity: CONTROLLER_PIN.serviceIdentity,
        service_version_id: CONTROLLER_PIN.versionId,
      },
      governance_reader: {
        service_identity: GOVERNANCE_PIN.serviceIdentity,
        service_version_id: GOVERNANCE_PIN.versionId,
      },
    },
    target_lineage: targetLineage,
  };
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
