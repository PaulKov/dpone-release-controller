import type { BoundedPipePolicy } from "./bounded";
import { CLOUDFLARE_UUID } from "./cloudflare-ids";
import type { JsonObject, PrivateServicePin } from "./types";

export const RUNTIME_CLOSURE_PUBLIC_PATH = "/v1/runtime/closure";
export const RUNTIME_CLOSURE_REQUEST_SCHEMA = "dpone.release-runtime-closure-request.v1";
export const RUNTIME_CLOSURE_OBSERVATION_SCHEMA =
  "dpone.release-runtime-closure-provider-observation.v1";
export const RUNTIME_CLOSURE_RESPONSE_SCHEMA = "dpone.release-runtime-closure-stream-response.v1";
export const RUNTIME_CLOSURE_MEDIA_TYPE = "application/vnd.dpone.release-controller-closure.v1+zip";
export const RUNTIME_CLOSURE_MAX_RAW_BYTES = 64 * 1024 * 1024;
export const RUNTIME_CLOSURE_MAX_EXPANDED_BYTES = 20 * 1024 * 1024;
export const RUNTIME_CLOSURE_MAX_MEMBER_BYTES = 16 * 1024 * 1024;
export const RUNTIME_CLOSURE_MEMBER_PATHS = Object.freeze([
  "closed-receipt-v2.json",
  "closure-manifest-v1.json",
  "receipt-chain-v2.json",
  "release-evidence-v2.json",
] as const);
export const RUNTIME_CLOSURE_STREAM_PIPE_POLICY: BoundedPipePolicy = Object.freeze({
  idleTimeoutMs: 30_000,
  maxChunks: 100_000,
  totalTimeoutMs: 900_000,
});

export const RUNTIME_CLOSURE_OBSERVATION_HEADER = "x-dpone-provider-observation";
export const RUNTIME_CLOSURE_OBSERVATION_DIGEST_HEADER = "x-dpone-provider-observation-sha256";
export const RUNTIME_CLOSURE_REQUEST_ID_HEADER = "x-dpone-request-id";
export const RUNTIME_CLOSURE_RESPONSE_SCHEMA_HEADER = "x-dpone-response-schema";
export const RUNTIME_CLOSURE_CONTROLLER_SERVICE_IDENTITY_HEADER =
  "x-dpone-controller-run-reader-service-identity";
export const RUNTIME_CLOSURE_CONTROLLER_SERVICE_VERSION_HEADER =
  "x-dpone-controller-run-reader-service-version-id";
export const RUNTIME_CLOSURE_GOVERNANCE_SERVICE_IDENTITY_HEADER =
  "x-dpone-governance-reader-service-identity";
export const RUNTIME_CLOSURE_GOVERNANCE_SERVICE_VERSION_HEADER =
  "x-dpone-governance-reader-service-version-id";

export const DIGEST = /^sha256:[0-9a-f]{64}$/u;
export const SHA1 = /^[0-9a-f]{40}$/u;
export const TAG = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
export const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;
export const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;
export const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{1,255}$/u;
export const SERVICE_IDENTITY =
  /^cloudflare-worker:[0-9a-f]{32}\/[A-Za-z0-9][A-Za-z0-9._-]{1,127}@[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;
export const VERSION = CLOUDFLARE_UUID;
export const OBSERVATION_MAX_BYTES = 12_288;
export const OBSERVATION_MAX_BASE64URL = 16_384;

export interface RuntimeClosureRequest {
  readonly releaseIdentityId: string;
  readonly requestId: string;
}

export interface RuntimeClosureStream {
  readonly body: ReadableStream<Uint8Array>;
  readonly length: number;
  readonly observation: JsonObject;
  readonly observationBase64url: string;
  readonly observationSha256: string;
}

export interface RuntimeClosureResponsePins {
  readonly controllerRunReader: PrivateServicePin;
  readonly governanceReader: PrivateServicePin;
}

export interface EncodedRuntimeClosureObservation {
  readonly base64url: string;
  readonly digest: string;
  readonly text: string;
}

export const OBSERVATION_KEYS = [
  "activation",
  "archive_source",
  "broker_accepted_at",
  "broker_request_id",
  "closed_check",
  "closure_artifact",
  "controller_run",
  "ledger",
  "provider_api_version",
  "provider_response_sha256",
  "runtime",
  "schema",
  "schema_version",
  "services",
  "target_lineage",
] as const;
export const ACTIVATION_KEYS = [
  "activated_record_id",
  "activated_record_sha256",
  "closed_projector_app_id",
  "closed_projector_app_slug",
  "closed_projector_installation_id",
  "controller_action_bundle_sha256",
  "controller_action_commit_sha",
  "controller_action_metadata_blob_sha",
  "provisioned_record_id",
  "provisioned_record_sha256",
  "target_branch_ruleset_evidence_sha256",
  "target_branch_ruleset_id",
  "target_branch_ruleset_projection_sha256",
  "target_default_branch_ref",
  "target_policy_blob_sha",
  "target_policy_commit_sha",
  "target_policy_sha256",
  "target_runtime_workflow_blob_sha",
  "target_runtime_workflow_sha256",
  "worker_version_id",
] as const;
export const LEDGER_KEYS = [
  "closed_check_verified_receipt_id",
  "closed_check_verified_receipt_sha256",
  "closed_check_verified_sequence",
  "head_receipt_id",
  "head_receipt_sha256",
  "head_receipt_type",
  "head_sequence",
  "phase",
  "release_identity_id",
] as const;
export const RUNTIME_KEYS = [
  "actor_id",
  "check_app_id",
  "check_app_slug",
  "check_name",
  "check_run_id",
  "check_status",
  "environment",
  "event",
  "head_branch",
  "peeled_commit_sha",
  "policy_blob_sha",
  "policy_sha256",
  "policy_source_commit_sha",
  "provider_response_sha256",
  "repository",
  "repository_id",
  "run_attempt",
  "run_id",
  "run_status",
  "tag",
  "tag_object_sha",
  "tag_ref",
  "workflow_path",
  "workflow_ref",
  "workflow_blob_sha",
  "workflow_sha",
  "workflow_sha256",
  "workflow_source_commit_sha",
] as const;
export const CLOSED_CHECK_KEYS = [
  "app_id",
  "app_slug",
  "check_run_id",
  "completed_at",
  "conclusion",
  "external_id",
  "head_sha",
  "name",
  "output_marker_sha256",
  "output_summary",
  "output_title",
  "provider_response_sha256",
  "started_at",
  "status",
] as const;
export const CONTROLLER_RUN_KEYS = [
  "conclusion",
  "event",
  "head_branch",
  "head_sha",
  "provider_response_sha256",
  "repository",
  "repository_id",
  "run_attempt",
  "run_id",
  "status",
  "workflow_id",
  "workflow_path",
  "workflow_sha",
] as const;
export const ARTIFACT_KEYS = [
  "created_at",
  "digest",
  "expired",
  "expires_at",
  "id",
  "name",
  "provider_response_sha256",
  "size_bytes",
  "workflow_run_head_sha",
  "workflow_run_id",
] as const;
export const ARCHIVE_SOURCE_KEYS = ["expires_at", "raw_url_retained", "url_sha256"] as const;
export const SERVICE_KEYS = ["service_identity", "service_version_id"] as const;
export const CLOSED_MARKER_KEYS = [
  "candidate_id",
  "closed_receipt_id",
  "closed_receipt_sha256",
  "closure_manifest_sha256",
  "controller_action_bundle_sha256",
  "controller_action_commit_sha",
  "controller_action_metadata_blob_sha",
  "controller_repository_id",
  "controller_run_attempt",
  "controller_run_id",
  "controller_workflow_id",
  "controller_workflow_sha",
  "evidence_artifact_digest",
  "evidence_artifact_id",
  "evidence_artifact_member_inventory_sha256",
  "evidence_artifact_name",
  "peeled_commit_sha",
  "receipt_chain_sha256",
  "release_authority_id",
  "release_evidence_sha256",
  "release_identity_id",
  "schema",
  "schema_version",
  "tag",
  "tag_object_sha",
  "target_repository_id",
] as const;
