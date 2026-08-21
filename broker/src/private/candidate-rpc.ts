import { canonicalBytes, canonicalJson, sha256Hex } from "../canonical";
import { TRUST } from "../config";
import { assert, BrokerError } from "../errors";
import type { JsonObject } from "../types";
import { exactObject, requireBoolean, requireInteger, requireString } from "../validation";
import {
  CANDIDATE_ARTIFACT_NAME,
  CANDIDATE_POLICY_PATH,
  CANDIDATE_WORKFLOW_PATH,
  type CandidateActivatedAuthority,
  type CandidateProviderInput,
  validateCandidateAuthority,
  validateCandidateInput,
} from "./candidate-contract";

export const CANDIDATE_RPC_PATH = "/rpc/v1/candidate/archive";
export const CANDIDATE_RPC_REQUEST_SCHEMA = "dpone.candidate-reader-rpc-request.v1";
export const CANDIDATE_OBSERVATION_SCHEMA = "dpone.github-actions-artifact-observation.v1";
export const CANDIDATE_MEDIA_TYPE = "application/vnd.dpone.release-candidate-artifact.v1+zip";
export const CANDIDATE_RESPONSE_SCHEMA = "dpone.release-candidate-stream-response.v1";
export const CANDIDATE_OBSERVATION_HEADER = "x-dpone-provider-observation";
export const CANDIDATE_OBSERVATION_DIGEST_HEADER = "x-dpone-provider-observation-sha256";
export const CANDIDATE_SERVICE_IDENTITY_HEADER = "x-dpone-candidate-reader-service-identity";
export const CANDIDATE_SERVICE_VERSION_HEADER = "x-dpone-candidate-reader-service-version-id";
export const CANDIDATE_RESPONSE_REQUEST_ID_HEADER = "x-dpone-request-id";
export const CANDIDATE_RESPONSE_SCHEMA_HEADER = "x-dpone-response-schema";

const SHA1 = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const TAG = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;

export interface CandidateReaderRpcRequest {
  readonly authority: CandidateActivatedAuthority;
  readonly input: CandidateProviderInput;
}

export function buildCandidateReaderRpcRequest(
  input: CandidateProviderInput,
  authority: CandidateActivatedAuthority,
): JsonObject {
  validateCandidateInput(input);
  validateCandidateAuthority(authority);
  return {
    artifact_digest: input.artifactDigest,
    artifact_id: input.artifactId,
    peeled_commit_sha: input.peeledCommitSha,
    policy_blob_sha: authority.policyBlobSha,
    policy_sha256: authority.policySha256,
    release: input.release,
    request_id: input.requestId,
    run_attempt: input.runAttempt,
    run_id: input.runId,
    schema: CANDIDATE_RPC_REQUEST_SCHEMA,
    schema_version: 1,
  };
}

export function parseCandidateReaderRpcRequest(value: unknown): CandidateReaderRpcRequest {
  const body = exactObject(value, [
    "artifact_digest",
    "artifact_id",
    "peeled_commit_sha",
    "policy_blob_sha",
    "policy_sha256",
    "release",
    "request_id",
    "run_attempt",
    "run_id",
    "schema",
    "schema_version",
  ]);
  requireLiteral(body, "schema", CANDIDATE_RPC_REQUEST_SCHEMA);
  requireExactInteger(body, "schema_version", 1);
  const input: CandidateProviderInput = {
    artifactDigest: requireString(body, "artifact_digest", 71, DIGEST),
    artifactId: requireInteger(body, "artifact_id", 1),
    peeledCommitSha: requireString(body, "peeled_commit_sha", 40, SHA1),
    release: requireString(body, "release", 64, TAG),
    requestId: requireString(body, "request_id", 128, REQUEST_ID),
    runAttempt: requireInteger(body, "run_attempt", 1, 1000),
    runId: requireInteger(body, "run_id", 1),
  };
  const authority = {
    policyBlobSha: requireString(body, "policy_blob_sha", 40, SHA1),
    policySha256: requireString(body, "policy_sha256", 71, DIGEST),
  };
  validateCandidateInput(input);
  validateCandidateAuthority(authority);
  return { authority, input };
}

export interface EncodedCandidateObservation {
  readonly base64url: string;
  readonly digest: string;
  readonly text: string;
}

export async function encodeCandidateObservation(
  observation: JsonObject,
): Promise<EncodedCandidateObservation> {
  const text = canonicalJson(observation);
  const bytes = new TextEncoder().encode(text);
  assert(
    bytes.byteLength > 0 && bytes.byteLength <= 6144,
    "CANDIDATE_OBSERVATION_SIZE_INVALID",
    500,
  );
  return {
    base64url: encodeBase64url(bytes),
    digest: `sha256:${await sha256Hex(bytes)}`,
    text,
  };
}

export async function decodeCandidateObservation(
  encoded: string,
  expectedDigest: string,
  request: CandidateReaderRpcRequest,
  service: {
    readonly identity: string;
    readonly versionId: string;
  },
  nowMs: number,
): Promise<{ readonly observation: JsonObject; readonly sizeBytes: number }> {
  assert(
    /^[A-Za-z0-9_-]{1,8192}$/u.test(encoded) && DIGEST.test(expectedDigest),
    "CANDIDATE_OBSERVATION_HEADER_INVALID",
    503,
  );
  const bytes = decodeBase64url(encoded);
  assert(bytes.byteLength <= 6144, "CANDIDATE_OBSERVATION_HEADER_INVALID", 503);
  assert(
    `sha256:${await sha256Hex(bytes)}` === expectedDigest,
    "CANDIDATE_OBSERVATION_DIGEST_MISMATCH",
    503,
  );
  let text: string;
  let decoded: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    decoded = JSON.parse(text);
  } catch {
    throw new BrokerError("CANDIDATE_OBSERVATION_INVALID", 503, false);
  }
  const observation = exactObject(decoded, [
    "artifact_created_at",
    "artifact_digest",
    "artifact_expired",
    "artifact_expires_at",
    "artifact_id",
    "artifact_name",
    "artifact_size_bytes",
    "broker_request_id",
    "candidate_reader_service_identity",
    "candidate_reader_service_version_id",
    "conclusion",
    "event",
    "head_branch",
    "head_sha",
    "policy_blob_sha",
    "policy_path",
    "policy_sha256",
    "policy_source_commit_sha",
    "provider_api_version",
    "provider_response_sha256",
    "release",
    "repository",
    "repository_id",
    "run_attempt",
    "run_id",
    "run_status",
    "schema",
    "schema_version",
    "source_url_expires_at",
    "source_url_sha256",
    "tag_object_sha",
    "tag_object_type",
    "tag_ref",
    "workflow_path",
  ]);
  assert(text === canonicalJson(observation), "CANDIDATE_OBSERVATION_NONCANONICAL", 503);
  validateObservationProjection(observation, request, service, nowMs);
  return {
    observation,
    sizeBytes: requireInteger(observation, "artifact_size_bytes", 1, 805_306_368),
  };
}

export function canonicalCandidateRpcBytes(request: CandidateReaderRpcRequest): Uint8Array {
  return canonicalBytes(buildCandidateReaderRpcRequest(request.input, request.authority));
}

function validateObservationProjection(
  observation: JsonObject,
  request: CandidateReaderRpcRequest,
  service: {
    readonly identity: string;
    readonly versionId: string;
  },
  nowMs: number,
): void {
  requireLiteral(observation, "schema", CANDIDATE_OBSERVATION_SCHEMA);
  requireExactInteger(observation, "schema_version", 1);
  requireLiteral(observation, "repository", TRUST.targetRepository);
  requireExactInteger(observation, "repository_id", TRUST.targetRepositoryId);
  requireLiteral(observation, "artifact_name", CANDIDATE_ARTIFACT_NAME);
  requireLiteral(observation, "artifact_digest", request.input.artifactDigest);
  requireExactInteger(observation, "artifact_id", request.input.artifactId);
  requireLiteral(observation, "broker_request_id", request.input.requestId);
  requireLiteral(observation, "candidate_reader_service_identity", service.identity);
  requireLiteral(observation, "candidate_reader_service_version_id", service.versionId);
  requireLiteral(observation, "release", request.input.release);
  requireLiteral(observation, "head_branch", request.input.release);
  requireLiteral(observation, "head_sha", request.input.peeledCommitSha);
  requireLiteral(observation, "policy_path", CANDIDATE_POLICY_PATH);
  requireLiteral(observation, "policy_blob_sha", request.authority.policyBlobSha);
  requireLiteral(observation, "policy_sha256", request.authority.policySha256);
  requireLiteral(observation, "policy_source_commit_sha", request.input.peeledCommitSha);
  requireLiteral(observation, "workflow_path", CANDIDATE_WORKFLOW_PATH);
  requireExactInteger(observation, "run_id", request.input.runId);
  requireExactInteger(observation, "run_attempt", request.input.runAttempt);
  requireLiteral(observation, "event", "push");
  requireLiteral(observation, "run_status", "completed");
  requireLiteral(observation, "conclusion", "success");
  requireLiteral(observation, "provider_api_version", "2026-03-10");
  requireLiteral(observation, "tag_ref", `refs/tags/${request.input.release}`);
  requireLiteral(observation, "tag_object_type", "tag");
  assert(!requireBoolean(observation, "artifact_expired"), "CANDIDATE_OBSERVATION_MISMATCH", 503);
  const tagObjectSha = requireString(observation, "tag_object_sha", 40, SHA1);
  assert(tagObjectSha !== request.input.peeledCommitSha, "CANDIDATE_OBSERVATION_MISMATCH", 503);
  for (const key of ["provider_response_sha256", "source_url_sha256"] as const) {
    requireString(observation, key, 71, DIGEST);
  }
  const createdAt = requireTimestamp(observation, "artifact_created_at");
  const artifactExpiresAt = requireTimestamp(observation, "artifact_expires_at");
  const sourceExpiresAt = requireTimestamp(observation, "source_url_expires_at");
  assert(
    Date.parse(createdAt) < Date.parse(artifactExpiresAt) &&
      Date.parse(artifactExpiresAt) > nowMs &&
      Date.parse(sourceExpiresAt) > nowMs &&
      Date.parse(sourceExpiresAt) <= nowMs + 60_000,
    "CANDIDATE_OBSERVATION_EXPIRY_INVALID",
    503,
  );
}

function requireTimestamp(object: JsonObject, key: string): string {
  const value = requireString(object, key, 32, TIMESTAMP);
  assert(Number.isFinite(Date.parse(value)), "CANDIDATE_OBSERVATION_INVALID", 503);
  return value;
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, Math.max(1, expected.length)) === expected,
    "CANDIDATE_OBSERVATION_MISMATCH",
    503,
  );
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "CANDIDATE_OBSERVATION_MISMATCH",
    503,
  );
}

function encodeBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function decodeBase64url(value: string): Uint8Array {
  const padded = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new BrokerError("CANDIDATE_OBSERVATION_HEADER_INVALID", 503, false);
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  assert(encodeBase64url(bytes) === value, "CANDIDATE_OBSERVATION_HEADER_INVALID", 503);
  return bytes;
}
