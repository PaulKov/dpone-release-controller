import { canonicalJson, sha256Hex } from "../canonical";
import { TRUST } from "../config";
import { BrokerError } from "../errors";
import type { JsonObject } from "../types";
import {
  providerArray,
  providerInteger,
  providerObject,
  providerString,
  requireProviderLiteral,
} from "./github-provider";

export const CANDIDATE_API_REPOSITORY = `/repos/${TRUST.targetRepository}` as const;
export const CANDIDATE_ARTIFACT_NAME = "release-candidates";
export const CANDIDATE_WORKFLOW_PATH = ".github/workflows/release.yml";
export const CANDIDATE_POLICY_PATH = ".agents/policy/github-branch-protection.yml";
export const MAX_RAW_CANDIDATE_BYTES = 805_306_368;
export const CANDIDATE_STREAM_PIPE_POLICY = Object.freeze({
  idleTimeoutMs: 30_000,
  maximumChunks: 100_000,
  totalTimeoutMs: 900_000,
});

const API_ORIGIN = "https://api.github.com";
const MAX_POLICY_BYTES = 131_072;
const SHA1 = /^[0-9a-f]{40}$/u;
const TAG = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;

export interface CandidateReaderConfig {
  readonly workerVersionId: string;
}

export interface CandidateProviderInput {
  readonly artifactDigest: string;
  readonly artifactId: number;
  readonly peeledCommitSha: string;
  readonly release: string;
  readonly requestId: string;
  readonly runAttempt: number;
  readonly runId: number;
}

/** Authority resolved from the append-only activated A1 record, not the caller. */
export interface CandidateActivatedAuthority {
  readonly policyBlobSha: string;
  readonly policySha256: string;
}

export function validateCandidateInput(input: CandidateProviderInput): void {
  if (
    !TAG.test(input.release) ||
    !SHA1.test(input.peeledCommitSha) ||
    !DIGEST.test(input.artifactDigest) ||
    !Number.isSafeInteger(input.runId) ||
    input.runId <= 0 ||
    !Number.isSafeInteger(input.runAttempt) ||
    input.runAttempt <= 0 ||
    !Number.isSafeInteger(input.artifactId) ||
    input.artifactId <= 0 ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u.test(input.requestId)
  ) {
    throw new BrokerError("CANDIDATE_BINDING_INVALID", 400, false);
  }
}

export function validateCandidateConfig(config: CandidateReaderConfig): void {
  if (!SAFE_NAME.test(config.workerVersionId)) {
    throw new BrokerError("CANDIDATE_READER_CONFIGURATION_INVALID", 503, false);
  }
}

export function validateCandidateAuthority(authority: CandidateActivatedAuthority): void {
  if (!SHA1.test(authority.policyBlobSha) || !DIGEST.test(authority.policySha256)) {
    throw new BrokerError("CANDIDATE_ACTIVATION_AUTHORITY_INVALID", 503, false);
  }
}

export function verifyCandidateRun(run: JsonObject, input: CandidateProviderInput): JsonObject {
  requireProviderInteger(run, "id", input.runId, "CANDIDATE_RUN_INVALID");
  requireProviderInteger(run, "run_attempt", input.runAttempt, "CANDIDATE_RUN_INVALID");
  requireProviderLiteral(run, "path", CANDIDATE_WORKFLOW_PATH, "CANDIDATE_RUN_INVALID");
  requireProviderLiteral(run, "event", "push", "CANDIDATE_RUN_INVALID");
  requireProviderLiteral(run, "head_branch", input.release, "CANDIDATE_RUN_INVALID");
  requireProviderLiteral(run, "head_sha", input.peeledCommitSha, "CANDIDATE_RUN_INVALID");
  requireProviderLiteral(run, "status", "completed", "CANDIDATE_RUN_INVALID");
  requireProviderLiteral(run, "conclusion", "success", "CANDIDATE_RUN_INVALID");
  for (const field of ["repository", "head_repository"] as const) {
    const repository = providerObject(run[field], "CANDIDATE_RUN_INVALID");
    requireProviderInteger(repository, "id", TRUST.targetRepositoryId, "CANDIDATE_RUN_INVALID");
  }
  return {
    conclusion: "success",
    event: "push",
    head_branch: input.release,
    head_sha: input.peeledCommitSha,
    id: input.runId,
    path: CANDIDATE_WORKFLOW_PATH,
    repository_id: TRUST.targetRepositoryId,
    run_attempt: input.runAttempt,
    status: "completed",
  };
}

export function verifyCandidateArtifact(
  artifact: JsonObject,
  input: CandidateProviderInput,
  nowMs: number,
): JsonObject {
  requireProviderInteger(artifact, "id", input.artifactId, "CANDIDATE_ARTIFACT_INVALID");
  requireProviderLiteral(artifact, "name", CANDIDATE_ARTIFACT_NAME, "CANDIDATE_ARTIFACT_INVALID");
  requireProviderLiteral(artifact, "expired", false, "CANDIDATE_ARTIFACT_INVALID");
  requireProviderLiteral(artifact, "digest", input.artifactDigest, "CANDIDATE_ARTIFACT_INVALID");
  const size = providerInteger(artifact, "size_in_bytes", "CANDIDATE_ARTIFACT_INVALID");
  if (size > MAX_RAW_CANDIDATE_BYTES) {
    throw new BrokerError("CANDIDATE_ARTIFACT_SIZE_INVALID", 503, false);
  }
  requireProviderLiteral(
    artifact,
    "url",
    `${API_ORIGIN}${CANDIDATE_API_REPOSITORY}/actions/artifacts/${input.artifactId}`,
    "CANDIDATE_ARTIFACT_INVALID",
  );
  requireProviderLiteral(
    artifact,
    "archive_download_url",
    `${API_ORIGIN}${CANDIDATE_API_REPOSITORY}/actions/artifacts/${input.artifactId}/zip`,
    "CANDIDATE_ARTIFACT_INVALID",
  );
  const workflow = providerObject(artifact.workflow_run, "CANDIDATE_ARTIFACT_INVALID");
  requireProviderInteger(workflow, "id", input.runId, "CANDIDATE_ARTIFACT_INVALID");
  requireProviderInteger(
    workflow,
    "repository_id",
    TRUST.targetRepositoryId,
    "CANDIDATE_ARTIFACT_INVALID",
  );
  requireProviderInteger(
    workflow,
    "head_repository_id",
    TRUST.targetRepositoryId,
    "CANDIDATE_ARTIFACT_INVALID",
  );
  requireProviderLiteral(workflow, "head_branch", input.release, "CANDIDATE_ARTIFACT_INVALID");
  requireProviderLiteral(workflow, "head_sha", input.peeledCommitSha, "CANDIDATE_ARTIFACT_INVALID");
  const createdAt = providerTimestamp(artifact, "created_at", "CANDIDATE_ARTIFACT_INVALID");
  const expiresAt = providerTimestamp(artifact, "expires_at", "CANDIDATE_ARTIFACT_INVALID");
  if (
    Date.parse(createdAt) > nowMs + 30_000 ||
    Date.parse(createdAt) >= Date.parse(expiresAt) ||
    Date.parse(expiresAt) <= nowMs
  ) {
    throw new BrokerError("CANDIDATE_ARTIFACT_EXPIRY_INVALID", 503, false);
  }
  return {
    created_at: createdAt,
    digest: input.artifactDigest,
    expired: false,
    expires_at: expiresAt,
    id: input.artifactId,
    name: CANDIDATE_ARTIFACT_NAME,
    size_in_bytes: size,
    workflow_run: {
      head_branch: input.release,
      head_repository_id: TRUST.targetRepositoryId,
      head_sha: input.peeledCommitSha,
      id: input.runId,
      repository_id: TRUST.targetRepositoryId,
    },
  };
}

export function verifyCandidateArtifactList(
  body: JsonObject,
  input: CandidateProviderInput,
  expected: JsonObject,
  nowMs: number,
): JsonObject {
  const values = providerArray(body, "artifacts", "CANDIDATE_ARTIFACT_LIST_INVALID");
  if (body.total_count !== 1 || values.length !== 1) {
    throw new BrokerError("CANDIDATE_ARTIFACT_SET_AMBIGUOUS", 503, false);
  }
  const projection = verifyCandidateArtifact(
    providerObject(values[0], "CANDIDATE_ARTIFACT_LIST_INVALID"),
    input,
    nowMs,
  );
  if (canonicalJson(projection) !== canonicalJson(expected)) {
    throw new BrokerError("CANDIDATE_ARTIFACT_LIST_MISMATCH", 503, false);
  }
  return { artifact: projection, total_count: 1 };
}

export function verifyCandidateTagReference(
  reference: JsonObject,
  tagRef: string,
  peeledCommitSha: string,
): string {
  requireProviderLiteral(reference, "ref", tagRef, "CANDIDATE_TAG_INVALID");
  const referenceObject = providerObject(reference.object, "CANDIDATE_TAG_INVALID");
  requireProviderLiteral(referenceObject, "type", "tag", "CANDIDATE_TAG_INVALID");
  const tagObjectSha = providerString(referenceObject, "sha", 40, "CANDIDATE_TAG_INVALID");
  if (!SHA1.test(tagObjectSha) || tagObjectSha === peeledCommitSha) {
    throw new BrokerError("CANDIDATE_TAG_INVALID", 503, false);
  }
  return tagObjectSha;
}

export function verifyCandidateAnnotatedTag(
  annotatedTag: JsonObject,
  input: CandidateProviderInput,
  tagRef: string,
  tagObjectSha: string,
): JsonObject {
  requireProviderLiteral(annotatedTag, "sha", tagObjectSha, "CANDIDATE_TAG_INVALID");
  requireProviderLiteral(annotatedTag, "tag", input.release, "CANDIDATE_TAG_INVALID");
  const peeled = providerObject(annotatedTag.object, "CANDIDATE_TAG_INVALID");
  requireProviderLiteral(peeled, "type", "commit", "CANDIDATE_TAG_INVALID");
  requireProviderLiteral(peeled, "sha", input.peeledCommitSha, "CANDIDATE_TAG_INVALID");
  return {
    peeled_commit_sha: input.peeledCommitSha,
    ref: tagRef,
    tag_object_sha: tagObjectSha,
    tag_object_type: "tag",
  };
}

export async function verifyCandidatePolicy(
  contents: JsonObject,
  input: CandidateProviderInput,
  authority: CandidateActivatedAuthority,
): Promise<JsonObject> {
  requireProviderLiteral(contents, "type", "file", "CANDIDATE_POLICY_INVALID");
  requireProviderLiteral(contents, "path", CANDIDATE_POLICY_PATH, "CANDIDATE_POLICY_INVALID");
  requireProviderLiteral(
    contents,
    "name",
    "github-branch-protection.yml",
    "CANDIDATE_POLICY_INVALID",
  );
  requireProviderLiteral(contents, "encoding", "base64", "CANDIDATE_POLICY_INVALID");
  const size = providerInteger(contents, "size", "CANDIDATE_POLICY_INVALID");
  if (size > MAX_POLICY_BYTES) {
    throw new BrokerError("CANDIDATE_POLICY_SIZE_INVALID", 503, false);
  }
  const bytes = decodeProviderBase64(
    providerString(contents, "content", MAX_POLICY_BYTES * 2, "CANDIDATE_POLICY_INVALID"),
  );
  if (bytes.byteLength !== size) {
    throw new BrokerError("CANDIDATE_POLICY_SIZE_INVALID", 503, false);
  }
  const blobSha = providerString(contents, "sha", 40, "CANDIDATE_POLICY_INVALID");
  if (!SHA1.test(blobSha) || (await gitBlobSha1(bytes)) !== blobSha) {
    throw new BrokerError("CANDIDATE_POLICY_BLOB_INVALID", 503, false);
  }
  if (blobSha !== authority.policyBlobSha) {
    throw new BrokerError("CANDIDATE_POLICY_BLOB_MISMATCH", 503, false);
  }
  const digest = `sha256:${await sha256Hex(bytes)}`;
  if (digest !== authority.policySha256) {
    throw new BrokerError("CANDIDATE_POLICY_DIGEST_MISMATCH", 503, false);
  }
  return {
    blob_sha: blobSha,
    path: CANDIDATE_POLICY_PATH,
    sha256: digest,
    source_commit_sha: input.peeledCommitSha,
  };
}

function providerTimestamp(object: JsonObject, key: string, code: string): string {
  const value = providerString(object, key, 32, code);
  if (!TIMESTAMP.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new BrokerError(code, 503, false);
  }
  return value;
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

function decodeProviderBase64(value: string): Uint8Array {
  const compact = value.replaceAll("\n", "");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(compact)) {
    throw new BrokerError("CANDIDATE_POLICY_ENCODING_INVALID", 503, false);
  }
  try {
    return Uint8Array.from(atob(compact), (character) => character.charCodeAt(0));
  } catch {
    throw new BrokerError("CANDIDATE_POLICY_ENCODING_INVALID", 503, false);
  }
}

async function gitBlobSha1(bytes: Uint8Array): Promise<string> {
  const prefix = new TextEncoder().encode(`blob ${bytes.byteLength}\0`);
  const preimage = new Uint8Array(prefix.byteLength + bytes.byteLength);
  preimage.set(prefix);
  preimage.set(bytes, prefix.byteLength);
  const digest = await crypto.subtle.digest("SHA-1", preimage.buffer);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
