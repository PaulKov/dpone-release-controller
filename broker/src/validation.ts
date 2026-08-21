import { canonicalJson } from "./canonical";
import { readBoundedBytes } from "./bounded";
import { isGitSha, isSha256, LIMITS, TRUST } from "./config";
import { assert, BrokerError } from "./errors";
import { digestDomain } from "./identity";
import type { AuthenticatedWorkflow, JsonObject, JsonValue, ReleaseBinding } from "./types";

const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;
const TAG = /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;

export async function parseJsonObject(request: Request): Promise<JsonObject> {
  const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  assert(contentType === "application/json", "CONTENT_TYPE_REQUIRED", 415);
  const declaredLength = request.headers.get("content-length");
  let expectedLength: number | null = null;
  if (declaredLength !== null) {
    assert(/^(?:0|[1-9][0-9]{0,9})$/u.test(declaredLength), "CONTENT_LENGTH_INVALID");
    const parsed = Number(declaredLength);
    assert(Number.isSafeInteger(parsed), "CONTENT_LENGTH_INVALID");
    assert(parsed <= LIMITS.bodyBytes, "BODY_TOO_LARGE", 413);
    expectedLength = parsed;
  }
  const bytes = await readBoundedBytes(request, LIMITS.bodyBytes, "BODY_TOO_LARGE");
  assert(expectedLength === null || bytes.byteLength === expectedLength, "CONTENT_LENGTH_MISMATCH");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new BrokerError("BODY_UTF8_INVALID", 400, false);
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(text) as unknown;
  } catch {
    throw new BrokerError("BODY_JSON_INVALID", 400, false);
  }
  assertJsonBudget(decoded);
  const object = requireObject(decoded, "BODY_OBJECT_REQUIRED");
  assert(text === canonicalJson(object), "BODY_NOT_CANONICAL");
  return object;
}

export function requestId(request: Request): string {
  const supplied = request.headers.get("x-request-id");
  if (supplied !== null) {
    assert(REQUEST_ID.test(supplied), "REQUEST_ID_INVALID");
    return supplied;
  }
  return crypto.randomUUID();
}

export function parseReleaseBinding(value: unknown): ReleaseBinding {
  const object = exactObject(value, [
    "attempt_id",
    "candidate_artifact_digest",
    "candidate_artifact_id",
    "candidate_id",
    "candidate_inventory_sha256",
    "candidate_manifest_digest",
    "candidate_run_attempt",
    "candidate_run_id",
    "controller_repo_id",
    "controller_workflow_id",
    "controller_workflow_sha",
    "peeled_commit_sha",
    "policy_sha256",
    "release_authority_id",
    "release_identity_id",
    "run_attempt",
    "run_id",
    "tag",
    "tag_object_sha",
    "tag_ref",
    "target_repo_id",
  ]);
  const tag = requireString(object, "tag", 64, TAG);
  const tagRef = requireString(object, "tag_ref", 80);
  assert(tagRef === `refs/tags/${tag}`, "TAG_REF_MISMATCH");
  const targetRepoId = requireInteger(object, "target_repo_id", 1);
  const controllerRepoId = requireInteger(object, "controller_repo_id", 1);
  const controllerWorkflowId = requireInteger(object, "controller_workflow_id", 1);
  assert(targetRepoId === TRUST.targetRepositoryId, "TARGET_REPOSITORY_MISMATCH", 403);
  assert(controllerRepoId === TRUST.controllerRepositoryId, "CONTROLLER_REPOSITORY_MISMATCH", 403);
  const peeledCommitSha = requireString(object, "peeled_commit_sha", 40);
  const tagObjectSha = requireString(object, "tag_object_sha", 40);
  assert(isGitSha(peeledCommitSha) && isGitSha(tagObjectSha), "GIT_ID_INVALID");
  assert(peeledCommitSha !== tagObjectSha, "TAG_OBJECT_MUST_BE_ANNOTATED");
  const policySha256 = requireString(object, "policy_sha256", 71);
  assert(isSha256(policySha256), "POLICY_DIGEST_INVALID");
  return {
    attemptId: requireTaggedDigest(object, "attempt_id"),
    candidateArtifactDigest: requireTaggedDigest(object, "candidate_artifact_digest"),
    candidateArtifactId: positiveSafeInteger(
      requireString(object, "candidate_artifact_id", 32, /^[1-9][0-9]{0,31}$/u),
      "CANDIDATE_ARTIFACT_ID_INVALID",
    ),
    candidateId: requireTaggedDigest(object, "candidate_id"),
    candidateInventorySha256: requireTaggedDigest(object, "candidate_inventory_sha256"),
    candidateManifestDigest: requireTaggedDigest(object, "candidate_manifest_digest"),
    candidateRunAttempt: requireInteger(object, "candidate_run_attempt", 1, 1000),
    candidateRunId: positiveSafeInteger(
      requireString(object, "candidate_run_id", 32, /^[1-9][0-9]{0,31}$/u),
      "CANDIDATE_RUN_ID_INVALID",
    ),
    controllerRepoId,
    controllerWorkflowId,
    controllerWorkflowSha: requireString(object, "controller_workflow_sha", 40, /^[0-9a-f]{40}$/u),
    peeledCommitSha,
    policySha256,
    releaseAuthorityId: requireTaggedDigest(object, "release_authority_id"),
    releaseIdentityId: requireTaggedDigest(object, "release_identity_id"),
    runAttempt: requireInteger(object, "run_attempt", 1, 1000),
    runId: positiveSafeInteger(
      requireString(object, "run_id", 32, /^[1-9][0-9]{0,31}$/u),
      "RUN_ID_INVALID",
    ),
    tag,
    tagObjectSha,
    tagRef,
    targetRepoId,
  };
}

export async function verifyReleaseBinding(
  binding: ReleaseBinding,
  auth: AuthenticatedWorkflow,
  trustedWorkflow: { readonly id: number; readonly sha: string },
): Promise<void> {
  assert(binding.controllerWorkflowId === trustedWorkflow.id, "CONTROLLER_WORKFLOW_MISMATCH", 403);
  assert(binding.controllerWorkflowSha === trustedWorkflow.sha, "WORKFLOW_SHA_MISMATCH", 403);
  assert(binding.controllerWorkflowSha === auth.workflowSha, "WORKFLOW_SHA_MISMATCH", 403);
  assert(
    binding.runId === positiveSafeInteger(auth.runId, "RUN_ID_INVALID"),
    "RUN_ID_MISMATCH",
    403,
  );
  assert(binding.runAttempt === auth.runAttempt, "RUN_ATTEMPT_MISMATCH", 403);

  const expectedIdentity = await digestDomain("dpone.release.identity.v2", {
    projects: [
      "apache-airflow-providers-dpone",
      "dpone",
      "dpone-airflow-pack",
      "dpone-native-accel",
    ],
    release: binding.tag,
    repository_id: TRUST.targetRepositoryId,
  });
  assert(binding.releaseIdentityId === expectedIdentity, "RELEASE_IDENTITY_ID_MISMATCH", 403);

  const expectedAuthority = await digestDomain("dpone.release.authority.v2", {
    peeled_commit_sha: binding.peeledCommitSha,
    policy_sha256: binding.policySha256,
    protected_base_ref: "refs/heads/master",
    release_identity_id: binding.releaseIdentityId,
    tag_object_sha: binding.tagObjectSha,
  });
  assert(binding.releaseAuthorityId === expectedAuthority, "RELEASE_AUTHORITY_ID_MISMATCH", 403);

  const expectedAttempt = await digestDomain("dpone.release.attempt.v2", {
    controller_repository_id: binding.controllerRepoId,
    controller_run_attempt: binding.runAttempt,
    controller_run_id: binding.runId,
    controller_workflow_id: binding.controllerWorkflowId,
    release_authority_id: binding.releaseAuthorityId,
  });
  assert(binding.attemptId === expectedAttempt, "ATTEMPT_ID_MISMATCH", 403);

  const expectedCandidate = await digestDomain("dpone.release.candidate.v2", {
    candidate_inventory_sha256: binding.candidateInventorySha256,
    release_authority_id: binding.releaseAuthorityId,
  });
  assert(binding.candidateId === expectedCandidate, "CANDIDATE_ID_MISMATCH", 403);
}

function requireTaggedDigest(object: JsonObject, key: string): string {
  const value = requireString(object, key, 71);
  assert(isSha256(value), "DIGEST_INVALID");
  return value;
}

export function exactObject(value: unknown, allowed: readonly string[]): JsonObject {
  assert(new Set(allowed).size === allowed.length, "SCHEMA_FIELD_DECLARATION_DUPLICATE", 500);
  const object = requireObject(value, "OBJECT_REQUIRED");
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(object)) {
    assert(allowedSet.has(key), "UNKNOWN_FIELD");
  }
  for (const key of allowed) {
    assert(Object.hasOwn(object, key), "REQUIRED_FIELD_MISSING");
  }
  return object;
}

export function requireObject(value: unknown, code: string): JsonObject {
  assert(value !== null && typeof value === "object" && !Array.isArray(value), code);
  return value as JsonObject;
}

export function requireString(
  object: JsonObject,
  key: string,
  maxLength: number,
  pattern?: RegExp,
): string {
  const value = object[key];
  assert(
    typeof value === "string" && value.length > 0 && value.length <= maxLength,
    "FIELD_INVALID",
  );
  if (pattern !== undefined) {
    pattern.lastIndex = 0;
    const match = pattern.exec(value);
    assert(match !== null && match[0] === value, "FIELD_INVALID");
  }
  return value;
}

export function requireInteger(
  object: JsonObject,
  key: string,
  minimum: number,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  const value = object[key];
  assert(
    typeof value === "number" &&
      Number.isSafeInteger(value) &&
      value >= minimum &&
      value <= maximum,
    "FIELD_INVALID",
  );
  return value;
}

export function requireBoolean(object: JsonObject, key: string): boolean {
  const value = object[key];
  assert(typeof value === "boolean", "FIELD_INVALID");
  return value;
}

function assertJsonBudget(value: unknown): asserts value is JsonValue {
  const stack: { depth: number; value: unknown }[] = [{ depth: 0, value }];
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined) {
      break;
    }
    nodes += 1;
    assert(nodes <= LIMITS.jsonNodes, "JSON_TOO_COMPLEX", 413);
    assert(current.depth <= LIMITS.jsonDepth, "JSON_TOO_DEEP", 413);
    const item = current.value;
    if (item === null || typeof item === "boolean") {
      continue;
    }
    if (typeof item === "number") {
      assert(Number.isSafeInteger(item), "JSON_NUMBER_INVALID");
      continue;
    }
    if (typeof item === "string") {
      assert(
        new TextEncoder().encode(item).length <= LIMITS.maxStringBytes,
        "JSON_STRING_TOO_LARGE",
        413,
      );
      assert(hasOnlyUnicodeScalars(item), "JSON_STRING_UNICODE_INVALID");
      continue;
    }
    assert(typeof item === "object", "JSON_VALUE_INVALID");
    if (Array.isArray(item)) {
      for (const child of item) {
        stack.push({ depth: current.depth + 1, value: child });
      }
      continue;
    }
    for (const [key, child] of Object.entries(item as Record<string, unknown>)) {
      assert(/^[A-Za-z0-9_-]{1,128}$/u.test(key), "JSON_KEY_INVALID", 413);
      stack.push({ depth: current.depth + 1, value: child });
    }
  }
}

function hasOnlyUnicodeScalars(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const following = value.charCodeAt(index + 1);
      if (!(following >= 0xdc00 && following <= 0xdfff)) {
        return false;
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function positiveSafeInteger(value: string, code: string): number {
  const parsed = Number(value);
  assert(Number.isSafeInteger(parsed) && parsed > 0, code);
  return parsed;
}
