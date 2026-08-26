import {
  CONTROLLER_ACTION_BUNDLE_MAX_MEMBER_BYTES,
  CONTROLLER_ACTION_BUNDLE_MAX_TOTAL_BYTES,
  CONTROLLER_ACTION_BUNDLE_SCHEMA,
  CONTROLLER_ACTION_EXECUTABLE_PATHS,
  RUNTIME_CLOSURE_ACTION_METADATA_PATH,
  SHA1,
} from "./activation-contract";
import { canonicalBytes, sha256Hex } from "./canonical";
import { TRUST } from "./config";
import { assert } from "./errors";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireObject, requireString } from "./validation";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const MEMBER_KEYS = ["git_blob_sha", "mode", "path", "sha256", "size_bytes"] as const;

export interface ControllerActionMemberBytes {
  readonly bytes: Uint8Array;
  readonly path: (typeof CONTROLLER_ACTION_EXECUTABLE_PATHS)[number];
}

export interface ControllerActionMemberObservation {
  readonly git_blob_sha: string;
  readonly mode: "100644";
  readonly path: (typeof CONTROLLER_ACTION_EXECUTABLE_PATHS)[number];
  readonly sha256: string;
  readonly size_bytes: number;
}

/**
 * Parse the schema-owner's closed Commit-A executable inventory.
 *
 * The document deliberately has no self-digest. Its exact canonical UTF-8
 * bytes are the digest domain persisted in A0/A1 and terminal evidence.
 */
export function parseControllerActionBundle(value: unknown, expectedCommitSha: string): JsonObject {
  assert(SHA1.test(expectedCommitSha), "CONTROLLER_ACTION_COMMIT_INVALID");
  const document = exactObject(value, [
    "commit_sha",
    "members",
    "repository",
    "repository_id",
    "schema",
    "schema_version",
  ]);
  requireLiteral(document, "schema", CONTROLLER_ACTION_BUNDLE_SCHEMA);
  requireExactInteger(document, "schema_version", 1);
  requireLiteral(document, "repository", TRUST.controllerRepository);
  requireExactInteger(document, "repository_id", TRUST.controllerRepositoryId);
  requireLiteral(document, "commit_sha", expectedCommitSha);
  const members = document.members;
  assert(
    Array.isArray(members) && members.length === CONTROLLER_ACTION_EXECUTABLE_PATHS.length,
    "CONTROLLER_ACTION_BUNDLE_MEMBER_SET_INVALID",
  );
  let totalBytes = 0;
  for (let index = 0; index < CONTROLLER_ACTION_EXECUTABLE_PATHS.length; index += 1) {
    const member = exactObject(members[index], MEMBER_KEYS);
    const expectedPath = CONTROLLER_ACTION_EXECUTABLE_PATHS[index];
    assert(expectedPath !== undefined, "CONTROLLER_ACTION_BUNDLE_MEMBER_SET_INVALID", 500);
    requireLiteral(member, "path", expectedPath);
    requireLiteral(member, "mode", "100644");
    const sizeBytes = requireInteger(
      member,
      "size_bytes",
      1,
      CONTROLLER_ACTION_BUNDLE_MAX_MEMBER_BYTES,
    );
    totalBytes += sizeBytes;
    requireString(member, "git_blob_sha", 40, SHA1);
    requireString(member, "sha256", 71, DIGEST);
  }
  assert(
    totalBytes <= CONTROLLER_ACTION_BUNDLE_MAX_TOTAL_BYTES,
    "CONTROLLER_ACTION_BUNDLE_TOO_LARGE",
  );
  return document;
}

/** Recompute the sole tagged digest over exact canonical inventory bytes. */
export async function controllerActionBundleSha256(document: JsonObject): Promise<string> {
  const commitSha = requireString(document, "commit_sha", 40, SHA1);
  parseControllerActionBundle(document, commitSha);
  return `sha256:${await sha256Hex(canonicalBytes(document))}`;
}

/**
 * Construct the canonical inventory only from independently downloaded blob
 * bytes. Both the provider Git identity and raw SHA-256 are recomputed here.
 */
export async function buildControllerActionBundle(
  commitSha: string,
  inputs: readonly ControllerActionMemberBytes[],
): Promise<JsonObject> {
  assert(SHA1.test(commitSha), "CONTROLLER_ACTION_COMMIT_INVALID", 503);
  assert(
    inputs.length === CONTROLLER_ACTION_EXECUTABLE_PATHS.length,
    "CONTROLLER_ACTION_BUNDLE_MEMBER_SET_INVALID",
    503,
  );
  const members: ControllerActionMemberObservation[] = [];
  for (let index = 0; index < CONTROLLER_ACTION_EXECUTABLE_PATHS.length; index += 1) {
    const input = inputs[index];
    const expectedPath = CONTROLLER_ACTION_EXECUTABLE_PATHS[index];
    assert(
      input !== undefined && input.path === expectedPath,
      "CONTROLLER_ACTION_BUNDLE_MEMBER_SET_INVALID",
      503,
    );
    assert(
      input.bytes.byteLength >= 1 &&
        input.bytes.byteLength <= CONTROLLER_ACTION_BUNDLE_MAX_MEMBER_BYTES,
      "CONTROLLER_ACTION_BUNDLE_MEMBER_SIZE_INVALID",
      503,
    );
    members.push(await observeControllerActionMember(input.path, input.bytes));
  }
  return assembleControllerActionBundle(commitSha, members);
}

/** Recompute one member without retaining any provider URL or source text. */
export async function observeControllerActionMember(
  path: (typeof CONTROLLER_ACTION_EXECUTABLE_PATHS)[number],
  bytes: Uint8Array,
): Promise<ControllerActionMemberObservation> {
  assert(
    CONTROLLER_ACTION_EXECUTABLE_PATHS.includes(path),
    "CONTROLLER_ACTION_BUNDLE_MEMBER_SET_INVALID",
    503,
  );
  assert(
    bytes.byteLength >= 1 && bytes.byteLength <= CONTROLLER_ACTION_BUNDLE_MAX_MEMBER_BYTES,
    "CONTROLLER_ACTION_BUNDLE_MEMBER_SIZE_INVALID",
    503,
  );
  return {
    git_blob_sha: await gitBlobSha(bytes),
    mode: "100644",
    path,
    sha256: `sha256:${await sha256Hex(bytes)}`,
    size_bytes: bytes.byteLength,
  };
}

/** Assemble only the exact six already byte-verified member observations. */
export function assembleControllerActionBundle(
  commitSha: string,
  members: readonly ControllerActionMemberObservation[],
): JsonObject {
  assert(SHA1.test(commitSha), "CONTROLLER_ACTION_COMMIT_INVALID", 503);
  assert(
    members.length === CONTROLLER_ACTION_EXECUTABLE_PATHS.length,
    "CONTROLLER_ACTION_BUNDLE_MEMBER_SET_INVALID",
    503,
  );
  const document: JsonObject = {
    commit_sha: commitSha,
    members: members.map((member) => ({ ...member })),
    repository: TRUST.controllerRepository,
    repository_id: TRUST.controllerRepositoryId,
    schema: CONTROLLER_ACTION_BUNDLE_SCHEMA,
    schema_version: 1,
  };
  return parseControllerActionBundle(document, commitSha);
}

export function runtimeClosureMetadataBlobSha(document: JsonObject): string {
  const commitSha = requireString(document, "commit_sha", 40, SHA1);
  const parsed = parseControllerActionBundle(document, commitSha);
  const members = parsed.members;
  assert(Array.isArray(members), "CONTROLLER_ACTION_BUNDLE_MEMBER_SET_INVALID", 500);
  const index = CONTROLLER_ACTION_EXECUTABLE_PATHS.indexOf(RUNTIME_CLOSURE_ACTION_METADATA_PATH);
  const member = requireObject(members[index], "CONTROLLER_ACTION_BUNDLE_MEMBER_SET_INVALID");
  return requireString(member, "git_blob_sha", 40, SHA1);
}

async function gitBlobSha(bytes: Uint8Array): Promise<string> {
  const header = new TextEncoder().encode(`blob ${bytes.byteLength}\0`);
  const input = new Uint8Array(header.byteLength + bytes.byteLength);
  input.set(header, 0);
  input.set(bytes, header.byteLength);
  const digest = await crypto.subtle.digest("SHA-1", input);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, Math.max(512, expected.length)) === expected,
    "CONTROLLER_ACTION_BUNDLE_LITERAL_MISMATCH",
  );
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "CONTROLLER_ACTION_BUNDLE_INTEGER_MISMATCH",
  );
}
