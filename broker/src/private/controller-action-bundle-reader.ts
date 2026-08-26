import {
  CONTROLLER_ACTION_BUNDLE_MAX_MEMBER_BYTES,
  CONTROLLER_ACTION_EXECUTABLE_PATHS,
  POSITIVE_ID,
  SAFE_NAME,
  SHA1,
} from "../activation-contract";
import {
  assembleControllerActionBundle,
  controllerActionBundleSha256,
  observeControllerActionMember,
  type ControllerActionMemberObservation,
} from "../controller-action-bundle";
import { digestObject } from "../canonical";
import { TRUST } from "../config";
import { assert, BrokerError } from "../errors";
import type { JsonObject } from "../types";
import { exactObject, requireInteger, requireString } from "../validation";
import type { InstallationTokenSource } from "./github-app";
import {
  githubJson,
  githubRequest,
  type ProviderFetch,
  providerArray,
  providerInteger,
  providerObject,
  providerString,
  requireGitHubOk,
  requireProviderLiteral,
} from "./github-provider";

export const CONTROLLER_ACTION_BUNDLE_OBSERVATION_REQUEST_SCHEMA =
  "dpone.release-controller-action-bundle-observation-request.v1";
export const CONTROLLER_ACTION_BUNDLE_OBSERVATION_SCHEMA =
  "dpone.release-controller-action-bundle-observation.v1";

const API_REPOSITORY = `/repos/${TRUST.controllerRepository}` as const;
const PROVIDER_JSON_LIMIT = 262_144;
const PROVIDER_BLOB_JSON_LIMIT =
  Math.ceil((CONTROLLER_ACTION_BUNDLE_MAX_MEMBER_BYTES * 4) / 3) + 1_048_576;
const MAX_TREE_ENTRIES = 2_048;
const PROVIDER_API_VERSION = "2026-03-10";

export interface ControllerActionBundleReaderConfig {
  readonly appId: string;
  readonly appSlug: string;
  readonly installationId: string;
  readonly workerVersionId: string;
}

export interface ControllerActionBundleObservationRequest {
  readonly appId: string;
  readonly appSlug: string;
  readonly commitSha: string;
  readonly installationId: string;
  readonly requestId: string;
}

interface TreeWalkMember {
  readonly blobSha: string;
  readonly path: (typeof CONTROLLER_ACTION_EXECUTABLE_PATHS)[number];
}

/**
 * Credential-isolated A0 observer for the complete Commit-A executable set.
 * No caller-supplied member digest is used while fetching or hashing bytes.
 */
export class ControllerActionBundleReader {
  public constructor(
    private readonly config: ControllerActionBundleReaderConfig,
    private readonly tokens: InstallationTokenSource,
    private readonly providerFetch: ProviderFetch = fetch,
  ) {
    validateConfig(config);
  }

  public async observe(input: ControllerActionBundleObservationRequest): Promise<JsonObject> {
    this.assertCredentialBinding(input);
    const authorization = `Bearer ${await this.tokens.installationToken()}`;
    const commit = await this.get(
      authorization,
      `${API_REPOSITORY}/git/commits/${input.commitSha}`,
      "CONTROLLER_ACTION_COMMIT_PROVIDER_INVALID",
    );
    requireProviderLiteral(
      commit,
      "sha",
      input.commitSha,
      "CONTROLLER_ACTION_COMMIT_PROVIDER_INVALID",
    );
    const commitTreeSha = providerString(
      providerObject(commit.tree, "CONTROLLER_ACTION_COMMIT_PROVIDER_INVALID"),
      "sha",
      40,
      "CONTROLLER_ACTION_COMMIT_PROVIDER_INVALID",
    );
    assert(SHA1.test(commitTreeSha), "CONTROLLER_ACTION_COMMIT_PROVIDER_INVALID", 503);

    const walk = await this.walkExecutableBlobs(authorization, commitTreeSha);
    const observedMembers: ControllerActionMemberObservation[] = [];
    for (const member of walk.members) {
      const bytes = await this.readBlob(authorization, member.blobSha);
      const observed = await observeControllerActionMember(member.path, bytes);
      assert(
        observed.git_blob_sha === member.blobSha,
        "CONTROLLER_ACTION_BLOB_IDENTITY_MISMATCH",
        503,
      );
      observedMembers.push(observed);
    }
    const bundle = assembleControllerActionBundle(input.commitSha, observedMembers);
    const body: JsonObject = {
      app_id: this.config.appId,
      app_slug: this.config.appSlug,
      commit_tree_sha: commitTreeSha,
      controller_action_bundle: bundle,
      controller_action_bundle_sha256: await controllerActionBundleSha256(bundle),
      installation_id: this.config.installationId,
      provider_api_version: PROVIDER_API_VERSION,
      provider_tree_walk_sha256: await digestObject({
        commit_sha: input.commitSha,
        commit_tree_sha: commitTreeSha,
        directories: walk.directories,
        members: walk.members.map((member) => ({
          git_blob_sha: member.blobSha,
          mode: "100644",
          path: member.path,
        })),
      }),
      repository: TRUST.controllerRepository,
      repository_id: TRUST.controllerRepositoryId,
      request_id: input.requestId,
      schema: CONTROLLER_ACTION_BUNDLE_OBSERVATION_SCHEMA,
      schema_version: 1,
      worker_version_id: this.config.workerVersionId,
    };
    return { ...body, provider_observation_sha256: await digestObject(body) };
  }

  private assertCredentialBinding(input: ControllerActionBundleObservationRequest): void {
    assert(
      input.appId === this.config.appId &&
        input.appSlug === this.config.appSlug &&
        input.installationId === this.config.installationId,
      "CONTROLLER_ACTION_APP_BINDING_MISMATCH",
      503,
    );
    assert(SHA1.test(input.commitSha), "CONTROLLER_ACTION_COMMIT_INVALID", 400);
  }

  private async walkExecutableBlobs(
    authorization: string,
    commitTreeSha: string,
  ): Promise<{
    readonly directories: JsonObject[];
    readonly members: TreeWalkMember[];
  }> {
    const directories: JsonObject[] = [];
    const root = await this.getTree(authorization, commitTreeSha);
    const actionsTreeSha = treeEntrySha(root, "actions", "040000", "tree");
    directories.push({ path: "actions", tree_sha: actionsTreeSha });
    const actions = await this.getTree(authorization, actionsTreeSha);
    const members: TreeWalkMember[] = [];
    for (const actionName of ["broker-call", "lease-sentinel", "runtime-closure"] as const) {
      const actionTreeSha = treeEntrySha(actions, actionName, "040000", "tree");
      const actionPath = `actions/${actionName}`;
      directories.push({ path: actionPath, tree_sha: actionTreeSha });
      const actionTree = await this.getTree(authorization, actionTreeSha);
      const metadataPath = `${actionPath}/action.yml` as TreeWalkMember["path"];
      members.push({
        blobSha: treeEntrySha(actionTree, "action.yml", "100644", "blob"),
        path: metadataPath,
      });
      const distTreeSha = treeEntrySha(actionTree, "dist", "040000", "tree");
      const distPath = `${actionPath}/dist`;
      directories.push({ path: distPath, tree_sha: distTreeSha });
      const distTree = await this.getTree(authorization, distTreeSha);
      const bundlePath = `${distPath}/index.js` as TreeWalkMember["path"];
      members.push({
        blobSha: treeEntrySha(distTree, "index.js", "100644", "blob"),
        path: bundlePath,
      });
    }
    assert(
      members.every((member, index) => member.path === CONTROLLER_ACTION_EXECUTABLE_PATHS[index]),
      "CONTROLLER_ACTION_BUNDLE_MEMBER_SET_INVALID",
      503,
    );
    return { directories, members };
  }

  private async getTree(authorization: string, treeSha: string): Promise<JsonObject> {
    assert(SHA1.test(treeSha), "CONTROLLER_ACTION_TREE_INVALID", 503);
    const tree = await this.get(
      authorization,
      `${API_REPOSITORY}/git/trees/${treeSha}`,
      "CONTROLLER_ACTION_TREE_INVALID",
    );
    requireProviderLiteral(tree, "sha", treeSha, "CONTROLLER_ACTION_TREE_INVALID");
    requireProviderLiteral(tree, "truncated", false, "CONTROLLER_ACTION_TREE_INVALID");
    const entries = providerArray(tree, "tree", "CONTROLLER_ACTION_TREE_INVALID");
    assert(
      entries.length >= 1 && entries.length <= MAX_TREE_ENTRIES,
      "CONTROLLER_ACTION_TREE_INVALID",
      503,
    );
    return tree;
  }

  private async readBlob(authorization: string, expectedBlobSha: string): Promise<Uint8Array> {
    assert(SHA1.test(expectedBlobSha), "CONTROLLER_ACTION_BLOB_INVALID", 503);
    const blob = await this.get(
      authorization,
      `${API_REPOSITORY}/git/blobs/${expectedBlobSha}`,
      "CONTROLLER_ACTION_BLOB_INVALID",
      PROVIDER_BLOB_JSON_LIMIT,
    );
    requireProviderLiteral(blob, "sha", expectedBlobSha, "CONTROLLER_ACTION_BLOB_INVALID");
    requireProviderLiteral(blob, "encoding", "base64", "CONTROLLER_ACTION_BLOB_INVALID");
    const size = providerInteger(blob, "size", "CONTROLLER_ACTION_BLOB_INVALID");
    assert(
      size <= CONTROLLER_ACTION_BUNDLE_MAX_MEMBER_BYTES,
      "CONTROLLER_ACTION_BLOB_INVALID",
      503,
    );
    const content = providerString(
      blob,
      "content",
      PROVIDER_BLOB_JSON_LIMIT,
      "CONTROLLER_ACTION_BLOB_INVALID",
    );
    return decodeProviderBase64(content, size);
  }

  private async get(
    authorization: string,
    path: `/${string}`,
    code: string,
    maximumBytes = PROVIDER_JSON_LIMIT,
  ): Promise<JsonObject> {
    const response = await githubRequest(this.providerFetch, {
      authorization,
      method: "GET",
      path,
    });
    await requireGitHubOk(response, code);
    return githubJson(response, maximumBytes, code);
  }
}

export function parseControllerActionBundleObservationRequest(
  value: unknown,
): ControllerActionBundleObservationRequest {
  const body = exactObject(value, [
    "app_id",
    "app_slug",
    "controller_action_commit_sha",
    "installation_id",
    "repository_id",
    "request_id",
    "schema",
    "schema_version",
  ]);
  requireLiteral(body, "schema", CONTROLLER_ACTION_BUNDLE_OBSERVATION_REQUEST_SCHEMA);
  requireExactInteger(body, "schema_version", 1);
  requireExactInteger(body, "repository_id", TRUST.controllerRepositoryId);
  return {
    appId: requireString(body, "app_id", 32, POSITIVE_ID),
    appSlug: requireString(body, "app_slug", 128, SAFE_NAME),
    commitSha: requireString(body, "controller_action_commit_sha", 40, SHA1),
    installationId: requireString(body, "installation_id", 32, POSITIVE_ID),
    requestId: requireString(body, "request_id", 128, /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u),
  };
}

function treeEntrySha(
  tree: JsonObject,
  expectedPath: string,
  expectedMode: string,
  expectedType: string,
): string {
  const entries = providerArray(tree, "tree", "CONTROLLER_ACTION_TREE_INVALID");
  const matches = entries
    .map((value) => providerObject(value, "CONTROLLER_ACTION_TREE_INVALID"))
    .filter((entry) => entry.path === expectedPath);
  assert(matches.length === 1, "CONTROLLER_ACTION_TREE_INVALID", 503);
  const entry = matches[0];
  assert(entry !== undefined, "CONTROLLER_ACTION_TREE_INVALID", 503);
  requireProviderLiteral(entry, "mode", expectedMode, "CONTROLLER_ACTION_TREE_INVALID");
  requireProviderLiteral(entry, "type", expectedType, "CONTROLLER_ACTION_TREE_INVALID");
  const sha = providerString(entry, "sha", 40, "CONTROLLER_ACTION_TREE_INVALID");
  assert(SHA1.test(sha), "CONTROLLER_ACTION_TREE_INVALID", 503);
  return sha;
}

function decodeProviderBase64(content: string, expectedBytes: number): Uint8Array {
  const normalized = content.replaceAll("\n", "");
  assert(
    normalized.length >= 4 &&
      normalized.length <= Math.ceil((CONTROLLER_ACTION_BUNDLE_MAX_MEMBER_BYTES * 4) / 3) + 4 &&
      normalized.length % 4 === 0 &&
      /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(normalized),
    "CONTROLLER_ACTION_BLOB_INVALID",
    503,
  );
  let decoded: string;
  try {
    decoded = atob(normalized);
  } catch {
    throw new BrokerError("CONTROLLER_ACTION_BLOB_INVALID", 503, false);
  }
  assert(decoded.length === expectedBytes, "CONTROLLER_ACTION_BLOB_INVALID", 503);
  const bytes = new Uint8Array(decoded.length);
  for (let index = 0; index < decoded.length; index += 1) {
    bytes[index] = decoded.charCodeAt(index);
  }
  return bytes;
}

function validateConfig(config: ControllerActionBundleReaderConfig): void {
  assert(
    POSITIVE_ID.test(config.appId) &&
      POSITIVE_ID.test(config.installationId) &&
      SAFE_NAME.test(config.appSlug) &&
      SAFE_NAME.test(config.workerVersionId),
    "CONTROLLER_ACTION_READER_CONFIGURATION_INVALID",
    503,
  );
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, Math.max(1, expected.length)) === expected,
    "CONTROLLER_ACTION_REQUEST_INVALID",
  );
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "CONTROLLER_ACTION_REQUEST_INVALID",
  );
}
