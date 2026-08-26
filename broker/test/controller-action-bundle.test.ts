import { describe, expect, it } from "vitest";

import { CONTROLLER_ACTION_EXECUTABLE_PATHS } from "../src/activation-contract";
import { canonicalJson, digestObject } from "../src/canonical";
import { ControllerActionBundleClient } from "../src/controller-action-bundle-client";
import {
  buildControllerActionBundle,
  controllerActionBundleSha256,
  parseControllerActionBundle,
} from "../src/controller-action-bundle";
import { TRUST } from "../src/config";
import {
  ControllerActionBundleReader,
  parseControllerActionBundleObservationRequest,
  type ControllerActionBundleObservationRequest,
} from "../src/private/controller-action-bundle-reader";
import type { ProviderFetch } from "../src/private/github-provider";
import type { JsonObject } from "../src/types";

const API = `https://api.github.com/repos/${TRUST.controllerRepository}`;
const COMMIT = "a".repeat(40);
const VERSION = "controller-reader-version-0001";
const REQUEST_ID = "action-bundle-request-0001";
const TREE_SHAS = {
  actions: "2".repeat(40),
  broker: "3".repeat(40),
  brokerDist: "4".repeat(40),
  commit: "1".repeat(40),
  lease: "5".repeat(40),
  leaseDist: "6".repeat(40),
  runtime: "7".repeat(40),
  runtimeDist: "8".repeat(40),
} as const;

describe("Commit-A executable bundle authority", () => {
  it("constructs only the exact six byte-verified members in canonical order", async () => {
    const bundle = await expectedBundle();
    const parsed = parseControllerActionBundle(bundle, COMMIT);
    expect(parsed).toEqual(bundle);
    expect(bundle.members).toHaveLength(6);
    expect((bundle.members as JsonObject[]).map((member) => member.path)).toEqual(
      CONTROLLER_ACTION_EXECUTABLE_PATHS,
    );
    expect((bundle.members as JsonObject[])[0]).toMatchObject({
      git_blob_sha: "2e65efe2a145dda7ee51d1741299f848e5bf752e",
      mode: "100644",
      sha256: "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
      size_bytes: 1,
    });
    await expect(controllerActionBundleSha256(bundle)).resolves.toMatch(/^sha256:[0-9a-f]{64}$/u);

    const reordered = structuredClone(bundle);
    const members = reordered.members as JsonObject[];
    const first = members[0];
    const second = members[1];
    if (first === undefined || second === undefined) throw new Error("missing test members");
    members[0] = second;
    members[1] = first;
    expect(() => parseControllerActionBundle(reordered, COMMIT)).toThrow(
      "CONTROLLER_ACTION_BUNDLE_LITERAL_MISMATCH",
    );

    const expanded = structuredClone(bundle);
    (expanded.members as JsonObject[]).push({
      git_blob_sha: "f".repeat(40),
      mode: "100644",
      path: "actions/runtime-closure/dist/index.js.map",
      sha256: `sha256:${"f".repeat(64)}`,
      size_bytes: 1,
    });
    expect(() => parseControllerActionBundle(expanded, COMMIT)).toThrow(
      "CONTROLLER_ACTION_BUNDLE_MEMBER_SET_INVALID",
    );
  });

  it("independently walks Commit A and recomputes every provider blob", async () => {
    const bundle = await expectedBundle();
    const calls: string[] = [];
    const reader = new ControllerActionBundleReader(
      config(),
      tokenSource(),
      provider(bundle, calls),
    );
    const observation = await reader.observe(input());
    expect(observation).toMatchObject({
      commit_tree_sha: TREE_SHAS.commit,
      controller_action_bundle: bundle,
      controller_action_bundle_sha256: await controllerActionBundleSha256(bundle),
      provider_api_version: "2026-03-10",
      repository: TRUST.controllerRepository,
      repository_id: TRUST.controllerRepositoryId,
      worker_version_id: VERSION,
    });
    const unsigned = { ...observation };
    delete unsigned.provider_observation_sha256;
    expect(observation.provider_observation_sha256).toBe(await digestObject(unsigned));
    expect(calls.filter((path) => path.includes("/git/blobs/")).length).toBe(6);
    expect(calls.some((path) => path.includes("?ref=") || path.includes("contents/"))).toBe(false);
  });

  it("fails closed on App binding, blob-byte drift, and request shape drift", async () => {
    const bundle = await expectedBundle();
    let accessed = false;
    const never: ProviderFetch = async () => {
      accessed = true;
      throw new Error("must not be called");
    };
    await expect(
      new ControllerActionBundleReader(config(), tokenSource(), never).observe({
        ...input(),
        appId: "999",
      }),
    ).rejects.toThrow("CONTROLLER_ACTION_APP_BINDING_MISMATCH");
    expect(accessed).toBe(false);

    await expect(
      new ControllerActionBundleReader(
        config(),
        tokenSource(),
        provider(bundle, [], { corruptFirstBlob: true }),
      ).observe(input()),
    ).rejects.toThrow("CONTROLLER_ACTION_BLOB_IDENTITY_MISMATCH");

    expect(() =>
      parseControllerActionBundleObservationRequest({
        ...requestBody(),
        url: "https://evil.invalid",
      }),
    ).toThrow("UNKNOWN_FIELD");
    expect(() =>
      parseControllerActionBundleObservationRequest({
        ...requestBody(),
        controller_action_commit_sha: "not-a-sha",
      }),
    ).toThrow("FIELD_INVALID");
  });

  it("crosses the Service Binding with selectors only and verifies the complete observation", async () => {
    const bundle = await expectedBundle();
    const observation = await new ControllerActionBundleReader(
      config(),
      tokenSource(),
      provider(bundle, []),
    ).observe(input());
    const service = {
      fetch: async (request: Request) => {
        expect(request.url).toBe(
          "https://dpone-release-controller-run-reader.internal/rpc/v1/a0/controller-action-bundle",
        );
        expect(request.headers.get("cloudflare-workers-version-overrides")).toBe(
          'dpone-release-controller-run-reader="controller-reader-version-0001"',
        );
        const requestBodyValue = await request.json();
        expect(requestBodyValue).toEqual(requestBody());
        expect(requestBodyValue).not.toHaveProperty("controller_action_bundle");
        return new Response(canonicalJson(observation), {
          headers: { "content-type": "application/json" },
          status: 200,
        });
      },
    } as unknown as Fetcher;
    const result = await new ControllerActionBundleClient(
      service,
      {
        serviceIdentity:
          "cloudflare-worker:0123456789abcdef0123456789abcdef/dpone-release-controller-run-reader@controller-reader-version-0001",
        serviceName: "dpone-release-controller-run-reader",
        versionId: VERSION,
      },
      { appId: "101", appSlug: "controller-reader", installationId: "202" },
    ).observe(COMMIT, REQUEST_ID);
    expect(result.bundle).toEqual(bundle);
    expect(result.observationSha256).toBe(observation.provider_observation_sha256);
  });
});

async function expectedBundle(): Promise<JsonObject> {
  return buildControllerActionBundle(
    COMMIT,
    CONTROLLER_ACTION_EXECUTABLE_PATHS.map((path, index) => ({
      bytes: new TextEncoder().encode(String.fromCharCode(97 + index)),
      path,
    })),
  );
}

function provider(
  bundle: JsonObject,
  calls: string[],
  options: { readonly corruptFirstBlob?: boolean } = {},
): ProviderFetch {
  const members = bundle.members as JsonObject[];
  const blobs = new Map(
    members.map((member, index) => [
      member.git_blob_sha as string,
      new TextEncoder().encode(
        String.fromCharCode(97 + index + (options.corruptFirstBlob && index === 0 ? 1 : 0)),
      ),
    ]),
  );
  return async (target, init) => {
    const url = targetUrl(target);
    calls.push(url);
    expect(init?.method).toBe("GET");
    expect(init?.redirect).toBe("error");
    const headers = new Headers(init?.headers);
    expect(headers.get("authorization")).toBe("Bearer ghs_TestInstallationToken1234");
    expect(headers.get("x-github-api-version")).toBe("2026-03-10");

    if (url === `${API}/git/commits/${COMMIT}`) {
      return response({ sha: COMMIT, tree: { sha: TREE_SHAS.commit } });
    }
    const tree = treeResponse(url, members);
    if (tree !== undefined) return response(tree);
    const prefix = `${API}/git/blobs/`;
    if (url.startsWith(prefix)) {
      const sha = url.slice(prefix.length);
      const bytes = blobs.get(sha);
      if (bytes === undefined) return new Response("not found", { status: 404 });
      return response({
        content: `${base64(bytes)}\n`,
        encoding: "base64",
        sha,
        size: bytes.byteLength,
      });
    }
    return new Response("not found", { status: 404 });
  };
}

function treeResponse(url: string, members: JsonObject[]): JsonObject | undefined {
  const trees = new Map<string, JsonObject[]>([
    [TREE_SHAS.commit, [treeEntry("actions", "040000", TREE_SHAS.actions, "tree")]],
    [
      TREE_SHAS.actions,
      [
        treeEntry("broker-call", "040000", TREE_SHAS.broker, "tree"),
        treeEntry("lease-sentinel", "040000", TREE_SHAS.lease, "tree"),
        treeEntry("runtime-closure", "040000", TREE_SHAS.runtime, "tree"),
      ],
    ],
    [
      TREE_SHAS.broker,
      [
        treeEntry("action.yml", "100644", members[0]?.git_blob_sha as string, "blob"),
        treeEntry("dist", "040000", TREE_SHAS.brokerDist, "tree"),
      ],
    ],
    [
      TREE_SHAS.brokerDist,
      [treeEntry("index.js", "100644", members[1]?.git_blob_sha as string, "blob")],
    ],
    [
      TREE_SHAS.lease,
      [
        treeEntry("action.yml", "100644", members[2]?.git_blob_sha as string, "blob"),
        treeEntry("dist", "040000", TREE_SHAS.leaseDist, "tree"),
      ],
    ],
    [
      TREE_SHAS.leaseDist,
      [treeEntry("index.js", "100644", members[3]?.git_blob_sha as string, "blob")],
    ],
    [
      TREE_SHAS.runtime,
      [
        treeEntry("action.yml", "100644", members[4]?.git_blob_sha as string, "blob"),
        treeEntry("dist", "040000", TREE_SHAS.runtimeDist, "tree"),
      ],
    ],
    [
      TREE_SHAS.runtimeDist,
      [treeEntry("index.js", "100644", members[5]?.git_blob_sha as string, "blob")],
    ],
  ]);
  const prefix = `${API}/git/trees/`;
  if (!url.startsWith(prefix)) return undefined;
  const sha = url.slice(prefix.length);
  const tree = trees.get(sha);
  return tree === undefined ? undefined : { sha, tree, truncated: false };
}

function treeEntry(path: string, mode: string, sha: string, type: string): JsonObject {
  return { mode, path, sha, type };
}

function base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function response(body: JsonObject): Response {
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json" },
    status: 200,
  });
}

function targetUrl(target: RequestInfo | URL): string {
  if (typeof target === "string") return target;
  return target instanceof URL ? target.toString() : target.url;
}

function config() {
  return {
    appId: "101",
    appSlug: "controller-reader",
    installationId: "202",
    workerVersionId: VERSION,
  };
}

function tokenSource() {
  return { installationToken: async () => "ghs_TestInstallationToken1234" };
}

function input(): ControllerActionBundleObservationRequest {
  return {
    appId: "101",
    appSlug: "controller-reader",
    commitSha: COMMIT,
    installationId: "202",
    requestId: REQUEST_ID,
  };
}

function requestBody(): JsonObject {
  return {
    app_id: "101",
    app_slug: "controller-reader",
    controller_action_commit_sha: COMMIT,
    installation_id: "202",
    repository_id: TRUST.controllerRepositoryId,
    request_id: REQUEST_ID,
    schema: "dpone.release-controller-action-bundle-observation-request.v1",
    schema_version: 1,
  };
}
