import { sha256Hex } from "../../src/canonical";
import { TRUST } from "../../src/config";
import {
  CandidateProviderReader,
  type CandidateActivatedAuthority,
  type CandidateProviderInput,
} from "../../src/private/candidate-provider";
import type { InstallationTokenSource } from "../../src/private/github-app";
import type { ProviderFetch } from "../../src/private/github-provider";
import type { JsonObject } from "../../src/types";

export const CANDIDATE_NOW = Date.parse("2026-08-15T12:00:00Z");
export const CANDIDATE_COMMIT = "b".repeat(40);
export const CANDIDATE_TAG_OBJECT = "a".repeat(40);
export const CANDIDATE_VERSION = "candidate-reader-version-0001";
export const CANDIDATE_ZIP = Uint8Array.from([0x50, 0x4b, 0x03, 0x04]);

const API = `https://api.github.com/repos/${TRUST.targetRepository}`;
const POLICY_BYTES = new TextEncoder().encode("policy: exact\n");
const TOKEN = "ghs_TestInstallationToken1234";

export interface CandidateCall {
  readonly authorization: string | null;
  readonly method: string | undefined;
  readonly redirect: RequestRedirect | undefined;
  readonly url: string;
}

export interface CandidateProviderOverrides {
  readonly artifact?: Readonly<JsonObject>;
  readonly artifactsLink?: boolean;
  readonly listedArtifact?: Readonly<JsonObject>;
  readonly policy?: Readonly<JsonObject>;
  readonly redirectLocations?: readonly string[];
  readonly redirectStatus?: number;
  readonly reference?: Readonly<JsonObject>;
  readonly run?: Readonly<JsonObject>;
  readonly signedResponse?: Response;
  readonly tag?: Readonly<JsonObject>;
}

export interface CandidateHarness {
  readonly authority: CandidateActivatedAuthority;
  readonly calls: CandidateCall[];
  readonly input: CandidateProviderInput;
  readonly reader: CandidateProviderReader;
  readonly tokenCalls: { count: number };
}

export async function candidateHarness(
  overrides: CandidateProviderOverrides = {},
): Promise<CandidateHarness> {
  const artifactDigest = `sha256:${await sha256Hex(CANDIDATE_ZIP)}`;
  const policySha256 = `sha256:${await sha256Hex(POLICY_BYTES)}`;
  const policyBlobSha = await gitBlobSha1(POLICY_BYTES);
  const input: CandidateProviderInput = {
    artifactDigest,
    artifactId: 456,
    peeledCommitSha: CANDIDATE_COMMIT,
    release: "v0.74.0",
    requestId: "request-candidate-0001",
    runAttempt: 2,
    runId: 123,
  };
  const calls: CandidateCall[] = [];
  const locations = [...(overrides.redirectLocations ?? [signedUrl()])];
  const fetcher: ProviderFetch = async (target, init) => {
    const url = targetUrl(target);
    const headers = new Headers(init?.headers);
    calls.push({
      authorization: headers.get("authorization"),
      method: init?.method,
      redirect: init?.redirect,
      url,
    });

    if (url === `${API}/actions/runs/123`) {
      return jsonResponse({ ...run(), ...overrides.run });
    }
    if (url === `${API}/actions/artifacts/456`) {
      return jsonResponse({ ...artifact(input), ...overrides.artifact });
    }
    if (url === `${API}/actions/runs/123/artifacts?name=release-candidates&per_page=100&page=1`) {
      const listed = {
        ...artifact(input),
        ...overrides.artifact,
        ...overrides.listedArtifact,
      };
      return jsonResponse(
        { artifacts: [listed], total_count: 1 },
        overrides.artifactsLink ? { link: `<${url}&page=2>; rel="next"` } : {},
      );
    }
    if (url === `${API}/git/ref/tags/v0.74.0`) {
      return jsonResponse({ ...reference(), ...overrides.reference });
    }
    if (url === `${API}/git/tags/${CANDIDATE_TAG_OBJECT}`) {
      return jsonResponse({ ...tag(), ...overrides.tag });
    }
    if (
      url === `${API}/contents/.agents/policy/github-branch-protection.yml?ref=${CANDIDATE_COMMIT}`
    ) {
      return jsonResponse({
        ...policy(policyBlobSha),
        ...overrides.policy,
      });
    }
    if (url === `${API}/actions/artifacts/456/zip`) {
      const location = locations.shift();
      return new Response(null, {
        headers: location === undefined ? {} : { location },
        status: overrides.redirectStatus ?? 302,
      });
    }
    if (url.startsWith("https://productionresultssa0.blob.core.windows.net/")) {
      return (
        overrides.signedResponse ??
        new Response(CANDIDATE_ZIP, {
          headers: {
            "content-length": String(CANDIDATE_ZIP.byteLength),
            "content-type": "application/zip",
          },
        })
      );
    }
    return new Response("not found", { status: 404 });
  };
  const tokenCalls = { count: 0 };
  const tokens: InstallationTokenSource = {
    async installationToken() {
      tokenCalls.count += 1;
      return TOKEN;
    },
  };
  return {
    authority: { policyBlobSha, policySha256 },
    calls,
    input,
    reader: new CandidateProviderReader(
      { workerVersionId: CANDIDATE_VERSION },
      tokens,
      fetcher,
      () => CANDIDATE_NOW,
    ),
    tokenCalls,
  };
}

export function signedUrl(expiresAt = "2026-08-15T12:00:45Z"): string {
  const url = new URL(
    "https://productionresultssa0.blob.core.windows.net/actions-results/run/artifact.zip",
  );
  url.searchParams.set("se", expiresAt);
  url.searchParams.set("sig", "A".repeat(32));
  url.searchParams.set("sp", "r");
  url.searchParams.set("spr", "https");
  url.searchParams.set("sr", "b");
  url.searchParams.set("st", "2026-08-15T11:59:55Z");
  url.searchParams.set("sv", "2025-11-05");
  url.searchParams.set("rscd", "attachment; filename=release-candidates.zip");
  url.searchParams.set("rsct", "application/zip");
  return url.toString();
}

function run(): JsonObject {
  return {
    conclusion: "success",
    event: "push",
    head_branch: "v0.74.0",
    head_repository: { id: TRUST.targetRepositoryId },
    head_sha: CANDIDATE_COMMIT,
    id: 123,
    path: ".github/workflows/release.yml",
    repository: { id: TRUST.targetRepositoryId },
    run_attempt: 2,
    status: "completed",
  };
}

function artifact(input: CandidateProviderInput): JsonObject {
  return {
    archive_download_url: `${API}/actions/artifacts/456/zip`,
    created_at: "2026-08-15T11:00:00Z",
    digest: input.artifactDigest,
    expired: false,
    expires_at: "2026-08-16T11:00:00Z",
    id: 456,
    name: "release-candidates",
    size_in_bytes: CANDIDATE_ZIP.byteLength,
    url: `${API}/actions/artifacts/456`,
    workflow_run: {
      head_branch: "v0.74.0",
      head_repository_id: TRUST.targetRepositoryId,
      head_sha: CANDIDATE_COMMIT,
      id: 123,
      repository_id: TRUST.targetRepositoryId,
    },
  };
}

function reference(): JsonObject {
  return {
    object: { sha: CANDIDATE_TAG_OBJECT, type: "tag" },
    ref: "refs/tags/v0.74.0",
  };
}

function tag(): JsonObject {
  return {
    object: { sha: CANDIDATE_COMMIT, type: "commit" },
    sha: CANDIDATE_TAG_OBJECT,
    tag: "v0.74.0",
  };
}

function policy(blobSha: string): JsonObject {
  return {
    content: bytesBase64(POLICY_BYTES),
    encoding: "base64",
    name: "github-branch-protection.yml",
    path: ".agents/policy/github-branch-protection.yml",
    sha: blobSha,
    size: POLICY_BYTES.byteLength,
    type: "file",
  };
}

function jsonResponse(body: JsonObject, extra: HeadersInit = {}): Response {
  return new Response(JSON.stringify(body), {
    headers: {
      "content-type": "application/json",
      ...Object.fromEntries(new Headers(extra)),
    },
  });
}

function targetUrl(target: RequestInfo | URL): string {
  if (typeof target === "string") return target;
  return target instanceof URL ? target.toString() : target.url;
}

function bytesBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

async function gitBlobSha1(bytes: Uint8Array): Promise<string> {
  const prefix = new TextEncoder().encode(`blob ${bytes.byteLength}\0`);
  const preimage = new Uint8Array(prefix.byteLength + bytes.byteLength);
  preimage.set(prefix);
  preimage.set(bytes, prefix.byteLength);
  const digest = await crypto.subtle.digest("SHA-1", preimage.buffer);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
