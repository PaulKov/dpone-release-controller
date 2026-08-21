import { describe, expect, it } from "vitest";

import { canonicalJson, digestObject } from "../src/canonical";
import { TRUST } from "../src/config";
import { GitHubOidcEvidenceClient } from "../src/github-oidc-evidence-client";
import {
  GitHubOidcEvidenceReader,
  oidcProviderFixtureBytes,
} from "../src/private/github-oidc-evidence";
import type { JsonObject, PrivateServicePin } from "../src/types";

const NOW = Date.parse("2026-08-15T12:00:00Z");
const REQUEST_ID = "activation-evidence-request-0002";
const WORKER_VERSION = "00000000-0000-0000-0000-000000000001";
const PIN: PrivateServicePin = {
  serviceIdentity: `cloudflare-worker:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/controller-run-reader@${WORKER_VERSION}`,
  serviceName: "controller-run-reader",
  versionId: WORKER_VERSION,
};

describe("version-pinned OIDC evidence client", () => {
  it("rechecks exact raw bytes, projection, freshness and service identity", async () => {
    const observation = await providerObservation();
    let override = "";
    const service = {
      async fetch(request: Request): Promise<Response> {
        override = request.headers.get("cloudflare-workers-version-overrides") ?? "";
        return response(observation);
      },
    } as unknown as Fetcher;
    const result = await client(service).observe(REQUEST_ID);
    expect(result.observation_sha256).toBe(observation.observation_sha256);
    expect(override).toBe(`controller-run-reader="${WORKER_VERSION}"`);
  });

  it("rejects raw-byte, projection, identity, timestamp and digest drift", async () => {
    const base = await providerObservation();
    const mutations: JsonObject[] = [
      { ...base, raw_response_base64url: "e30" },
      { ...base, projection: { ...object(base, "projection"), use_immutable_subject: false } },
      { ...base, observer_service_identity: "cloudflare-worker:attacker/service@version-00000001" },
      { ...base, observed_at: "2026-08-15T11:58:59Z" },
      { ...base, observation_sha256: tagged("f") },
    ];
    for (const mutation of mutations) {
      if (mutation.observation_sha256 === base.observation_sha256) {
        const unsigned = { ...mutation };
        delete unsigned.observation_sha256;
        mutation.observation_sha256 = await digestObject(unsigned);
      }
      await expect(client(serviceFor(mutation)).observe(REQUEST_ID)).rejects.toThrow();
    }
  });

  it("rejects redirects, cookies, encoding transforms, and wrong media types", async () => {
    const observation = await providerObservation();
    for (const headers of [
      { "content-type": "text/plain" },
      { "content-type": "application/json", location: "https://attacker.invalid" },
      { "content-encoding": "gzip", "content-type": "application/json" },
      { "content-type": "application/json", "set-cookie": "authority=leak" },
    ]) {
      const service = {
        fetch: async () =>
          new Response(canonicalJson(observation), {
            headers: { ...headers, "x-request-id": REQUEST_ID },
            status: 200,
          }),
      } as unknown as Fetcher;
      await expect(client(service).observe(REQUEST_ID)).rejects.toThrow(
        "A0_OIDC_EVIDENCE_SERVICE_RESPONSE_INVALID",
      );
    }
  });
});

function client(service: Fetcher): GitHubOidcEvidenceClient {
  return new GitHubOidcEvidenceClient(
    service,
    PIN,
    {
      observerRole: "controller_run_reader",
      repository: TRUST.controllerRepository,
      repositoryId: TRUST.controllerRepositoryId,
    },
    () => NOW,
  );
}

async function providerObservation(): Promise<JsonObject> {
  return new GitHubOidcEvidenceReader(
    {
      cloudflareAccountId: "a".repeat(32),
      observerRole: "controller_run_reader",
      repository: TRUST.controllerRepository,
      repositoryId: TRUST.controllerRepositoryId,
      serviceName: PIN.serviceName,
      workerVersionId: PIN.versionId,
    },
    { installationToken: async () => "ghs_test-token-never-returned" },
    async () =>
      new Response(
        Uint8Array.from(
          oidcProviderFixtureBytes({
            sub_claim_prefix: "repo:PaulKov@74862786/dpone-release-controller@1305993853",
            use_default: true,
            use_immutable_subject: true,
          }),
        ).buffer,
        { headers: { "content-type": "application/json" }, status: 200 },
      ),
    () => NOW,
  ).observe(REQUEST_ID);
}

function serviceFor(observation: JsonObject): Fetcher {
  return { fetch: async () => response(observation) } as unknown as Fetcher;
}

function response(observation: JsonObject): Response {
  return new Response(canonicalJson(observation), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "x-request-id": REQUEST_ID,
    },
    status: 200,
  });
}

function object(parent: JsonObject, key: string): JsonObject {
  const value = parent[key];
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(key);
  return value;
}

function tagged(character: string): string {
  return `sha256:${character.repeat(64)}`;
}
