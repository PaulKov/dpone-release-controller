import { describe, expect, it } from "vitest";

import { TRUST } from "../src/config";
import {
  GitHubOidcEvidenceReader,
  oidcProviderFixtureBytes,
  type GitHubOidcEvidenceConfig,
} from "../src/private/github-oidc-evidence";
import type { JsonObject } from "../src/types";

const NOW = Date.parse("2026-08-15T12:00:00.999Z");
const REQUEST_ID = "activation-evidence-request-0001";
const WORKER_VERSION = "00000000-0000-0000-0000-000000000001";

describe("GitHub A0 OIDC provider evidence", () => {
  it("captures exact raw bytes and recomputes the immutable default-subject projection", async () => {
    const raw = oidcProviderFixtureBytes(providerBody());
    const calls: { authorization: string | null; url: string; version: string | null }[] = [];
    const observation = await reader(controllerConfig(), async (input, init) => {
      const headers = new Headers(init?.headers);
      calls.push({
        authorization: headers.get("authorization"),
        url: providerTargetUrl(input),
        version: headers.get("x-github-api-version"),
      });
      return new Response(Uint8Array.from(raw).buffer, {
        headers: { "content-type": "application/json" },
        status: 200,
      });
    }).observe(REQUEST_ID);

    expect(calls).toEqual([
      {
        authorization: "Bearer ghs_test-token-never-returned",
        url: "https://api.github.com/repos/PaulKov/dpone-release-controller/actions/oidc/customization/sub",
        version: "2026-03-10",
      },
    ]);
    expect(observation).toMatchObject({
      evidence_kind: "github_oidc_subject_customization",
      observed_at: "2026-08-15T12:00:00Z",
      observer_role: "controller_run_reader",
      observer_service_identity: `cloudflare-worker:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/controller-run-reader@${WORKER_VERSION}`,
      projection: providerBody(),
      repository: TRUST.controllerRepository,
      repository_id: TRUST.controllerRepositoryId,
      request_id: REQUEST_ID,
    });
    expect(observation.observation_sha256).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(observation.raw_response_sha256).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(JSON.stringify(observation)).not.toContain("ghs_test-token");
  });

  it("fails closed on mutable/default-name subject modes and provider-shape drift", async () => {
    const invalid: JsonObject[] = [
      { ...providerBody(), use_default: false },
      { ...providerBody(), use_immutable_subject: false },
      { ...providerBody(), sub_claim_prefix: "repo:PaulKov/dpone-release-controller" },
      { use_default: true, use_immutable_subject: true },
      { ...providerBody(), include_claim_keys: [] },
      { ...providerBody(), future_provider_field: true },
    ];
    for (const body of invalid) {
      await expect(
        reader(controllerConfig(), async () => providerResponse(body)).observe(REQUEST_ID),
      ).rejects.toThrow();
    }
  });

  it("rejects redirects, cookies, non-JSON bodies, oversize bodies and repository-role aliasing", async () => {
    for (const headers of [
      { "content-encoding": "gzip", "content-type": "application/json" },
      { "content-range": "bytes 0-1/2", "content-type": "application/json" },
      { "content-type": "application/json", location: "https://attacker.invalid" },
      { "content-type": "application/json", "set-cookie": "secret=value" },
      { "content-type": "application/json", "transfer-encoding": "chunked" },
      { "content-type": "text/plain" },
    ]) {
      const candidate = cancelableProviderResponse(headers);
      await expect(
        reader(controllerConfig(), async () => candidate.response).observe(REQUEST_ID),
      ).rejects.toThrow("A0_OIDC_PROVIDER_RESPONSE_INVALID");
      expect(candidate.canceled()).toBe(true);
    }
    await expect(
      reader(
        controllerConfig(),
        async () =>
          new Response(new Uint8Array(4_097), {
            headers: { "content-length": "4097", "content-type": "application/json" },
            status: 200,
          }),
      ).observe(REQUEST_ID),
    ).rejects.toThrow("A0_OIDC_PROVIDER_RESPONSE_TOO_LARGE");
    expect(
      () =>
        new GitHubOidcEvidenceReader(
          { ...controllerConfig(), observerRole: "governance_reader" },
          tokenSource(),
        ),
    ).toThrow("A0_OIDC_READER_CONFIGURATION_INVALID");
  });
});

function providerTargetUrl(input: RequestInfo | URL): string {
  if (typeof input === "string") return input;
  return input instanceof URL ? input.toString() : input.url;
}

function reader(
  config: GitHubOidcEvidenceConfig,
  providerFetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>,
): GitHubOidcEvidenceReader {
  return new GitHubOidcEvidenceReader(config, tokenSource(), providerFetch, () => NOW);
}

function tokenSource() {
  return { installationToken: async () => "ghs_test-token-never-returned" };
}

function controllerConfig(): GitHubOidcEvidenceConfig {
  return {
    cloudflareAccountId: "a".repeat(32),
    observerRole: "controller_run_reader",
    repository: TRUST.controllerRepository,
    repositoryId: TRUST.controllerRepositoryId,
    serviceName: "controller-run-reader",
    workerVersionId: WORKER_VERSION,
  };
}

function providerBody(): JsonObject {
  return {
    sub_claim_prefix: "repo:PaulKov@74862786/dpone-release-controller@1305993853",
    use_default: true,
    use_immutable_subject: true,
  };
}

function providerResponse(body: JsonObject, headers: Record<string, string> = {}): Response {
  return new Response(Uint8Array.from(oidcProviderFixtureBytes(body)).buffer, {
    headers: { "content-type": "application/json", ...headers },
    status: 200,
  });
}

function cancelableProviderResponse(headers: Record<string, string>): {
  readonly canceled: () => boolean;
  readonly response: Response;
} {
  let canceled = false;
  const body = new ReadableStream<Uint8Array>({
    cancel() {
      canceled = true;
    },
    start(controller) {
      controller.enqueue(oidcProviderFixtureBytes(providerBody()));
    },
  });
  return {
    canceled: () => canceled,
    response: new Response(body, { headers, status: 200 }),
  };
}
