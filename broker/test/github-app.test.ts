import { decodeJwt } from "jose";
import { beforeAll, describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical";
import { type GitHubAppConfig, GitHubAppTokenProvider } from "../src/private/github-app";
import type { ProviderFetch } from "../src/private/github-provider";
import type { JsonObject } from "../src/types";

const NOW = 2_000_000_000_000;
let privateKey = "";

beforeAll(async () => {
  privateKey = await generatePkcs8();
});

describe("isolated GitHub App token provider", () => {
  it("requests one selected repository and the exact read-only permission set", async () => {
    let calls = 0;
    const providerFetch: ProviderFetch = async (target, init) => {
      calls += 1;
      expect(providerTargetUrl(target)).toBe(
        "https://api.github.com/app/installations/202/access_tokens",
      );
      expect(init?.method).toBe("POST");
      expect(init?.redirect).toBe("error");
      const headers = new Headers(init?.headers);
      expect(headers.get("x-github-api-version")).toBe("2026-03-10");
      const authorization = headers.get("authorization");
      expect(authorization?.startsWith("Bearer ")).toBe(true);
      const claims = decodeJwt((authorization ?? "").slice("Bearer ".length));
      expect(claims.iss).toBe("101");
      expect(claims.exp).toBe(2_000_000_540);
      expect(claims.iat).toBe(1_999_999_940);
      expect(init?.body).toBe(
        canonicalJson({
          permissions: permissions(),
          repository_ids: [1_305_993_853],
        }),
      );
      return providerResponse(tokenResponse());
    };
    const token = await new GitHubAppTokenProvider(
      config(),
      providerFetch,
      () => NOW,
    ).installationToken();
    expect(token).toBe(classicToken());
    expect(calls).toBe(1);
  });

  it("rejects provider privilege or repository expansion", async () => {
    await expect(
      new GitHubAppTokenProvider(
        config(),
        async () =>
          providerResponse(
            tokenResponse({ permissions: { ...permissions(), deployments: "write" } }),
          ),
        () => NOW,
      ).installationToken(),
    ).rejects.toThrow("GITHUB_INSTALLATION_PERMISSION_INVALID");

    await expect(
      new GitHubAppTokenProvider(
        config(),
        async () =>
          providerResponse(
            tokenResponse({
              repositories: [repository(), { full_name: "PaulKov/another", id: 99 }],
            }),
          ),
        () => NOW,
      ).installationToken(),
    ).rejects.toThrow("GITHUB_INSTALLATION_SCOPE_INVALID");
  });

  it("rejects expired, overlong and non-installation bearer responses", async () => {
    await expect(
      new GitHubAppTokenProvider(
        config(),
        async () => providerResponse(tokenResponse({ expires_at: new Date(NOW).toISOString() })),
        () => NOW,
      ).installationToken(),
    ).rejects.toThrow("GITHUB_INSTALLATION_TOKEN_INVALID");

    await expect(
      new GitHubAppTokenProvider(
        config(),
        async () => providerResponse(tokenResponse({ token: "github_pat_broad" })),
        () => NOW,
      ).installationToken(),
    ).rejects.toThrow("GITHUB_INSTALLATION_TOKEN_INVALID");

    for (const token of [
      "ghs_too-short",
      `ghs_${"a".repeat(4092)}`,
      `ghs_${"a".repeat(35)}\n`,
      `github_pat_${"a".repeat(40)}`,
    ]) {
      await expect(
        new GitHubAppTokenProvider(
          config(),
          async () => providerResponse(tokenResponse({ token })),
          () => NOW,
        ).installationToken(),
      ).rejects.toThrow("GITHUB_INSTALLATION_TOKEN_INVALID");
    }
  });

  it("accepts stateless opaque installation tokens without decoding them", async () => {
    for (const stateless of [
      `ghs_${"a".repeat(80)}.${"b".repeat(80)}-${"c".repeat(80)}`,
      `ghs_101_e30.eyJpc3MiOiIxMDEifQ.${"a-b_c".repeat(24)}`,
    ]) {
      await expect(
        new GitHubAppTokenProvider(
          config(),
          async () => providerResponse(tokenResponse({ token: stateless })),
          () => NOW,
        ).installationToken(),
      ).resolves.toBe(stateless);
    }
  });

  it("rejects downloaded PKCS#1 keys at runtime; provisioning must convert first", () => {
    expect(
      () =>
        new GitHubAppTokenProvider({
          ...config(),
          privateKey:
            "-----BEGIN RSA PRIVATE KEY-----\nnot-a-runtime-key\n-----END RSA PRIVATE KEY-----",
        }),
    ).toThrow("GITHUB_APP_CONFIGURATION_INVALID");
  });
});

function providerTargetUrl(target: RequestInfo | URL): string {
  if (typeof target === "string") return target;
  return target instanceof URL ? target.toString() : target.url;
}

function config(): GitHubAppConfig {
  return {
    appId: "101",
    installationId: "202",
    permissions: permissions(),
    privateKey,
    repository: "PaulKov/dpone-release-controller",
    repositoryId: 1_305_993_853,
  };
}

function permissions() {
  return {
    actions: "read",
    checks: "read",
    contents: "read",
    metadata: "read",
  } as const;
}

function repository(): JsonObject {
  return {
    full_name: "PaulKov/dpone-release-controller",
    id: 1_305_993_853,
  };
}

function tokenResponse(overrides: Readonly<Record<string, unknown>> = {}): JsonObject {
  return {
    expires_at: new Date(NOW + 3_600_000).toISOString(),
    permissions: permissions(),
    repositories: [repository()],
    repository_selection: "selected",
    token: classicToken(),
    ...overrides,
  };
}

function classicToken(): string {
  return `ghs_${"ClassicInstallationToken".repeat(2)}`;
}

function providerResponse(value: JsonObject): Response {
  return new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json" },
    status: 201,
  });
}

async function generatePkcs8(): Promise<string> {
  const keys = await crypto.subtle.generateKey(
    {
      hash: "SHA-256",
      modulusLength: 2048,
      name: "RSASSA-PKCS1-v1_5",
      publicExponent: new Uint8Array([1, 0, 1]),
    },
    true,
    ["sign", "verify"],
  );
  const bytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keys.privateKey));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const base64 = btoa(binary)
    .match(/.{1,64}/gu)
    ?.join("\n");
  if (base64 === undefined) throw new Error("PKCS8 encoding failed");
  return `-----BEGIN PRIVATE KEY-----\n${base64}\n-----END PRIVATE KEY-----`;
}
