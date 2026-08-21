import { importPKCS8, SignJWT } from "jose";

import { canonicalJson } from "../canonical";
import { BrokerError } from "../errors";
import type { JsonObject } from "../types";
import {
  githubJson,
  githubRequest,
  type ProviderFetch,
  providerArray,
  providerInteger,
  providerObject,
  providerString,
  requireGitHubOk,
} from "./github-provider";

const POSITIVE_ID = /^[1-9][0-9]{0,31}$/u;
// GitHub installation tokens are opaque. The alphabet admits both classic
// tokens and the 2026 stateless/JWT-shaped rollout without decoding either.
const INSTALLATION_TOKEN = /^ghs_[A-Za-z0-9._-]{36,4091}$/u;
const MAX_TOKEN_LIFETIME_MS = 3_660_000;

export interface GitHubAppConfig {
  readonly appId: string;
  readonly installationId: string;
  readonly permissions: Readonly<Record<string, "read" | "write">>;
  readonly privateKey: string;
  readonly repository: string;
  readonly repositoryId: number;
}

/** Credential source implemented only inside a private provider Worker. */
export interface InstallationTokenSource {
  installationToken(): Promise<string>;
}

/**
 * Issues an exact-repository installation token inside a credential-isolated
 * private Worker. The token is never serialised into an RPC response.
 */
export class GitHubAppTokenProvider {
  private readonly signingKey: Promise<CryptoKey>;

  public constructor(
    private readonly config: GitHubAppConfig,
    private readonly providerFetch: ProviderFetch = fetch,
    private readonly now: () => number = Date.now,
  ) {
    validateConfig(config);
    this.signingKey = importPKCS8(config.privateKey, "RS256");
  }

  public async installationToken(): Promise<string> {
    const nowMs = this.now();
    const nowSeconds = Math.floor(nowMs / 1000);
    let appJwt: string;
    try {
      appJwt = await new SignJWT({})
        .setProtectedHeader({ alg: "RS256", typ: "JWT" })
        .setIssuer(this.config.appId)
        .setIssuedAt(nowSeconds - 60)
        .setExpirationTime(nowSeconds + 540)
        .sign(await this.signingKey);
    } catch {
      throw new BrokerError("GITHUB_APP_KEY_INVALID", 503, false);
    }
    const requestBody: JsonObject = {
      permissions: { ...this.config.permissions },
      repository_ids: [this.config.repositoryId],
    };
    const response = await githubRequest(this.providerFetch, {
      authorization: `Bearer ${appJwt}`,
      body: canonicalJson(requestBody),
      method: "POST",
      path: `/app/installations/${this.config.installationId}/access_tokens`,
    });
    await requireGitHubOk(response, "GITHUB_INSTALLATION_TOKEN_FAILED");
    const body = await githubJson(response, 65_536, "GITHUB_INSTALLATION_TOKEN_INVALID", 201);
    verifyGrantedRepository(body, this.config);
    verifyGrantedPermissions(body, this.config.permissions);
    const expiresAt = Date.parse(
      providerString(body, "expires_at", 64, "GITHUB_INSTALLATION_TOKEN_INVALID"),
    );
    if (
      !Number.isFinite(expiresAt) ||
      expiresAt <= nowMs + 30_000 ||
      expiresAt > nowMs + MAX_TOKEN_LIFETIME_MS
    ) {
      throw new BrokerError("GITHUB_INSTALLATION_TOKEN_INVALID", 503, false);
    }
    const token = providerString(body, "token", 4096, "GITHUB_INSTALLATION_TOKEN_INVALID");
    if (!INSTALLATION_TOKEN.test(token)) {
      throw new BrokerError("GITHUB_INSTALLATION_TOKEN_INVALID", 503, false);
    }
    return token;
  }
}

function verifyGrantedRepository(body: JsonObject, config: GitHubAppConfig): void {
  const repositories = providerArray(body, "repositories", "GITHUB_INSTALLATION_TOKEN_INVALID");
  if (repositories.length !== 1) {
    throw new BrokerError("GITHUB_INSTALLATION_SCOPE_INVALID", 503, false);
  }
  const repository = providerObject(repositories[0], "GITHUB_INSTALLATION_TOKEN_INVALID");
  if (
    providerInteger(repository, "id", "GITHUB_INSTALLATION_TOKEN_INVALID") !==
      config.repositoryId ||
    providerString(repository, "full_name", 256, "GITHUB_INSTALLATION_TOKEN_INVALID") !==
      config.repository
  ) {
    throw new BrokerError("GITHUB_INSTALLATION_SCOPE_INVALID", 503, false);
  }
  const selection = body.repository_selection;
  if (selection !== undefined && selection !== "selected") {
    throw new BrokerError("GITHUB_INSTALLATION_SCOPE_INVALID", 503, false);
  }
}

function verifyGrantedPermissions(
  body: JsonObject,
  expected: Readonly<Record<string, "read" | "write">>,
): void {
  const permissions = providerObject(body.permissions, "GITHUB_INSTALLATION_TOKEN_INVALID");
  const actualKeys = Object.keys(permissions).sort();
  const expectedKeys = Object.keys(expected).sort();
  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new BrokerError("GITHUB_INSTALLATION_PERMISSION_INVALID", 503, false);
  }
  for (const key of expectedKeys) {
    if (permissions[key] !== expected[key]) {
      throw new BrokerError("GITHUB_INSTALLATION_PERMISSION_INVALID", 503, false);
    }
  }
}

function validateConfig(config: GitHubAppConfig): void {
  if (
    !POSITIVE_ID.test(config.appId) ||
    !POSITIVE_ID.test(config.installationId) ||
    !Number.isSafeInteger(config.repositoryId) ||
    config.repositoryId <= 0 ||
    !/^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/u.test(config.repository) ||
    !config.privateKey.startsWith("-----BEGIN PRIVATE KEY-----\n") ||
    !config.privateKey.endsWith("\n-----END PRIVATE KEY-----") ||
    config.privateKey.length > 16_384
  ) {
    throw new BrokerError("GITHUB_APP_CONFIGURATION_INVALID", 503, false);
  }
  const keys = Object.keys(config.permissions);
  if (
    keys.length === 0 ||
    keys.some(
      (key) =>
        !/^[a-z_]{1,64}$/u.test(key) ||
        (config.permissions[key] !== "read" && config.permissions[key] !== "write"),
    )
  ) {
    throw new BrokerError("GITHUB_APP_CONFIGURATION_INVALID", 503, false);
  }
}
