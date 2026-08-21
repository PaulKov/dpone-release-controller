import { generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";

import { adminReplayKey, authenticateAdmin } from "../src/admin-auth";
import type { TrustedRuntimeConfig } from "../src/types";

const CONFIG: TrustedRuntimeConfig = {
  adminAccessApplicationId: "11111111-1111-4111-8111-111111111111",
  adminAccessAudience: "access-audience-immutable-000001",
  adminAccessGroup: "release-activation-admins",
  adminAccessIdentity: "release-admin@example.invalid",
  adminAccessIssuer: "https://dpone.cloudflareaccess.com",
  adminAccessPolicyId: "22222222-2222-4222-8222-222222222222",
  adminAccessSubjectId: "33333333-3333-4333-8333-333333333333",
  adminHostname: "release-broker.example.invalid",
  adminMtlsCertSha256: "a".repeat(64),
  cloudflareAccountId: "a".repeat(32),
  cloudflareObserverRpcAuthKey: "A".repeat(43),
  workerVersionId: "ingress-worker-version-0001",
  workerServiceIdentity:
    "cloudflare-worker:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/authority-broker@ingress-worker-version-0001",
  wormRpcAuthKey: "A".repeat(43),
};

let privateKey: CryptoKey;
let publicKey: CryptoKey;

beforeAll(async () => {
  ({ privateKey, publicKey } = await generateKeyPair("RS256", {
    extractable: false,
  }));
});

describe("activation admin dual authentication", () => {
  it("admits only the exact mTLS and Access identity pair", async () => {
    const token = await issueToken();
    const result = await authenticateAdmin(request(token), CONFIG, async () => publicKey);
    expect(result.identityNonce).toHaveLength(36);
    expect(result.tokenSha256).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(result.claimsDigest).toMatch(/^sha256:[0-9a-f]{64}$/u);
  });

  it("denies either missing factor and a forged certificate", async () => {
    const token = await issueToken();
    await expect(
      authenticateAdmin(request(null), CONFIG, async () => publicKey),
    ).rejects.toThrowError("ADMIN_ACCESS_REQUIRED");
    await expect(
      authenticateAdmin(request(token, null), CONFIG, async () => publicKey),
    ).rejects.toThrowError("ADMIN_MTLS_REQUIRED");
    await expect(
      authenticateAdmin(request(token, "b".repeat(64)), CONFIG, async () => publicKey),
    ).rejects.toThrowError("ADMIN_MTLS_DENIED");
  });

  it("denies an unpresented or revoked mTLS certificate", async () => {
    const token = await issueToken();
    await expect(
      authenticateAdmin(
        request(token, CONFIG.adminMtlsCertSha256, { presented: "0" }),
        CONFIG,
        async () => publicKey,
      ),
    ).rejects.toThrowError("ADMIN_MTLS_REQUIRED");
    await expect(
      authenticateAdmin(
        request(token, CONFIG.adminMtlsCertSha256, { revoked: "1" }),
        CONFIG,
        async () => publicKey,
      ),
    ).rejects.toThrowError("ADMIN_MTLS_REQUIRED");
  });

  it("denies the wrong Access audience, identity, subject or token type", async () => {
    const cases = [
      await issueToken({ audience: "wrong-access-audience-000001" }),
      await issueToken({ email: "attacker@example.invalid" }),
      await issueToken({ subject: "44444444-4444-4444-8444-444444444444" }),
      await issueToken({ type: "org" }),
    ];
    for (const token of cases) {
      await expect(
        authenticateAdmin(request(token), CONFIG, async () => publicKey),
      ).rejects.toThrowError();
    }
  });

  it("requires Cloudflare's exact one-element audience array", async () => {
    const stringAudience = await issueToken({ audienceAsString: true });
    await expect(
      authenticateAdmin(request(stringAudience), CONFIG, async () => publicKey),
    ).rejects.toThrowError("ADMIN_ACCESS_DENIED");

    const multipleAudiences = await issueToken({
      audiences: [CONFIG.adminAccessAudience, "second-access-audience-000001"],
    });
    await expect(
      authenticateAdmin(request(multipleAudiences), CONFIG, async () => publicKey),
    ).rejects.toThrowError("ADMIN_ACCESS_DENIED");
  });

  it("does not depend on unstable custom IdP group claims", async () => {
    const token = await issueToken({ groups: ["provider-renamed-group"] });
    const result = await authenticateAdmin(request(token), CONFIG, async () => publicKey);
    expect(result.identityNonce).toHaveLength(36);
  });

  it("binds replay admission to token, method, path, body and request id", async () => {
    const token = await issueToken();
    const authentication = await authenticateAdmin(request(token), CONFIG, async () => publicKey);
    const base = {
      authentication,
      canonicalBody: '{"request_id":"admin-request-0001"}',
      method: "POST",
      path: "/v1/admin/activation/provision",
      requestId: "admin-request-0001",
    } as const;
    const replayKey = await adminReplayKey(base);
    await expect(adminReplayKey(base)).resolves.toBe(replayKey);
    await expect(
      adminReplayKey({ ...base, canonicalBody: '{"request_id":"admin-request-0002"}' }),
    ).resolves.not.toBe(replayKey);
    await expect(
      adminReplayKey({ ...base, path: "/v1/admin/activation/finalize" }),
    ).resolves.not.toBe(replayKey);
  });

  it("never accepts a GitHub bearer on an admin route", async () => {
    const token = await issueToken();
    const adminRequest = request(token);
    adminRequest.headers.set("authorization", "Bearer github-oidc-token");
    await expect(
      authenticateAdmin(adminRequest, CONFIG, async () => publicKey),
    ).rejects.toThrowError("ADMIN_GITHUB_OIDC_FORBIDDEN");
  });
});

async function issueToken(
  overrides: {
    readonly audience?: string;
    readonly audienceAsString?: boolean;
    readonly audiences?: string[];
    readonly email?: string;
    readonly groups?: string[];
    readonly subject?: string;
    readonly type?: string;
  } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    email: overrides.email ?? CONFIG.adminAccessIdentity,
    groups: overrides.groups ?? [CONFIG.adminAccessGroup],
    identity_nonce: crypto.randomUUID(),
    type: overrides.type ?? "app",
  })
    .setProtectedHeader({ alg: "RS256", kid: "access-test", typ: "JWT" })
    .setIssuer(CONFIG.adminAccessIssuer)
    .setAudience(
      overrides.audienceAsString
        ? CONFIG.adminAccessAudience
        : (overrides.audiences ?? [overrides.audience ?? CONFIG.adminAccessAudience]),
    )
    .setSubject(overrides.subject ?? CONFIG.adminAccessSubjectId)
    .setIssuedAt(now)
    .setNotBefore(now - 1)
    .setExpirationTime(now + 60)
    .sign(privateKey);
}

function request(
  token: string | null,
  fingerprint: string | null = CONFIG.adminMtlsCertSha256,
  tls: { readonly presented?: string; readonly revoked?: string } = {},
): Request {
  const headers = new Headers({
    "content-type": "application/json",
    "x-request-id": "admin-request-0001",
  });
  if (token !== null) {
    headers.set("cf-access-jwt-assertion", token);
  }
  const value = new Request(`https://${CONFIG.adminHostname}/v1/admin/activation/provision`, {
    body: "{}",
    headers,
    method: "POST",
  });
  Object.defineProperty(value, "cf", {
    value: {
      tlsClientAuth:
        fingerprint === null
          ? undefined
          : {
              certFingerprintSHA256: fingerprint,
              certPresented: tls.presented ?? "1",
              certRevoked: tls.revoked ?? "0",
              certVerified: "SUCCESS",
            },
    },
  });
  return value;
}
