import {
  createRemoteJWKSet,
  errors as joseErrors,
  jwtVerify,
  type JWTVerifyGetKey,
  type JWTPayload,
} from "jose";

import { digestObject, sha256Hex, timingSafeEqual } from "./canonical";
import { assert, BrokerError } from "./errors";
import type { JsonObject, TrustedRuntimeConfig } from "./types";

const ACCESS_HEADER = "cf-access-jwt-assertion";
const ADMIN_PATHS = new Set(["/v1/admin/activation/finalize", "/v1/admin/activation/provision"]);
const remoteKeySets = new Map<string, JWTVerifyGetKey>();

interface TlsClientAuthView {
  readonly certFingerprintSHA256?: string;
  readonly certPresented?: string;
  readonly certRevoked?: string;
  readonly certVerified?: string;
}

interface RequestCfView {
  readonly tlsClientAuth?: TlsClientAuthView;
}

export interface AdminAuthentication {
  readonly claimsDigest: string;
  readonly expiresAt: number;
  readonly identityNonce: string;
  readonly tokenSha256: string;
}

const ACCESS_MAX_SESSION_SECONDS = 900;

/**
 * Enforces both independent admin factors: a Cloudflare-verified client
 * certificate and a short-lived Cloudflare Access identity JWT. The caller
 * must atomically consume a body-bound replay key before activation RPC.
 */
export async function authenticateAdmin(
  request: Request,
  config: TrustedRuntimeConfig,
  keySet: JWTVerifyGetKey = accessKeySet(config.adminAccessIssuer),
): Promise<AdminAuthentication> {
  assertAdminRequestTarget(request, config);
  assertAdminMtls(request, config);
  assert(request.headers.get("authorization") === null, "ADMIN_GITHUB_OIDC_FORBIDDEN", 404);
  const token = request.headers.get(ACCESS_HEADER);
  assert(
    token !== null && token.length <= 16_384 && /^[A-Za-z0-9._~-]+$/u.test(token),
    "ADMIN_ACCESS_REQUIRED",
    404,
  );
  try {
    const verified = await jwtVerify(token, keySet, {
      algorithms: ["RS256"],
      audience: config.adminAccessAudience,
      clockTolerance: 10,
      issuer: config.adminAccessIssuer,
      maxTokenAge: `${ACCESS_MAX_SESSION_SECONDS}s`,
      requiredClaims: ["aud", "email", "exp", "iat", "identity_nonce", "iss", "nbf", "sub", "type"],
    });
    assert(verified.protectedHeader.alg === "RS256", "ADMIN_ACCESS_DENIED", 404);
    return await validateAccessClaims(verified.payload, config, token);
  } catch (error) {
    if (error instanceof BrokerError) {
      throw error;
    }
    if (error instanceof joseErrors.JOSEError) {
      throw new BrokerError("ADMIN_ACCESS_DENIED", 404, false);
    }
    throw new BrokerError("ADMIN_ACCESS_UNAVAILABLE", 503, true);
  }
}

/** Verifies the mTLS factor from trusted Cloudflare request metadata. */
export function assertAdminMtls(request: Request, config: TrustedRuntimeConfig): void {
  const cf = request.cf as RequestCfView | undefined;
  const tls = cf?.tlsClientAuth;
  assert(
    tls?.certPresented === "1" && tls.certVerified === "SUCCESS" && tls.certRevoked === "0",
    "ADMIN_MTLS_REQUIRED",
    404,
  );
  const fingerprint = tls.certFingerprintSHA256;
  assert(
    fingerprint !== undefined &&
      /^[0-9a-f]{64}$/u.test(fingerprint) &&
      timingSafeEqual(fingerprint, config.adminMtlsCertSha256),
    "ADMIN_MTLS_DENIED",
    404,
  );
}

function assertAdminRequestTarget(request: Request, config: TrustedRuntimeConfig): void {
  const url = new URL(request.url);
  assert(request.method === "POST", "ADMIN_ROUTE_NOT_FOUND", 404);
  assert(url.hostname === config.adminHostname, "ADMIN_ROUTE_NOT_FOUND", 404);
  assert(ADMIN_PATHS.has(url.pathname), "ADMIN_ROUTE_NOT_FOUND", 404);
  assert(url.search === "", "ADMIN_ROUTE_NOT_FOUND", 404);
}

async function validateAccessClaims(
  payload: JWTPayload,
  config: TrustedRuntimeConfig,
  token: string,
): Promise<AdminAuthentication> {
  const audience = claimSingleAudience(payload.aud);
  const email = claimString(payload.email, "ADMIN_ACCESS_IDENTITY_DENIED");
  const subject = claimString(payload.sub, "ADMIN_ACCESS_IDENTITY_DENIED");
  const identityNonce = claimString(payload.identity_nonce, "ADMIN_ACCESS_NONCE_INVALID");
  const issuedAt = claimTime(payload.iat);
  const notBefore = claimTime(payload.nbf);
  const expiresAt = claimTime(payload.exp);
  assert(payload.type === "app", "ADMIN_ACCESS_TOKEN_TYPE_DENIED", 404);
  assert(audience === config.adminAccessAudience, "ADMIN_ACCESS_DENIED", 404);
  assert(email === config.adminAccessIdentity, "ADMIN_ACCESS_IDENTITY_DENIED", 404);
  assert(subject === config.adminAccessSubjectId, "ADMIN_ACCESS_IDENTITY_DENIED", 404);
  assert(
    identityNonce.length >= 16 && identityNonce.length <= 512,
    "ADMIN_ACCESS_NONCE_INVALID",
    404,
  );
  assert(
    notBefore <= issuedAt &&
      issuedAt < expiresAt &&
      expiresAt - issuedAt <= ACCESS_MAX_SESSION_SECONDS,
    "ADMIN_ACCESS_TIME_INVALID",
    404,
  );
  const claims: JsonObject = {
    access_application_id: config.adminAccessApplicationId,
    access_policy_group: config.adminAccessGroup,
    access_policy_id: config.adminAccessPolicyId,
    audience,
    email,
    expires_at: expiresAt,
    issued_at: issuedAt,
    identity_nonce: identityNonce,
    not_before: notBefore,
    subject,
  };
  return {
    claimsDigest: await digestObject(claims),
    expiresAt,
    identityNonce,
    tokenSha256: `sha256:${await sha256Hex(token)}`,
  };
}

export async function adminReplayKey(input: {
  readonly authentication: AdminAuthentication;
  readonly canonicalBody: string;
  readonly method: string;
  readonly path: string;
  readonly requestId: string;
}): Promise<string> {
  const bodySha256 = `sha256:${await sha256Hex(input.canonicalBody)}`;
  return digestObject({
    body_sha256: bodySha256,
    domain: "dpone.release-broker.admin-request-replay.v1",
    method: input.method,
    path: input.path,
    request_id: input.requestId,
    token_sha256: input.authentication.tokenSha256,
  });
}

function accessKeySet(issuer: string): JWTVerifyGetKey {
  const existing = remoteKeySets.get(issuer);
  if (existing !== undefined) {
    return existing;
  }
  const created = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`), {
    cacheMaxAge: 10 * 60 * 1000,
    cooldownDuration: 30 * 1000,
    timeoutDuration: 5 * 1000,
  });
  remoteKeySets.set(issuer, created);
  return created;
}

function claimSingleAudience(value: unknown): string {
  assert(
    Array.isArray(value) && value.length === 1 && typeof value[0] === "string",
    "ADMIN_ACCESS_DENIED",
    404,
  );
  return value[0];
}

function claimString(value: unknown, code: string): string {
  assert(typeof value === "string" && value.length > 0 && value.length <= 512, code, 404);
  return value;
}

function claimTime(value: unknown): number {
  assert(
    typeof value === "number" && Number.isSafeInteger(value) && value > 0,
    "ADMIN_ACCESS_TIME_INVALID",
    404,
  );
  return value;
}
