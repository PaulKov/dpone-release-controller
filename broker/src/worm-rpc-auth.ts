import { canonicalBytes } from "./canonical";
import { CLOUDFLARE_UUID } from "./cloudflare-ids";
import { assert, BrokerError } from "./errors";

const AUTH_SCHEMA = "dpone.release-worm-rpc-auth.v1";
const CLOUDFLARE_OBSERVER_AUTH_SCHEMA = "dpone.release-cloudflare-observer-rpc-auth.v1";
export const CLOUDFLARE_OBSERVER_RPC_PATH_V1 = "/rpc/v1/cloudflare/deployments/observe" as const;
export const CLOUDFLARE_OBSERVER_RPC_PATH_V2 = "/rpc/v2/cloudflare/deployments/observe" as const;
const AUTH_KEY = /^[A-Za-z0-9_-]{43}$/u;
const IDENTITY =
  /^cloudflare-worker:[0-9a-f]{32}[/][A-Za-z0-9][A-Za-z0-9._-]{1,127}@[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;
const VERSION = CLOUDFLARE_UUID;
const MAC = /^hmac-sha256:[0-9a-f]{64}$/u;
const SIGNED_HEADERS = [
  "content-length",
  "content-type",
  "x-dpone-batch-id",
  "x-dpone-callee-service",
  "x-dpone-callee-service-identity",
  "x-dpone-callee-version",
  "x-dpone-canonical-sha256",
  "x-dpone-cloudflare-observer-worker-version",
  "x-dpone-committed-at",
  "x-dpone-evidence-kind",
  "x-dpone-effect-id",
  "x-dpone-generation",
  "x-dpone-ingress-worker-version",
  "x-dpone-observer-service",
  "x-dpone-observer-service-identity",
  "x-dpone-observer-version",
  "x-dpone-object-key",
  "x-dpone-record-id",
  "x-dpone-sanitized-record-sha256",
  "x-dpone-sequence",
  "x-request-id",
] as const;

export type WormRpcPath =
  | "/rpc/v1/activation"
  | "/rpc/v1/activation-head"
  | "/rpc/v1/activation-evidence"
  | "/rpc/v1/cloudflare-evidence"
  | "/rpc/v1/cloudflare-evidence/absence"
  | "/rpc/v1/cloudflare-evidence/batch"
  | "/rpc/v1/cloudflare-evidence/reconcile"
  | "/rpc/v1/exact-object-effect"
  | "/rpc/v2/cloudflare-evidence/batch"
  | "/rpc/v2/cloudflare-evidence/batch/resume";

export interface WormRpcCallerAuth {
  readonly key: string;
  readonly serviceIdentity: string;
  readonly versionId: string;
}

export type CloudflareObserverRpcPath =
  | typeof CLOUDFLARE_OBSERVER_RPC_PATH_V1
  | typeof CLOUDFLARE_OBSERVER_RPC_PATH_V2;

/** Add a version-bound HMAC capability after every security-relevant header is final. */
export async function signWormRpcRequest(
  headers: Headers,
  path: WormRpcPath,
  caller: WormRpcCallerAuth,
): Promise<void> {
  const versionHeader = isCloudflareEvidencePath(path)
    ? "x-dpone-cloudflare-observer-worker-version"
    : "x-dpone-ingress-worker-version";
  await signVersionBoundRpcRequest(headers, path, AUTH_SCHEMA, versionHeader, caller);
}

/** Sign the ingress-to-observer read RPC with its cryptographically isolated key. */
export async function signCloudflareObserverRpcRequest(
  headers: Headers,
  caller: WormRpcCallerAuth,
  path: CloudflareObserverRpcPath = CLOUDFLARE_OBSERVER_RPC_PATH_V1,
): Promise<void> {
  await signVersionBoundRpcRequest(
    headers,
    path,
    CLOUDFLARE_OBSERVER_AUTH_SCHEMA,
    "x-dpone-ingress-worker-version",
    caller,
  );
}

/** Verify the configured caller identity/version and HMAC before any B2 operation. */
export async function verifyWormRpcRequest(
  headers: Headers,
  path: WormRpcPath,
  key: string | undefined,
  expectedCallerIdentity: string | undefined,
): Promise<void> {
  const versionHeader = isCloudflareEvidencePath(path)
    ? "x-dpone-cloudflare-observer-worker-version"
    : "x-dpone-ingress-worker-version";
  await verifyVersionBoundRpcRequest(
    headers,
    path,
    AUTH_SCHEMA,
    versionHeader,
    key,
    expectedCallerIdentity,
    "WORM_RPC_AUTH_INVALID",
  );
}

function isCloudflareEvidencePath(path: WormRpcPath): boolean {
  return /^\/rpc\/v[12]\/cloudflare-evidence(?:\/|$)/u.test(path);
}

/** Verify the exact ingress identity/version before the observer reads provider state. */
export async function verifyCloudflareObserverRpcRequest(
  headers: Headers,
  key: string | undefined,
  expectedCallerIdentity: string | undefined,
  path: CloudflareObserverRpcPath = CLOUDFLARE_OBSERVER_RPC_PATH_V1,
): Promise<void> {
  await verifyVersionBoundRpcRequest(
    headers,
    path,
    CLOUDFLARE_OBSERVER_AUTH_SCHEMA,
    "x-dpone-ingress-worker-version",
    key,
    expectedCallerIdentity,
    "CLOUDFLARE_OBSERVER_RPC_AUTH_INVALID",
  );
}

export function validateWormRpcAuthKey(value: string | undefined): string {
  if (value === undefined || !AUTH_KEY.test(value)) {
    throw new BrokerError("WORM_RPC_AUTH_CONFIGURATION_INVALID", 503, false);
  }
  const decoded = decodeBase64url(value);
  if (decoded.byteLength !== 32 || encodeBase64url(decoded) !== value) {
    throw new BrokerError("WORM_RPC_AUTH_CONFIGURATION_INVALID", 503, false);
  }
  return value;
}

function authPayload(headers: Headers, path: string, schema: string) {
  return {
    caller_service_identity: headers.get("x-dpone-rpc-caller-service-identity"),
    caller_version_id: headers.get("x-dpone-rpc-caller-version"),
    headers: Object.fromEntries(SIGNED_HEADERS.map((name) => [name, headers.get(name)])),
    method: "POST",
    path,
    schema,
    schema_version: 1,
  };
}

async function signVersionBoundRpcRequest(
  headers: Headers,
  path: string,
  schema: string,
  versionHeader: string,
  caller: WormRpcCallerAuth,
): Promise<void> {
  validateCaller(caller);
  assert(headers.get(versionHeader) === caller.versionId, "WORM_RPC_CALLER_VERSION_MISMATCH", 500);
  headers.set("x-dpone-rpc-auth-schema", schema);
  headers.set("x-dpone-rpc-caller-service-identity", caller.serviceIdentity);
  headers.set("x-dpone-rpc-caller-version", caller.versionId);
  const signature = await crypto.subtle.sign(
    "HMAC",
    await importAuthKey(caller.key, ["sign"]),
    Uint8Array.from(canonicalBytes(authPayload(headers, path, schema))).buffer,
  );
  headers.set("x-dpone-rpc-auth-mac", `hmac-sha256:${hex(new Uint8Array(signature))}`);
}

async function verifyVersionBoundRpcRequest(
  headers: Headers,
  path: string,
  schema: string,
  versionHeader: string,
  key: string | undefined,
  expectedCallerIdentity: string | undefined,
  errorCode: string,
): Promise<void> {
  const expected = validateExpectedCaller(key, expectedCallerIdentity);
  if (
    headers.get("x-dpone-rpc-auth-schema") !== schema ||
    headers.get("x-dpone-rpc-caller-service-identity") !== expected.serviceIdentity ||
    headers.get("x-dpone-rpc-caller-version") !== expected.versionId ||
    headers.get(versionHeader) !== expected.versionId
  ) {
    throw new BrokerError(errorCode, 503, false);
  }
  const taggedMac = headers.get("x-dpone-rpc-auth-mac");
  if (taggedMac === null || !MAC.test(taggedMac)) {
    throw new BrokerError(errorCode, 503, false);
  }
  const verified = await crypto.subtle.verify(
    "HMAC",
    await importAuthKey(expected.key, ["verify"]),
    Uint8Array.from(bytesFromHex(taggedMac.slice("hmac-sha256:".length))).buffer,
    Uint8Array.from(canonicalBytes(authPayload(headers, path, schema))).buffer,
  );
  if (!verified) throw new BrokerError(errorCode, 503, false);
}

function validateCaller(caller: WormRpcCallerAuth): void {
  validateWormRpcAuthKey(caller.key);
  assert(IDENTITY.test(caller.serviceIdentity), "WORM_RPC_CALLER_IDENTITY_INVALID", 500);
  assert(VERSION.test(caller.versionId), "WORM_RPC_CALLER_VERSION_INVALID", 500);
  assert(
    caller.serviceIdentity.endsWith(`@${caller.versionId}`),
    "WORM_RPC_CALLER_IDENTITY_INVALID",
    500,
  );
}

function validateExpectedCaller(
  key: string | undefined,
  serviceIdentity: string | undefined,
): WormRpcCallerAuth {
  const validatedKey = validateWormRpcAuthKey(key);
  if (serviceIdentity === undefined || !IDENTITY.test(serviceIdentity)) {
    throw new BrokerError("WORM_RPC_AUTH_CONFIGURATION_INVALID", 503, false);
  }
  const separator = serviceIdentity.lastIndexOf("@");
  const versionId = serviceIdentity.slice(separator + 1);
  if (!VERSION.test(versionId)) {
    throw new BrokerError("WORM_RPC_AUTH_CONFIGURATION_INVALID", 503, false);
  }
  return { key: validatedKey, serviceIdentity, versionId };
}

async function importAuthKey(value: string, usages: ("sign" | "verify")[]): Promise<CryptoKey> {
  validateWormRpcAuthKey(value);
  return crypto.subtle.importKey(
    "raw",
    Uint8Array.from(decodeBase64url(value)).buffer,
    { hash: "SHA-256", name: "HMAC" },
    false,
    usages,
  );
}

function decodeBase64url(value: string): Uint8Array {
  let binary: string;
  try {
    binary = atob(
      value
        .replaceAll("-", "+")
        .replaceAll("_", "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "="),
    );
  } catch {
    throw new BrokerError("WORM_RPC_AUTH_CONFIGURATION_INVALID", 503, false);
  }
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function bytesFromHex(value: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/u.test(value)) {
    throw new BrokerError("WORM_RPC_AUTH_INVALID", 503, false);
  }
  return Uint8Array.from(value.match(/.{2}/gu) ?? [], (pair) => Number.parseInt(pair, 16));
}
