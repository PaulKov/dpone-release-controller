import { INTERNAL_RESPONSE_READ_POLICY, readBoundedBytes } from "../bounded";
import { canonicalBytes } from "../canonical";
import { LIMITS } from "../config";
import { BrokerError } from "../errors";
import type { JsonObject } from "../types";

export const PROVIDER_JSON_LIMIT = 65_536;
const PROVIDER_TIMEOUT_MS = 15_000;

export interface B2NativeConfig {
  readonly applicationKey: string;
  readonly bucketId: string;
  readonly bucketName: string;
  readonly keyId: string;
  readonly prefix: string;
}

export interface B2Session {
  readonly accountId: string;
  readonly apiUrl: string;
  readonly authorizationEvidence: JsonObject;
  readonly authorizationToken: string;
  readonly downloadUrl: string;
}

export type ProviderFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export async function authorizedPost(
  providerFetch: ProviderFetch,
  session: B2Session,
  operation: string,
  body: JsonObject,
): Promise<Response> {
  const bytes = canonicalBytes(body);
  const response = await safeFetch(
    providerFetch,
    `${session.apiUrl}/b2api/v4/${operation}`,
    {
      body: Uint8Array.from(bytes).buffer,
      headers: {
        authorization: session.authorizationToken,
        "content-length": String(bytes.byteLength),
        "content-type": "application/json",
      },
      method: "POST",
      redirect: "error",
    },
    "B2_PROVIDER_UNAVAILABLE",
  );
  await requireProviderOk(response, "B2_PROVIDER_OPERATION_FAILED");
  return response;
}

export async function safeFetch(
  providerFetch: ProviderFetch,
  input: RequestInfo | URL,
  init: RequestInit,
  code: string,
): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), PROVIDER_TIMEOUT_MS);
  try {
    return await providerFetch(input, { ...init, signal: controller.signal });
  } catch {
    throw new BrokerError(code, 503, true);
  } finally {
    clearTimeout(timeout);
  }
}

export async function providerJson(
  response: Response,
  limit: number,
  code: string,
): Promise<JsonObject> {
  return (await providerJsonCapture(response, limit, code)).value;
}

export async function providerJsonCapture(
  response: Response,
  limit: number,
  code: string,
): Promise<{ readonly bytes: Uint8Array; readonly value: JsonObject }> {
  const mediaType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") {
    await response.body?.cancel(`${code}_CONTENT_TYPE_INVALID`).catch(() => undefined);
    throw new BrokerError(`${code}_CONTENT_TYPE_INVALID`, 503, false);
  }
  const bytes = await readBoundedBytes(
    response,
    limit,
    `${code}_TOO_LARGE`,
    INTERNAL_RESPONSE_READ_POLICY,
  );
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new BrokerError(code, 503, false);
  }
  return { bytes, value: providerObject(value, code) };
}

export async function requireProviderOk(response: Response, code: string): Promise<void> {
  if (!response.ok) {
    await response.body?.cancel(code).catch(() => undefined);
    throw new BrokerError(code, 503, response.status === 429 || response.status >= 500);
  }
}

export function validateConfig(config: B2NativeConfig): void {
  if (
    !/^[0-9a-f]{24}$/u.test(config.bucketId) ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{5,127}$/u.test(config.bucketName) ||
    !/^[A-Za-z0-9]{16,64}$/u.test(config.keyId) ||
    config.applicationKey.length < 16 ||
    config.applicationKey.length > 256 ||
    config.prefix !== "receipts/v1/"
  ) {
    throw new BrokerError("B2_CONFIGURATION_INVALID", 503, false);
  }
}

export function validateObjectInput(
  input: {
    readonly canonicalBytes: Uint8Array;
    readonly contentSha1: string;
    readonly digest: string;
    readonly key: string;
  },
  prefix: string,
): void {
  validateObjectKey(input.key, prefix);
  if (
    input.canonicalBytes.byteLength < 1 ||
    input.canonicalBytes.byteLength > LIMITS.bodyBytes ||
    !/^[0-9a-f]{40}$/u.test(input.contentSha1) ||
    !/^sha256:[0-9a-f]{64}$/u.test(input.digest)
  ) {
    throw new BrokerError("B2_OBJECT_INPUT_INVALID", 500, false);
  }
}

export function validateObjectKey(key: string, prefix: string): void {
  if (
    key.length > 512 ||
    !key.startsWith(prefix) ||
    !/^receipts\/v1\/(?:(?:activation\/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\/[01]-[0-9a-f]{64}|activation-evidence\/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\/[a-z][a-z0-9_]{2,63}\/[0-9a-f]{64}|cloudflare-observations\/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\/(?:cloudflare_network_surface|cloudflare_service_deployments)\/[0-9a-f]{64}|cloudflare-observations-v2\/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\/[0-9a-f]{64}\/(?:cloudflare_network_surface|cloudflare_service_deployments)\/[0-9a-f]{64})|[0-9]+\/v[0-9]+\.[0-9]+\.[0-9]+\/[0-9a-f]{64}\/[0-9]{12}-[0-9a-f]{64})\.json$/u.test(
      key,
    )
  ) {
    throw new BrokerError("B2_OBJECT_KEY_INVALID", 500, false);
  }
}

export function providerBaseUrl(value: string, kind: "api" | "download"): string {
  const url = parseProviderUrl(value);
  const hostPattern =
    kind === "api" ? /^api[0-9]{1,6}\.backblazeb2\.com$/u : /^f[0-9]{1,6}\.backblazeb2\.com$/u;
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.port !== "" ||
    url.pathname !== "/" ||
    !hostPattern.test(url.hostname)
  ) {
    throw new BrokerError("B2_PROVIDER_URL_INVALID", 503, false);
  }
  return url.origin;
}

export function providerUploadUrl(value: string, bucketId: string): string {
  const url = parseProviderUrl(value);
  const queryEntries = [...url.searchParams.entries()];
  const queryKeys = queryEntries.map(([key]) => key).sort();
  const queryCvt = url.searchParams.get("cvt");
  const pathMatch =
    /^\/b2api\/v4\/b2_upload_file\/([0-9a-f]{24})\/([A-Za-z0-9._~-]{16,2048})$/u.exec(url.pathname);
  const queryForm =
    url.pathname === "/b2api/v4/b2_upload_file" &&
    queryEntries.length === 2 &&
    queryKeys[0] === "bucket" &&
    queryKeys[1] === "cvt" &&
    url.searchParams.get("bucket") === bucketId &&
    queryCvt !== null &&
    /^[A-Za-z0-9._~-]{16,2048}$/u.test(queryCvt) &&
    !url.search.includes("%");
  const pathForm = url.search === "" && pathMatch?.[1] === bucketId && pathMatch[2] !== undefined;
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== "" ||
    url.port !== "" ||
    !/^pod-[a-z0-9-]{3,96}\.backblaze\.com$/u.test(url.hostname) ||
    (!queryForm && !pathForm)
  ) {
    throw new BrokerError("B2_PROVIDER_URL_INVALID", 503, false);
  }
  return value;
}

function parseProviderUrl(value: string): URL {
  try {
    return new URL(value);
  } catch {
    throw new BrokerError("B2_PROVIDER_URL_INVALID", 503, false);
  }
}

export function providerObject(value: unknown, code: string): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError(code, 503, false);
  }
  return value as JsonObject;
}

export function objectField(parent: JsonObject, key: string, code: string): JsonObject {
  return providerObject(parent[key], code);
}

export function authorizedValue(parent: JsonObject, key: string, code: string): JsonObject {
  const wrapper = objectField(parent, key, code);
  if (wrapper.isClientAuthorizedToRead !== true) {
    throw new BrokerError(code, 503, false);
  }
  return objectField(wrapper, "value", code);
}

export function requireExactSseB2(parent: JsonObject, code: string): void {
  const encryption = objectField(parent, "serverSideEncryption", code);
  requireLiteral(encryption, "algorithm", "AES256", code);
  requireLiteral(encryption, "mode", "SSE-B2", code);
}

export function stringField(parent: JsonObject, key: string, maximum: number): string {
  const value = parent[key];
  if (typeof value !== "string" || value.length < 1 || value.length > maximum) {
    throw new BrokerError("B2_PROVIDER_RESPONSE_INVALID", 503, false);
  }
  return value;
}

export function patternString(
  parent: JsonObject,
  key: string,
  pattern: RegExp,
  maximum: number,
): string {
  const value = stringField(parent, key, maximum);
  if (!pattern.test(value)) {
    throw new BrokerError("B2_PROVIDER_RESPONSE_INVALID", 503, false);
  }
  return value;
}

export function integerField(parent: JsonObject, key: string): number {
  const value = parent[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new BrokerError("B2_PROVIDER_RESPONSE_INVALID", 503, false);
  }
  return value;
}

export function booleanField(parent: JsonObject, key: string): boolean {
  const value = parent[key];
  if (typeof value !== "boolean") {
    throw new BrokerError("B2_PROVIDER_RESPONSE_INVALID", 503, false);
  }
  return value;
}

export function arrayField(parent: JsonObject, key: string, code: string): JsonObject["x"][] {
  const value = parent[key];
  if (!Array.isArray(value)) {
    throw new BrokerError(code, 503, false);
  }
  return value;
}

export function stringArrayField(parent: JsonObject, key: string, code: string): string[] {
  const value = arrayField(parent, key, code);
  if (!value.every((item) => typeof item === "string")) {
    throw new BrokerError(code, 503, false);
  }
  return value;
}

export function requireLiteral(
  parent: JsonObject,
  key: string,
  expected: string,
  code: string,
): void {
  if (stringField(parent, key, Math.max(1, expected.length)) !== expected) {
    throw new BrokerError(code, 503, false);
  }
}

export function requireLiteralHeader(headers: Headers, key: string, expected: string): void {
  if (headers.get(key) !== expected) {
    throw new BrokerError("B2_DOWNLOAD_BINDING_INVALID", 503, false);
  }
}

export function sameSet(actual: readonly string[], expected: readonly string[]): boolean {
  return (
    new Set(actual).size === actual.length &&
    [...actual].sort().join("\n") === [...expected].sort().join("\n")
  );
}

export async function sha1Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", Uint8Array.from(bytes).buffer);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}
