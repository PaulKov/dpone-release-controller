import { INTERNAL_RESPONSE_READ_POLICY, readBoundedBytes } from "../bounded";
import { sha256Hex } from "../canonical";
import { BrokerError } from "../errors";
import type { JsonObject, JsonValue } from "../types";

export type ProviderFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

const API_VERSION = "2026-03-10";
const API_ORIGIN = "https://api.github.com";
const PROVIDER_TIMEOUT_MS = 15_000;

/**
 * Executes one fixed GitHub API request without following redirects and with a
 * hard wall-clock deadline. Callers construct paths from already validated
 * integers and compile-time repository names; this helper never accepts a URL.
 */
export async function githubRequest(
  providerFetch: ProviderFetch,
  input: {
    readonly authorization: string;
    readonly body?: string;
    readonly method: "GET" | "POST";
    readonly path: `/${string}`;
  },
): Promise<Response> {
  return githubRequestWithRedirectPolicy(providerFetch, input, "error");
}

/** Exact GitHub API request used only to capture a documented signed redirect. */
export async function githubRedirectRequest(
  providerFetch: ProviderFetch,
  input: {
    readonly authorization: string;
    readonly method: "GET";
    readonly path: `/${string}`;
  },
): Promise<Response> {
  return githubRequestWithRedirectPolicy(providerFetch, input, "manual");
}

async function githubRequestWithRedirectPolicy(
  providerFetch: ProviderFetch,
  input: {
    readonly authorization: string;
    readonly body?: string;
    readonly method: "GET" | "POST";
    readonly path: `/${string}`;
  },
  redirect: "error" | "manual",
): Promise<Response> {
  const pathname = input.path.split("?", 1)[0] ?? "";
  const traversal = pathname
    .split("/")
    .some((segment) => segment === "." || segment === ".." || /%2e/iu.test(segment));
  if (
    !input.path.startsWith("/") ||
    input.path.startsWith("//") ||
    input.path.includes("\\") ||
    input.path.includes("#") ||
    /[\r\n\0]/u.test(input.path) ||
    input.path.length > 2048 ||
    traversal
  ) {
    throw new BrokerError("GITHUB_PROVIDER_PATH_INVALID", 500, false);
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), PROVIDER_TIMEOUT_MS);
  try {
    return await providerFetch(`${API_ORIGIN}${input.path}`, {
      ...(input.body === undefined ? {} : { body: input.body }),
      headers: {
        accept: "application/vnd.github+json",
        authorization: input.authorization,
        ...(input.body === undefined ? {} : { "content-type": "application/json" }),
        "user-agent": "dpone-release-authority-broker/1",
        "x-github-api-version": API_VERSION,
      },
      method: input.method,
      redirect,
      signal: controller.signal,
    });
  } catch {
    throw new BrokerError("GITHUB_PROVIDER_UNAVAILABLE", 503, true);
  } finally {
    clearTimeout(timeout);
  }
}

export async function requireGitHubOk(response: Response, code: string): Promise<void> {
  if (!response.ok) {
    await response.body?.cancel(code).catch(() => undefined);
    throw new BrokerError(code, 503, response.status === 429 || response.status >= 500);
  }
}

/**
 * Enforces the closed transport envelope for authority-bearing GitHub JSON.
 *
 * Platform metadata headers are tolerated, but redirects, cookies, byte
 * ranges, transfer framing, and content transformations are never part of a
 * provider observation. The body is canceled before any rejection.
 */
export async function requireExactGitHubJsonResponse(
  response: Response,
  expectedStatus: number,
  code: string,
): Promise<void> {
  const mediaType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (
    response.status !== expectedStatus ||
    mediaType !== "application/json" ||
    response.headers.has("content-encoding") ||
    response.headers.has("content-range") ||
    response.headers.has("location") ||
    response.headers.has("set-cookie") ||
    response.headers.has("transfer-encoding")
  ) {
    await response.body?.cancel(code).catch(() => undefined);
    throw new BrokerError(code, 503, false);
  }
}

export async function githubJson(
  response: Response,
  maximumBytes: number,
  code: string,
  expectedStatus = 200,
): Promise<JsonObject> {
  return (await githubJsonWithDigest(response, maximumBytes, code, expectedStatus)).value;
}

/** Parse bounded provider JSON while retaining only a digest of exact raw bytes. */
export async function githubJsonWithDigest(
  response: Response,
  maximumBytes: number,
  code: string,
  expectedStatus = 200,
): Promise<{ readonly providerResponseSha256: string; readonly value: JsonObject }> {
  await requireExactGitHubJsonResponse(response, expectedStatus, code);
  const bytes = await readBoundedBytes(response, maximumBytes, code, INTERNAL_RESPONSE_READ_POLICY);
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch {
    throw new BrokerError(code, 503, false);
  }
  return {
    providerResponseSha256: `sha256:${await sha256Hex(bytes)}`,
    value: providerObject(value, code),
  };
}

export function providerObject(value: unknown, code: string): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError(code, 503, false);
  }
  return value as JsonObject;
}

export function providerArray(object: JsonObject, key: string, code: string): JsonValue[] {
  const value = object[key];
  if (!Array.isArray(value)) {
    throw new BrokerError(code, 503, false);
  }
  return value;
}

export function providerString(
  object: JsonObject,
  key: string,
  maximum: number,
  code: string,
): string {
  const value = object[key];
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    throw new BrokerError(code, 503, false);
  }
  return value;
}

export function providerInteger(object: JsonObject, key: string, code: string): number {
  const value = object[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new BrokerError(code, 503, false);
  }
  return value;
}

export function providerNullableString(
  object: JsonObject,
  key: string,
  maximum: number,
  code: string,
): string | null {
  const value = object[key];
  if (value === null) return null;
  return providerString(object, key, maximum, code);
}

export function requireProviderLiteral(
  object: JsonObject,
  key: string,
  expected: JsonValue,
  code: string,
): void {
  if (object[key] !== expected) {
    throw new BrokerError(code, 503, false);
  }
}
