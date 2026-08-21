import { canonicalJson, digestObject } from "./canonical";
import {
  DIGEST,
  PROVIDER_REQUEST_ID,
  REQUEST_ID,
  TIMESTAMP,
  type CloudflareDeploymentObservationRequest,
  type DeploymentProjection,
  type SanitizedCloudflareEvidence,
} from "./cloudflare-deployment-observation-contract";
import { assert, BrokerError } from "./errors";
import {
  parseExpectedCloudflareNetworkSurface,
  parseExpectedServiceDeployments,
} from "./service-authority";
import type { JsonObject, JsonValue } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export function deploymentJson(value: DeploymentProjection): JsonObject {
  return {
    annotations: value.annotations,
    author_email: value.author_email,
    created_on: value.created_on,
    id: value.id,
    source: value.source,
    strategy: value.strategy,
    versions: value.versions.map((member) => ({ ...member })),
  };
}

export function parseAnnotations(value: JsonValue | undefined): JsonObject | null {
  if (value === undefined) return null;
  const annotations = requireAllowedObject(
    value,
    ["workers/message", "workers/triggered_by"],
    [],
    "CLOUDFLARE_DEPLOYMENT_ANNOTATIONS_INVALID",
  );
  for (const key of Object.keys(annotations)) requireString(annotations, key, 1000);
  return annotations;
}

export function requireAllowedObject(
  value: unknown,
  allowed: readonly string[],
  required: readonly string[],
  code: string,
): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError(code, 503, false);
  }
  const object = value as JsonObject;
  const allowedSet = new Set(allowed);
  if (
    Object.keys(object).some((key) => !allowedSet.has(key)) ||
    required.some((key) => !Object.hasOwn(object, key))
  ) {
    throw new BrokerError(code, 503, false);
  }
  return object;
}

export function requireTimestamp(object: JsonObject, key: string): string {
  const value = requireString(object, key, 40, TIMESTAMP);
  if (!Number.isFinite(Date.parse(value))) {
    throw new BrokerError("CLOUDFLARE_PROVIDER_TIMESTAMP_INVALID", 503, false);
  }
  return value;
}

export function optionalAsciiString(
  object: JsonObject,
  key: string,
  maximum: number,
): string | null {
  if (!Object.hasOwn(object, key)) return null;
  return requireString(object, key, maximum, /^[\x20-\x7e]+$/u);
}

export function compareWorkerVersion(left: JsonObject, right: JsonObject): number {
  const leftId = requireString(left, "worker_version_id", 128);
  const rightId = requireString(right, "worker_version_id", 128);
  return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
}

export function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function decodeBase64(value: string): Uint8Array {
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_BASE64_INVALID", 500, false);
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBase64(bytes) !== value) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_BASE64_INVALID", 500, false);
  }
  return bytes;
}

export function sanitizeProviderCalls(value: JsonValue | undefined): JsonValue[] {
  if (!Array.isArray(value)) {
    throw new BrokerError("CLOUDFLARE_EVIDENCE_CALLS_INVALID", 500, false);
  }
  return value.map((candidate) => {
    const row = requireJsonObject(candidate);
    const providerRequestId = row.provider_request_id;
    if (providerRequestId !== null) {
      requireString(row, "provider_request_id", 128, PROVIDER_REQUEST_ID);
    }
    return {
      content_type: requireString(row, "content_type", 32),
      operation: requireString(row, "operation", 32),
      provider_request_id: providerRequestId ?? null,
      raw_response_sha256: requireString(row, "raw_response_sha256", 71, DIGEST),
      request_path: requireString(row, "request_path", 512),
      status: requireInteger(row, "status", 200, 200),
    };
  });
}

export function sanitizePersistedProviderCalls(value: JsonValue | undefined): JsonValue[] {
  if (!Array.isArray(value)) {
    throw new BrokerError("CLOUDFLARE_SANITIZED_EVIDENCE_CALLS_INVALID", 500, false);
  }
  return value.map((candidate) => {
    const row = exactObject(candidate, [
      "content_type",
      "operation",
      "provider_request_id",
      "raw_response_sha256",
      "request_path",
      "status",
    ]);
    requireLiteral(row, "content_type", "application/json");
    requireExactInteger(row, "status", 200);
    if (row.provider_request_id !== null) {
      requireString(row, "provider_request_id", 128, PROVIDER_REQUEST_ID);
    }
    requireString(row, "operation", 32);
    requireString(row, "raw_response_sha256", 71, DIGEST);
    requireString(
      row,
      "request_path",
      512,
      /^\/client\/v4\/(?:accounts|zones)\/[A-Za-z0-9/._-]+$/u,
    );
    return row;
  });
}

export async function finalizeSanitizedRecord(
  withoutId: JsonObject,
): Promise<SanitizedCloudflareEvidence> {
  const recordId = await digestObject(withoutId);
  const record: JsonObject = { ...withoutId, record_id: recordId };
  const recordSha256 = await digestObject(record);
  const text = canonicalJson(record);
  assertSanitizedText(text);
  return { record, recordId, recordSha256 };
}

export function assertSanitizedText(text: string): void {
  for (const forbidden of [
    "raw_body_base64",
    "author_email",
    "author_id",
    "authorization",
    "cookie",
    "operator+secret@example",
  ]) {
    if (text.toLowerCase().includes(forbidden)) {
      throw new BrokerError("CLOUDFLARE_SANITIZED_EVIDENCE_SECRET_BOUNDARY", 500, false);
    }
  }
}

export function canonicalUtcMilliseconds(value: number): string {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_TIME_INVALID", 500, false);
  }
  return new Date(value).toISOString();
}

export function validateRequest(request: CloudflareDeploymentObservationRequest): void {
  assert(DIGEST.test(request.expectationSha256), "CLOUDFLARE_DEPLOYMENT_REQUEST_INVALID");
  assert(REQUEST_ID.test(request.requestId), "CLOUDFLARE_DEPLOYMENT_REQUEST_INVALID");
  parseExpectedServiceDeployments(request.expectedDeployments, request.phase);
  parseExpectedCloudflareNetworkSurface(request.expectedNetworkSurface);
}

export async function mapConcurrent<T, R>(
  values: readonly T[],
  concurrency: number,
  callback: (value: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(values.length);
  let next = 0;
  async function worker(): Promise<void> {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= values.length) return;
      const value = values[index];
      if (value === undefined) return;
      results[index] = await callback(value);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, values.length) }, worker));
  return results;
}

export function assertUnique(values: readonly string[], code: string): void {
  assert(new Set(values).size === values.length, code, 503);
}

export function requireJsonObject(value: JsonValue | undefined): JsonObject {
  if (value === null || value === undefined || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_OBSERVATION_INVALID", 500, false);
  }
  return value;
}

export function requireJsonArray(value: JsonValue | undefined): readonly JsonValue[] {
  if (!Array.isArray(value)) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_INVENTORY_MISMATCH", 503, false);
  }
  return value;
}

export function isJsonObject(value: JsonValue | undefined): value is JsonObject {
  return (
    value !== null && value !== undefined && typeof value === "object" && !Array.isArray(value)
  );
}

export function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(requireString(object, key, expected.length) === expected, "CLOUDFLARE_CONTRACT_INVALID");
}

export function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "CLOUDFLARE_CONTRACT_INVALID",
  );
}
