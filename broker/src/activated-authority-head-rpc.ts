import { parseHeadReadRequest } from "./activated-authority-head-proof";
import { activationSnapshotJson, parseActivationSnapshotCanonical } from "./activation-rpc";
import { canonicalJson } from "./canonical";
import { LIMITS } from "./config";
import { assert, BrokerError } from "./errors";
import type { ActivationSnapshot, JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export const ACTIVATED_AUTHORITY_HEAD_ADVANCE_REQUEST_SCHEMA =
  "dpone.activated-service-authority-head-advance-request.v1" as const;

const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;
const MAX_ADVANCE_BYTES = 2 * LIMITS.bodyBytes + 8192;

export interface HeadAdvanceRequest {
  readonly body: JsonObject;
  readonly requestId: string;
  readonly requestedAt: string;
  readonly snapshot: ActivationSnapshot;
}

export function buildHeadAdvanceRequestCanonical(
  snapshot: ActivationSnapshot,
  requestId: string,
  requestedAt: string,
): string {
  const body: JsonObject = {
    request_id: requestId,
    requested_at: requestedAt,
    schema: ACTIVATED_AUTHORITY_HEAD_ADVANCE_REQUEST_SCHEMA,
    schema_version: 1,
    snapshot: activationSnapshotJson(snapshot),
  };
  const text = canonicalJson(body);
  parseHeadAdvanceRequestCanonical(text);
  return text;
}

/** Decode one exact A0+A1 snapshot advance request before any provider read. */
export function parseHeadAdvanceRequestCanonical(text: string): HeadAdvanceRequest {
  const body = decodeCanonical(text, MAX_ADVANCE_BYTES, "ACTIVATED_AUTHORITY_HEAD_ADVANCE_INVALID");
  const request = exactObject(body, [
    "request_id",
    "requested_at",
    "schema",
    "schema_version",
    "snapshot",
  ]);
  literal(request, "schema", ACTIVATED_AUTHORITY_HEAD_ADVANCE_REQUEST_SCHEMA);
  exactInteger(request, "schema_version", 1);
  const requestId = requireString(request, "request_id", 128, REQUEST_ID);
  const requestedAt = requireString(request, "requested_at", 32, TIMESTAMP);
  const snapshotObject = exactObject(request.snapshot, [
    "activated",
    "provisioned",
    "schema",
    "schema_version",
  ]);
  const snapshot = parseActivationSnapshotCanonical(canonicalJson(snapshotObject));
  assert(
    snapshot !== null && snapshot.activated !== null,
    "ACTIVATED_AUTHORITY_HEAD_ADVANCE_INVALID",
    409,
  );
  return { body, requestId, requestedAt, snapshot };
}

export function parseHeadReadRequestCanonical(text: string): JsonObject {
  const body = decodeCanonical(text, LIMITS.bodyBytes, "ACTIVATED_AUTHORITY_HEAD_READ_INVALID");
  return parseHeadReadRequest(body);
}

export function assertFreshHeadRequest(requestedAt: string, nowMs: number): void {
  const requested = Date.parse(requestedAt);
  assert(
    Number.isFinite(requested) &&
      requested <= nowMs + 30_000 &&
      nowMs - requested >= -30_000 &&
      nowMs - requested <= 60_000,
    "ACTIVATED_AUTHORITY_HEAD_REQUEST_STALE",
    409,
  );
}

function decodeCanonical(text: string, maximum: number, code: string): JsonObject {
  const bytes = new TextEncoder().encode(text);
  if (bytes.byteLength === 0 || bytes.byteLength > maximum) {
    throw new BrokerError(`${code}_SIZE`, 413, false);
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(text);
  } catch {
    throw new BrokerError(code, 400, false);
  }
  if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) {
    throw new BrokerError(code, 400, false);
  }
  const body = decoded as JsonObject;
  assert(text === canonicalJson(body), `${code}_NONCANONICAL`, 400);
  return body;
}

function literal(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, expected.length) === expected,
    "ACTIVATED_AUTHORITY_HEAD_RPC_INVALID",
  );
}

function exactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "ACTIVATED_AUTHORITY_HEAD_RPC_INVALID",
  );
}
