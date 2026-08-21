import {
  activatedAuthorityHeadKey,
  activatedAuthorityHeadRecordSha256,
  parseActivatedAuthorityHead,
} from "./activated-authority-head";
import { canonicalBytes, canonicalJson } from "./canonical";
import { CLOUDFLARE_UUID } from "./cloudflare-ids";
import { LIMITS } from "./config";
import { assert, BrokerError } from "./errors";
import type { ActivationWorm, JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export const ACTIVATED_AUTHORITY_HEAD_CURRENT_SCHEMA =
  "dpone.activated-service-authority-head-current.v1" as const;
export const ACTIVATED_AUTHORITY_HEAD_READ_REQUEST_SCHEMA =
  "dpone.activated-service-authority-head-read-request.v1" as const;

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;
const VERSION_ID = /^[A-Za-z0-9._=-]{1,512}$/u;

/** Build a fresh current-head proof around a long-lived immutable witness. */
export async function buildCurrentHeadProof(input: {
  readonly brokerAcceptedAt: string;
  readonly head: JsonObject;
  readonly observedAt: string;
  readonly requestId: string;
  readonly requestedAt: string;
  readonly worm: ActivationWorm;
}): Promise<JsonObject> {
  const head = await parseActivatedAuthorityHead(input.head);
  const recordSha256 = await activatedAuthorityHeadRecordSha256(head);
  const expectedKey = await activatedAuthorityHeadKey(head);
  const proof: JsonObject = {
    broker_accepted_at: timestamp(input.brokerAcceptedAt),
    head,
    observed_at: timestamp(input.observedAt),
    record_sha256: recordSha256,
    request_id: requestId(input.requestId),
    requested_at: timestamp(input.requestedAt),
    schema: ACTIVATED_AUTHORITY_HEAD_CURRENT_SCHEMA,
    schema_version: 1,
    worm: headWorm(input.worm, recordSha256, expectedKey),
  };
  return parseCurrentHeadProof(proof);
}

/** Parse the complete proof and rederive every witness and WORM binding. */
export async function parseCurrentHeadProof(value: unknown): Promise<JsonObject> {
  const proof = exactObject(value, [
    "broker_accepted_at",
    "head",
    "observed_at",
    "record_sha256",
    "request_id",
    "requested_at",
    "schema",
    "schema_version",
    "worm",
  ]);
  assertCanonicalSize(proof);
  literal(proof, "schema", ACTIVATED_AUTHORITY_HEAD_CURRENT_SCHEMA);
  exactInteger(proof, "schema_version", 1);
  requestId(requireString(proof, "request_id", 128, REQUEST_ID));
  const requestedAt = timestamp(requireString(proof, "requested_at", 32, TIMESTAMP));
  const observedAt = timestamp(requireString(proof, "observed_at", 32, TIMESTAMP));
  const acceptedAt = timestamp(requireString(proof, "broker_accepted_at", 32, TIMESTAMP));
  const head = await parseActivatedAuthorityHead(proof.head);
  const expectedDigest = await activatedAuthorityHeadRecordSha256(head);
  assert(
    taggedField(proof, "record_sha256") === expectedDigest,
    "ACTIVATED_AUTHORITY_HEAD_PROOF_DIGEST_INVALID",
    503,
  );
  const expectedKey = await activatedAuthorityHeadKey(head);
  const worm = parseHeadWorm(proof.worm, expectedDigest, expectedKey);
  const activated = exactObject(head.activated, ["record_id", "record_sha256", "worm"]);
  const activatedWorm = exactObject(activated.worm, [
    "digest",
    "key",
    "retention_until",
    "version_id",
  ]);
  const committedAt = timestamp(requireString(head, "committed_at", 32, TIMESTAMP));
  assertFreshRead(requestedAt, observedAt, acceptedAt, committedAt);
  assertRetention(requireString(activatedWorm, "retention_until", 32, TIMESTAMP), observedAt);
  assertMinimumRetention(worm.retentionUntil, committedAt);
  return proof;
}

export function parseHeadReadRequest(value: unknown): JsonObject {
  const request = exactObject(value, [
    "expected_activated_record_id",
    "expected_activated_record_sha256",
    "expected_activated_service_authorities_sha256",
    "expected_ingress_worker_version_id",
    "request_id",
    "requested_at",
    "schema",
    "schema_version",
  ]);
  literal(request, "schema", ACTIVATED_AUTHORITY_HEAD_READ_REQUEST_SCHEMA);
  exactInteger(request, "schema_version", 1);
  taggedField(request, "expected_activated_record_id");
  taggedField(request, "expected_activated_record_sha256");
  taggedField(request, "expected_activated_service_authorities_sha256");
  requireString(request, "expected_ingress_worker_version_id", 36, CLOUDFLARE_UUID);
  requestId(requireString(request, "request_id", 128, REQUEST_ID));
  timestamp(requireString(request, "requested_at", 32, TIMESTAMP));
  return request;
}

export function buildHeadReadRequest(input: {
  readonly activatedRecordId: string;
  readonly activatedRecordSha256: string;
  readonly activatedServiceAuthoritiesSha256: string;
  readonly ingressWorkerVersionId: string;
  readonly requestId: string;
  readonly requestedAt: string;
}): JsonObject {
  return parseHeadReadRequest({
    expected_activated_record_id: input.activatedRecordId,
    expected_activated_record_sha256: input.activatedRecordSha256,
    expected_activated_service_authorities_sha256: input.activatedServiceAuthoritiesSha256,
    expected_ingress_worker_version_id: input.ingressWorkerVersionId,
    request_id: input.requestId,
    requested_at: input.requestedAt,
    schema: ACTIVATED_AUTHORITY_HEAD_READ_REQUEST_SCHEMA,
    schema_version: 1,
  });
}

export async function assertCurrentHeadMatchesRequest(
  value: unknown,
  rawRequest: unknown,
): Promise<JsonObject> {
  const proof = await parseCurrentHeadProof(value);
  const request = parseHeadReadRequest(rawRequest);
  const head = exactObject(proof.head, [
    "activated",
    "activated_service_authorities_sha256",
    "committed_at",
    "generation",
    "ingress_worker_version_id",
    "previous",
    "record_id",
    "schema",
    "schema_version",
  ]);
  const activated = exactObject(head.activated, ["record_id", "record_sha256", "worm"]);
  assert(
    proof.request_id === request.request_id &&
      proof.requested_at === request.requested_at &&
      activated.record_id === request.expected_activated_record_id &&
      activated.record_sha256 === request.expected_activated_record_sha256 &&
      head.activated_service_authorities_sha256 ===
        request.expected_activated_service_authorities_sha256 &&
      head.ingress_worker_version_id === request.expected_ingress_worker_version_id,
    "ACTIVATED_AUTHORITY_HEAD_STALE",
    503,
  );
  return proof;
}

/** Decode a canonical <=65,536-byte current-head RPC body before semantics. */
export async function parseCurrentHeadProofCanonical(text: string): Promise<JsonObject> {
  const bytes = new TextEncoder().encode(text);
  if (bytes.byteLength === 0 || bytes.byteLength > LIMITS.bodyBytes) {
    throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_PROOF_SIZE_INVALID", 503, false);
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(text);
  } catch {
    throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_PROOF_INVALID", 503, false);
  }
  const proof = await parseCurrentHeadProof(decoded);
  assert(text === canonicalJson(proof), "ACTIVATED_AUTHORITY_HEAD_PROOF_NONCANONICAL", 503);
  return proof;
}

function parseHeadWorm(
  value: unknown,
  expectedDigest: string,
  expectedKey: string,
): ActivationWorm {
  const worm = exactObject(value, ["digest", "key", "retention_until", "version_id"]);
  literal(worm, "digest", expectedDigest);
  literal(worm, "key", expectedKey);
  return {
    digest: expectedDigest,
    key: expectedKey,
    retentionUntil: requireString(worm, "retention_until", 32, TIMESTAMP),
    versionId: requireString(worm, "version_id", 512, VERSION_ID),
  };
}

function headWorm(worm: ActivationWorm, digest: string, key: string): JsonObject {
  assert(worm.digest === digest && worm.key === key, "ACTIVATED_AUTHORITY_HEAD_WORM_INVALID", 503);
  return {
    digest,
    key,
    retention_until: timestamp(worm.retentionUntil),
    version_id: requireString({ value: worm.versionId }, "value", 512, VERSION_ID),
  };
}

function assertFreshRead(
  requestedAt: string,
  observedAt: string,
  acceptedAt: string,
  committedAt: string,
): void {
  const requested = Date.parse(requestedAt);
  const observed = Date.parse(observedAt);
  const accepted = Date.parse(acceptedAt);
  const committed = Date.parse(committedAt);
  assert(
    committed <= observed &&
      requested <= observed &&
      observed - requested <= 60_000 &&
      observed <= accepted &&
      accepted - observed <= 60_000,
    "ACTIVATED_AUTHORITY_HEAD_STALE",
    503,
  );
}

function assertRetention(retentionUntil: string, observedAt: string): void {
  assert(
    Date.parse(retentionUntil) > Date.parse(observedAt),
    "ACTIVATED_AUTHORITY_HEAD_RETENTION_INVALID",
    503,
  );
}

function assertMinimumRetention(retentionUntil: string, committedAt: string): void {
  assert(
    Date.parse(retentionUntil) >= Date.parse(committedAt) + 2557 * 86_400_000,
    "ACTIVATED_AUTHORITY_HEAD_RETENTION_INVALID",
    503,
  );
}

function assertCanonicalSize(value: JsonObject): void {
  assert(
    canonicalBytes(value).byteLength > 0 && canonicalBytes(value).byteLength <= LIMITS.bodyBytes,
    "ACTIVATED_AUTHORITY_HEAD_PROOF_SIZE_INVALID",
    503,
  );
}

function timestamp(value: string): string {
  assert(
    TIMESTAMP.test(value) && new Date(Date.parse(value)).toISOString() === value,
    "ACTIVATED_AUTHORITY_HEAD_PROOF_INVALID",
    503,
  );
  return value;
}

function requestId(value: string): string {
  assert(REQUEST_ID.test(value), "ACTIVATED_AUTHORITY_HEAD_PROOF_INVALID", 503);
  return value;
}

function taggedField(object: JsonObject, key: string): string {
  return requireString(object, key, 71, DIGEST);
}

function literal(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, expected.length) === expected,
    "ACTIVATED_AUTHORITY_HEAD_PROOF_INVALID",
    503,
  );
}

function exactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "ACTIVATED_AUTHORITY_HEAD_PROOF_INVALID",
    503,
  );
}
