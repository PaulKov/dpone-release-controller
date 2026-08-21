import { canonicalBytes, canonicalJson, sha256Hex } from "./canonical";
import { LIMITS } from "./config";
import { assert, BrokerError } from "./errors";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export const ACTIVATION_PROOF_EFFECT_OPERATION = "ACTIVATION_PROOF" as const;
export const ACTIVATED_AUTHORITY_EFFECT_RESERVATION_SCHEMA =
  "dpone.activated-authority-effect-reservation.v1" as const;
const ACTIVATED_AUTHORITY_EFFECT_RESERVATION_ID_SCHEMA =
  "dpone.activated-authority-effect-reservation-id.v1" as const;

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;

/** Build the immutable reservation which pins one effect to one global head. */
export async function buildActivationProofEffectReservation(input: {
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly headGeneration: number;
  readonly headRecordId: string;
  readonly headRecordSha256: string;
  readonly headProof: JsonObject;
  readonly intentSha256: string;
  readonly replayClaimsSha256: string;
  readonly replayExpiresAt: number;
  readonly replayJtiSha256: string;
  readonly requestId: string;
}): Promise<JsonObject> {
  const headProof = await parseCurrentHeadProof(input.headProof);
  const proofHead = exactObject(headProof.head, [
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
  assert(
    proofHead.generation === input.headGeneration &&
      proofHead.record_id === input.headRecordId &&
      headProof.record_sha256 === input.headRecordSha256,
    "ACTIVATED_AUTHORITY_EFFECT_RESERVATION_INVALID",
    409,
  );
  const withoutId: JsonObject = {
    created_at: canonicalTimestamp(input.createdAt),
    expires_at: canonicalTimestamp(input.expiresAt),
    head: {
      generation: safePositiveInteger(input.headGeneration),
      record_id: tagged(input.headRecordId),
      record_sha256: tagged(input.headRecordSha256),
    },
    head_proof: headProof,
    head_proof_sha256: `sha256:${await sha256Hex(canonicalBytes(headProof))}`,
    intent_sha256: tagged(input.intentSha256),
    operation: ACTIVATION_PROOF_EFFECT_OPERATION,
    replay: {
      claims_sha256: tagged(input.replayClaimsSha256),
      expires_at: safePositiveInteger(input.replayExpiresAt),
      jti_sha256: tagged(input.replayJtiSha256),
    },
    request_id: requestId(input.requestId),
    schema: ACTIVATED_AUTHORITY_EFFECT_RESERVATION_SCHEMA,
    schema_version: 1,
  };
  assertWindow(withoutId.created_at, withoutId.expires_at);
  const reservation: JsonObject = {
    ...withoutId,
    reservation_id: `sha256:${await sha256Hex(
      canonicalBytes({
        head: withoutId.head ?? null,
        intent_sha256: withoutId.intent_sha256 ?? null,
        operation: ACTIVATION_PROOF_EFFECT_OPERATION,
        schema: ACTIVATED_AUTHORITY_EFFECT_RESERVATION_ID_SCHEMA,
        schema_version: 1,
      }),
    )}`,
  };
  assertSize(reservation);
  return reservation;
}

/** Parse and independently rederive the exact reservation identifier. */
export async function parseActivationProofEffectReservation(value: unknown): Promise<JsonObject> {
  const reservation = exactObject(value, [
    "created_at",
    "expires_at",
    "head",
    "head_proof",
    "head_proof_sha256",
    "intent_sha256",
    "operation",
    "replay",
    "request_id",
    "reservation_id",
    "schema",
    "schema_version",
  ]);
  literal(reservation, "schema", ACTIVATED_AUTHORITY_EFFECT_RESERVATION_SCHEMA);
  exactInteger(reservation, "schema_version", 1);
  literal(reservation, "operation", ACTIVATION_PROOF_EFFECT_OPERATION);
  const head = exactObject(reservation.head, ["generation", "record_id", "record_sha256"]);
  const replay = exactObject(reservation.replay, ["claims_sha256", "expires_at", "jti_sha256"]);
  const rebuilt = await buildActivationProofEffectReservation({
    createdAt: requireString(reservation, "created_at", 32, TIMESTAMP),
    expiresAt: requireString(reservation, "expires_at", 32, TIMESTAMP),
    headGeneration: requireInteger(head, "generation", 1, Number.MAX_SAFE_INTEGER),
    headRecordId: requireString(head, "record_id", 71, DIGEST),
    headRecordSha256: requireString(head, "record_sha256", 71, DIGEST),
    headProof: await parseCurrentHeadProof(reservation.head_proof),
    intentSha256: requireString(reservation, "intent_sha256", 71, DIGEST),
    replayClaimsSha256: requireString(replay, "claims_sha256", 71, DIGEST),
    replayExpiresAt: requireInteger(replay, "expires_at", 1, Number.MAX_SAFE_INTEGER),
    replayJtiSha256: requireString(replay, "jti_sha256", 71, DIGEST),
    requestId: requireString(reservation, "request_id", 128, REQUEST_ID),
  });
  assert(
    canonicalJson(reservation) === canonicalJson(rebuilt),
    "ACTIVATED_AUTHORITY_EFFECT_RESERVATION_INVALID",
    409,
  );
  return reservation;
}

function assertWindow(createdAtValue: unknown, expiresAtValue: unknown): void {
  assert(
    typeof createdAtValue === "string" && typeof expiresAtValue === "string",
    "ACTIVATED_AUTHORITY_EFFECT_RESERVATION_INVALID",
    409,
  );
  const createdAt = Date.parse(createdAtValue);
  const expiresAt = Date.parse(expiresAtValue);
  assert(
    createdAt < expiresAt && expiresAt - createdAt <= 60_000,
    "ACTIVATED_AUTHORITY_EFFECT_RESERVATION_INVALID",
    409,
  );
}

function assertSize(value: JsonObject): void {
  const size = canonicalBytes(value).byteLength;
  if (size === 0 || size > LIMITS.bodyBytes) {
    throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RESERVATION_SIZE_INVALID", 413, false);
  }
}

function canonicalTimestamp(value: string): string {
  assert(
    TIMESTAMP.test(value) && new Date(Date.parse(value)).toISOString() === value,
    "ACTIVATED_AUTHORITY_EFFECT_RESERVATION_INVALID",
    409,
  );
  return value;
}

function tagged(value: string): string {
  assert(DIGEST.test(value), "ACTIVATED_AUTHORITY_EFFECT_RESERVATION_INVALID", 409);
  return value;
}

function requestId(value: string): string {
  assert(REQUEST_ID.test(value), "ACTIVATED_AUTHORITY_EFFECT_RESERVATION_INVALID", 409);
  return value;
}

function safePositiveInteger(value: number): number {
  assert(
    Number.isSafeInteger(value) && value >= 1,
    "ACTIVATED_AUTHORITY_EFFECT_RESERVATION_INVALID",
    409,
  );
  return value;
}

function literal(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, expected.length) === expected,
    "ACTIVATED_AUTHORITY_EFFECT_RESERVATION_INVALID",
    409,
  );
}

function exactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "ACTIVATED_AUTHORITY_EFFECT_RESERVATION_INVALID",
    409,
  );
}
import { parseCurrentHeadProof } from "./activated-authority-head-proof";
