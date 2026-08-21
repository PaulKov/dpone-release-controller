import { parseActivationProofEffectReservation } from "./activated-authority-effect";
import {
  canonicalEffectTimestamp as canonicalTimestamp,
  decodeEffectCanonical as decodeCanonical,
  requireEffectExactInteger as exactInteger,
  requireEffectLiteral as literal,
  requireEffectObject as exactObjectValue,
} from "./activated-authority-effect-rpc-common";
import {
  assertCurrentHeadMatchesRequest,
  buildHeadReadRequest,
  parseCurrentHeadProof,
} from "./activated-authority-head-proof";
import { canonicalBytes, canonicalJson, sha256Hex } from "./canonical";
import { CLOUDFLARE_UUID } from "./cloudflare-ids";
import { assert } from "./errors";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export const AUTHORITY_EFFECT_RESERVE_REQUEST_SCHEMA =
  "dpone.activated-authority-effect-reserve-request.v1" as const;
export const AUTHORITY_EFFECT_RESERVE_RESULT_SCHEMA =
  "dpone.activated-authority-effect-reserve-result.v1" as const;
export const AUTHORITY_EFFECT_TRANSITION_REQUEST_SCHEMA =
  "dpone.activated-authority-effect-transition-request.v1" as const;
export const AUTHORITY_EFFECT_STATUS_SCHEMA = "dpone.activated-authority-effect-status.v1" as const;

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;

export interface AuthorityEffectReserveRequest {
  readonly body: JsonObject;
  readonly expiresAt: string;
  readonly intentSha256: string;
  readonly readRequest: JsonObject;
  readonly replayClaimsSha256: string;
  readonly replayExpiresAt: number;
  readonly replayJtiSha256: string;
  readonly requestId: string;
  readonly requestedAt: string;
}

export type AuthorityEffectTransition = "CANCEL" | "CONFIRM" | "DISPATCH" | "SEAL";
export type AuthorityEffectStatus =
  | "CANCELLED_UNDISPATCHED"
  | "CONFIRMED"
  | "DISPATCHED_HOLD"
  | "SEALED";

export function buildAuthorityEffectReserveRequest(input: {
  readonly activatedRecordId: string;
  readonly activatedRecordSha256: string;
  readonly activatedServiceAuthoritiesSha256: string;
  readonly expiresAt: string;
  readonly ingressWorkerVersionId: string;
  readonly intentSha256: string;
  readonly replayClaimsSha256: string;
  readonly replayExpiresAt: number;
  readonly replayJtiSha256: string;
  readonly requestId: string;
  readonly requestedAt: string;
}): string {
  const body: JsonObject = {
    expected_activated_record_id: input.activatedRecordId,
    expected_activated_record_sha256: input.activatedRecordSha256,
    expected_activated_service_authorities_sha256: input.activatedServiceAuthoritiesSha256,
    expected_ingress_worker_version_id: input.ingressWorkerVersionId,
    expires_at: input.expiresAt,
    intent_sha256: input.intentSha256,
    operation: "ACTIVATION_PROOF",
    replay_claims_sha256: input.replayClaimsSha256,
    replay_expires_at: input.replayExpiresAt,
    replay_jti_sha256: input.replayJtiSha256,
    request_id: input.requestId,
    requested_at: input.requestedAt,
    schema: AUTHORITY_EFFECT_RESERVE_REQUEST_SCHEMA,
    schema_version: 1,
  };
  const text = canonicalJson(body);
  parseAuthorityEffectReserveRequest(text);
  return text;
}

export function parseAuthorityEffectReserveRequest(
  canonical: string,
): AuthorityEffectReserveRequest {
  const body = decodeCanonical(canonical);
  const request = exactObject(body, [
    "expected_activated_record_id",
    "expected_activated_record_sha256",
    "expected_activated_service_authorities_sha256",
    "expected_ingress_worker_version_id",
    "expires_at",
    "intent_sha256",
    "operation",
    "replay_claims_sha256",
    "replay_expires_at",
    "replay_jti_sha256",
    "request_id",
    "requested_at",
    "schema",
    "schema_version",
  ]);
  literal(request, "schema", AUTHORITY_EFFECT_RESERVE_REQUEST_SCHEMA);
  exactInteger(request, "schema_version", 1);
  literal(request, "operation", "ACTIVATION_PROOF");
  const requestId = requireString(request, "request_id", 128, REQUEST_ID);
  const requestedAt = canonicalTimestamp(requireString(request, "requested_at", 32, TIMESTAMP));
  const expiresAt = canonicalTimestamp(requireString(request, "expires_at", 32, TIMESTAMP));
  const requestedMs = Date.parse(requestedAt);
  const expiresMs = Date.parse(expiresAt);
  assert(
    requestedMs < expiresMs && expiresMs - requestedMs <= 60_000,
    "ACTIVATED_AUTHORITY_EFFECT_REQUEST_INVALID",
    409,
  );
  const readRequest = buildHeadReadRequest({
    activatedRecordId: requireString(request, "expected_activated_record_id", 71, DIGEST),
    activatedRecordSha256: requireString(request, "expected_activated_record_sha256", 71, DIGEST),
    activatedServiceAuthoritiesSha256: requireString(
      request,
      "expected_activated_service_authorities_sha256",
      71,
      DIGEST,
    ),
    ingressWorkerVersionId: requireString(
      request,
      "expected_ingress_worker_version_id",
      36,
      CLOUDFLARE_UUID,
    ),
    requestId,
    requestedAt,
  });
  return {
    body: request,
    expiresAt,
    intentSha256: requireString(request, "intent_sha256", 71, DIGEST),
    readRequest,
    replayClaimsSha256: requireString(request, "replay_claims_sha256", 71, DIGEST),
    replayExpiresAt: requireInteger(request, "replay_expires_at", 1, Number.MAX_SAFE_INTEGER),
    replayJtiSha256: requireString(request, "replay_jti_sha256", 71, DIGEST),
    requestId,
    requestedAt,
  };
}

export async function buildAuthorityEffectReserveResult(
  headProof: JsonObject,
  reservation: JsonObject,
  status: "CONFIRMED" | "DISPATCHED_HOLD" | "RESERVED" | "SEALED",
  sealedResultCanonical?: string,
): Promise<string> {
  const sealedResult =
    sealedResultCanonical === undefined ? null : decodeCanonical(sealedResultCanonical);
  const body: JsonObject = {
    activated_authority_head: await parseCurrentHeadProof(headProof),
    reservation: await parseActivationProofEffectReservation(reservation),
    sealed_result: sealedResult,
    sealed_result_sha256:
      sealedResult === null ? null : `sha256:${await sha256Hex(canonicalBytes(sealedResult))}`,
    schema: AUTHORITY_EFFECT_RESERVE_RESULT_SCHEMA,
    schema_version: 1,
    status,
  };
  const canonical = canonicalJson(body);
  await parseAuthorityEffectReserveResult(canonical);
  return canonical;
}

export async function parseAuthorityEffectReserveResult(canonical: string): Promise<{
  readonly headProof: JsonObject;
  readonly reservation: JsonObject;
  readonly sealedResult: JsonObject | null;
  readonly sealedResultSha256: string | null;
  readonly status: "CONFIRMED" | "DISPATCHED_HOLD" | "RESERVED" | "SEALED";
}> {
  const body = exactObject(decodeCanonical(canonical), [
    "activated_authority_head",
    "reservation",
    "sealed_result",
    "sealed_result_sha256",
    "schema",
    "schema_version",
    "status",
  ]);
  literal(body, "schema", AUTHORITY_EFFECT_RESERVE_RESULT_SCHEMA);
  exactInteger(body, "schema_version", 1);
  const headProof = await parseCurrentHeadProof(body.activated_authority_head);
  const reservation = await parseActivationProofEffectReservation(body.reservation);
  assert(
    body.status === "CONFIRMED" ||
      body.status === "DISPATCHED_HOLD" ||
      body.status === "RESERVED" ||
      body.status === "SEALED",
    "ACTIVATED_AUTHORITY_EFFECT_RESULT_INVALID",
    503,
  );
  const sealedResult = body.sealed_result === null ? null : exactObjectValue(body.sealed_result);
  const sealedResultSha256 =
    body.sealed_result_sha256 === null
      ? null
      : requireString(body, "sealed_result_sha256", 71, DIGEST);
  assert(
    (body.status === "RESERVED" && sealedResult === null && sealedResultSha256 === null) ||
      (body.status !== "RESERVED" &&
        sealedResult !== null &&
        sealedResultSha256 === `sha256:${await sha256Hex(canonicalBytes(sealedResult))}`),
    "ACTIVATED_AUTHORITY_EFFECT_RESULT_INVALID",
    503,
  );
  const head = exactObject(reservation.head, ["generation", "record_id", "record_sha256"]);
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
    (body.status === "CONFIRMED" || reservation.request_id === headProof.request_id) &&
      head.generation === proofHead.generation &&
      head.record_id === proofHead.record_id &&
      head.record_sha256 === headProof.record_sha256,
    "ACTIVATED_AUTHORITY_EFFECT_RESULT_INVALID",
    503,
  );
  return {
    headProof,
    reservation,
    sealedResult,
    sealedResultSha256,
    status: body.status,
  };
}

export function buildAuthorityEffectTransitionRequest(input: {
  readonly action: AuthorityEffectTransition;
  readonly requestId: string;
  readonly requestedAt: string;
  readonly reservationId: string;
  readonly resultSha256?: string;
}): string {
  const body: JsonObject = {
    action: input.action,
    request_id: input.requestId,
    requested_at: input.requestedAt,
    reservation_id: input.reservationId,
    ...(input.action === "CONFIRM" ? { result_sha256: input.resultSha256 ?? null } : {}),
    schema: AUTHORITY_EFFECT_TRANSITION_REQUEST_SCHEMA,
    schema_version: 1,
  };
  const canonical = canonicalJson(body);
  parseAuthorityEffectTransitionRequest(canonical);
  return canonical;
}

export function parseAuthorityEffectTransitionRequest(canonical: string): {
  readonly action: AuthorityEffectTransition;
  readonly requestId: string;
  readonly requestedAt: string;
  readonly reservationId: string;
  readonly resultSha256?: string;
} {
  const decoded = decodeCanonical(canonical);
  const rawAction = decoded.action;
  assert(
    rawAction === "CANCEL" ||
      rawAction === "CONFIRM" ||
      rawAction === "DISPATCH" ||
      rawAction === "SEAL",
    "ACTIVATED_AUTHORITY_EFFECT_TRANSITION_INVALID",
    409,
  );
  const body = exactObject(
    decoded,
    rawAction === "CONFIRM"
      ? [
          "action",
          "request_id",
          "requested_at",
          "reservation_id",
          "result_sha256",
          "schema",
          "schema_version",
        ]
      : ["action", "request_id", "requested_at", "reservation_id", "schema", "schema_version"],
  );
  literal(body, "schema", AUTHORITY_EFFECT_TRANSITION_REQUEST_SCHEMA);
  exactInteger(body, "schema_version", 1);
  const resultSha256 =
    rawAction === "CONFIRM" ? requireString(body, "result_sha256", 71, DIGEST) : undefined;
  return {
    action: rawAction,
    requestId: requireString(body, "request_id", 128, REQUEST_ID),
    requestedAt: canonicalTimestamp(requireString(body, "requested_at", 32, TIMESTAMP)),
    reservationId: requireString(body, "reservation_id", 71, DIGEST),
    ...(resultSha256 === undefined ? {} : { resultSha256 }),
  };
}

export async function assertReserveResultMatchesRequest(
  value: { readonly headProof: JsonObject; readonly reservation: JsonObject },
  request: AuthorityEffectReserveRequest,
): Promise<void> {
  await assertCurrentHeadMatchesRequest(value.headProof, {
    ...request.readRequest,
    requested_at: value.headProof.requested_at ?? null,
  });
  assert(
    value.reservation.intent_sha256 === request.intentSha256,
    "ACTIVATED_AUTHORITY_EFFECT_RESULT_INVALID",
    503,
  );
}

export function parseAuthorityEffectStatus(
  canonical: string,
  reservationId: string,
): { readonly resultSha256: string | null; readonly status: AuthorityEffectStatus } {
  const body = exactObject(decodeCanonical(canonical), [
    "reservation_id",
    "result_sha256",
    "schema",
    "schema_version",
    "status",
  ]);
  literal(body, "schema", AUTHORITY_EFFECT_STATUS_SCHEMA);
  exactInteger(body, "schema_version", 1);
  assert(
    body.reservation_id === reservationId &&
      (body.status === "CANCELLED_UNDISPATCHED" ||
        body.status === "CONFIRMED" ||
        body.status === "DISPATCHED_HOLD" ||
        body.status === "SEALED"),
    "ACTIVATED_AUTHORITY_EFFECT_STATUS_INVALID",
    503,
  );
  const resultSha256 = body.result_sha256;
  assert(
    resultSha256 === null || (typeof resultSha256 === "string" && DIGEST.test(resultSha256)),
    "ACTIVATED_AUTHORITY_EFFECT_STATUS_INVALID",
    503,
  );
  return { resultSha256, status: body.status };
}
