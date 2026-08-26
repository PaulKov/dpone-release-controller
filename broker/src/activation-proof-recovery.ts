import { parseCurrentHeadProof } from "./activated-authority-head-proof";
import {
  ACTIVATION_PROOF_RECOVERY_SCHEMA,
  ACTIVATION_PROOF_SCHEMA,
} from "./activation-proof-contract";
import { canonicalBytes, canonicalJson, digestObject, sha256Hex } from "./canonical";
import { LIMITS } from "./config";
import { assert } from "./errors";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export async function activationProofRecoveryClaimsDigest(input: {
  readonly admissionClaimsSha256: string;
  readonly currentHead: JsonObject;
  readonly currentRequestId: string;
  readonly originalRequestId: string;
  readonly reservationId: string;
  readonly sealedResultSha256: string;
}): Promise<string> {
  const current = await parseCurrentHeadProof(input.currentHead);
  const head = parseHead(current);
  return digestObject({
    admission_claims_sha256: input.admissionClaimsSha256,
    current_head_record_id: head.record_id ?? null,
    current_head_record_sha256: current.record_sha256 ?? null,
    current_request_id: input.currentRequestId,
    original_request_id: input.originalRequestId,
    path: "/v1/activation/proof",
    request_schema: "dpone.release-broker-activation-proof-request.v1",
    reservation_id: input.reservationId,
    schema: "dpone.release-broker-activation-proof-recovery-claims.v1",
    schema_version: 1,
    sealed_result_sha256: input.sealedResultSha256,
  });
}

/** Wraps an exact sealed proof after durable observer-only JTI reconciliation. */
export async function buildActivationProofRecovery(input: {
  readonly currentHead: JsonObject;
  readonly currentRequestId: string;
  readonly nowMs: number;
  readonly originalProof: JsonObject;
  readonly originalRequestId: string;
  readonly reservationId: string;
  readonly sealedResultSha256: string;
}): Promise<JsonObject> {
  const currentHead = await parseCurrentHeadProof(input.currentHead);
  const headAcceptedAt = Date.parse(
    requireString(
      currentHead,
      "broker_accepted_at",
      32,
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u,
    ),
  );
  assert(
    currentHead.request_id === input.currentRequestId &&
      input.currentRequestId !== input.originalRequestId &&
      headAcceptedAt <= input.nowMs &&
      input.nowMs - headAcceptedAt <= 60_000,
    "ACTIVATION_PROOF_RECOVERY_HEAD_STALE",
    503,
  );
  const originalProof = exactObject(input.originalProof, [
    "activated",
    "activated_authority_head",
    "admitted_at",
    "controller",
    "expires_at",
    "proof_sha256",
    "provisioned",
    "request_id",
    "schema",
    "schema_version",
  ]);
  requireLiteral(originalProof, "schema", ACTIVATION_PROOF_SCHEMA);
  requireExactInteger(originalProof, "schema_version", 1);
  const unsigned = { ...originalProof };
  delete unsigned.proof_sha256;
  const admittedAt = canonicalProofTimestamp(requireString(originalProof, "admitted_at", 20));
  const expiresAt = canonicalProofTimestamp(requireString(originalProof, "expires_at", 20));
  assert(
    requireString(originalProof, "proof_sha256", 71, /^sha256:[0-9a-f]{64}$/u) ===
      `sha256:${await sha256Hex(canonicalBytes(unsigned))}` &&
      input.sealedResultSha256 === `sha256:${await sha256Hex(canonicalBytes(originalProof))}` &&
      requireString(originalProof, "request_id", 128) === input.originalRequestId &&
      Date.parse(expiresAt) - Date.parse(admittedAt) === 60_000 &&
      input.nowMs < Date.parse(expiresAt),
    "ACTIVATION_PROOF_RECOVERY_INVALID",
    503,
  );
  const originalHead = await parseCurrentHeadProof(originalProof.activated_authority_head);
  assertSameImmutableHead(currentHead, originalHead);
  const body: JsonObject = {
    activated_authority_head: currentHead,
    activation_proof: originalProof,
    current_request_id: input.currentRequestId,
    original_request_id: input.originalRequestId,
    reservation_id: input.reservationId,
    schema: ACTIVATION_PROOF_RECOVERY_SCHEMA,
    schema_version: 1,
    sealed_result_sha256: input.sealedResultSha256,
  };
  const recovery: JsonObject = {
    ...body,
    recovery_sha256: `sha256:${await sha256Hex(canonicalBytes(body))}`,
  };
  assert(
    canonicalBytes(recovery).byteLength > 0 &&
      canonicalBytes(recovery).byteLength <= LIMITS.bodyBytes,
    "ACTIVATION_PROOF_RECOVERY_SIZE_INVALID",
    503,
  );
  return recovery;
}

function assertSameImmutableHead(currentProof: JsonObject, originalProof: JsonObject): void {
  const current = parseHead(currentProof);
  const original = parseHead(originalProof);
  assert(
    current.record_id === original.record_id &&
      currentProof.record_sha256 === originalProof.record_sha256 &&
      canonicalJson(current.activated) === canonicalJson(original.activated) &&
      current.activated_service_authorities_sha256 ===
        original.activated_service_authorities_sha256 &&
      current.ingress_worker_version_id === original.ingress_worker_version_id,
    "ACTIVATION_PROOF_RECOVERY_HEAD_MISMATCH",
    503,
  );
}

function parseHead(proof: JsonObject): JsonObject {
  return exactObject(proof.head, [
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
}

function canonicalProofTimestamp(value: string): string {
  assert(
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(value) &&
      new Date(Date.parse(value)).toISOString().replace(".000Z", "Z") === value,
    "ACTIVATION_PROOF_RECOVERY_INVALID",
    503,
  );
  return value;
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, expected.length) === expected,
    "ACTIVATION_PROOF_RECOVERY_INVALID",
    503,
  );
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "ACTIVATION_PROOF_RECOVERY_INVALID",
    503,
  );
}
