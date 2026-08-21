import {
  ACTIVATION_OPERATION_ATTEMPT_SCHEMA,
  ACTIVATION_OPERATION_ISSUANCE_SCHEMA,
  type ActivationOperationIdentity,
  type ActivationOperationSequence,
} from "./activation-operation-contract";
import { FINALIZE_REQUEST_SCHEMA, PROVISION_REQUEST_SCHEMA } from "./activation-contract";
import { canonicalBytes, digestObject, sha256Hex } from "./canonical";
import { CLOUDFLARE_UUID } from "./cloudflare-ids";
import { BrokerError } from "./errors";
import type { JsonObject } from "./types";
import { exactObject } from "./validation";

const MAX_SEMANTIC_REQUEST_BYTES = 65_536;
const MAX_ORDINAL = 1_000_000;

/** Derive transport/auth-independent identity from an already parsed request. */
export async function activationOperationIdentity(
  body: JsonObject,
  sequence: ActivationOperationSequence,
  workerVersionId: string,
): Promise<ActivationOperationIdentity> {
  if (!CLOUDFLARE_UUID.test(workerVersionId)) fail("ACTIVATION_OPERATION_WORKER_INVALID");
  const semanticRequest = semanticProjection(body, sequence);
  const semanticRequestBytes = canonicalBytes(semanticRequest);
  if (
    semanticRequestBytes.byteLength === 0 ||
    semanticRequestBytes.byteLength > MAX_SEMANTIC_REQUEST_BYTES
  ) {
    fail("ACTIVATION_OPERATION_INTENT_SIZE_INVALID", 413);
  }
  const intentSha256 = `sha256:${await sha256Hex(semanticRequestBytes)}`;
  const attemptId = await digestObject({
    intent_sha256: intentSha256,
    schema: ACTIVATION_OPERATION_ATTEMPT_SCHEMA,
    schema_version: 1,
    sequence,
    worker_version_id: workerVersionId,
  });
  return {
    attemptId,
    intentSha256,
    semanticRequest: decodeSemanticRequest(semanticRequestBytes),
    semanticRequestBytes,
    sequence,
    workerVersionId,
  };
}

function decodeSemanticRequest(bytes: Uint8Array): JsonObject {
  const decoded: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) {
    fail("ACTIVATION_OPERATION_INTENT_INVALID");
  }
  return decoded as JsonObject;
}

export async function activationOperationIssuanceIdentity(
  attemptId: string,
  ordinal: number,
): Promise<{ readonly internalRequestId: string; readonly issuanceId: string }> {
  if (
    !/^sha256:[0-9a-f]{64}$/u.test(attemptId) ||
    !Number.isSafeInteger(ordinal) ||
    ordinal < 1 ||
    ordinal > MAX_ORDINAL
  ) {
    fail("ACTIVATION_OPERATION_ISSUANCE_INVALID");
  }
  const issuanceId = await digestObject({
    attempt_id: attemptId,
    broker_issued_ordinal: ordinal,
    schema: ACTIVATION_OPERATION_ISSUANCE_SCHEMA,
    schema_version: 1,
  });
  return {
    internalRequestId: `activation-${issuanceId.slice("sha256:".length)}`,
    issuanceId,
  };
}

function semanticProjection(value: JsonObject, sequence: ActivationOperationSequence): JsonObject {
  const body = exactObject(
    value,
    sequence === 0
      ? ["evidence", "observed_at", "request_id", "schema", "schema_version"]
      : [
          "approvals",
          "observed_at",
          "provisioned",
          "promotion",
          "request_id",
          "schema",
          "schema_version",
          "target",
        ],
  );
  const expectedSchema = sequence === 0 ? PROVISION_REQUEST_SCHEMA : FINALIZE_REQUEST_SCHEMA;
  if (body.schema !== expectedSchema || body.schema_version !== 1) {
    fail("ACTIVATION_OPERATION_INTENT_INVALID");
  }
  return sequence === 0
    ? {
        evidence: body.evidence ?? null,
        schema: expectedSchema,
        schema_version: 1,
      }
    : {
        approvals: body.approvals ?? null,
        promotion: body.promotion ?? null,
        provisioned: body.provisioned ?? null,
        schema: expectedSchema,
        schema_version: 1,
        target: body.target ?? null,
      };
}

function fail(code: string, status = 409): never {
  throw new BrokerError(code, status, false);
}
