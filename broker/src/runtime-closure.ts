import { boundedFixedLengthStream, type BoundedPipePolicy } from "./bounded";
import { canonicalBytes, canonicalJson, sha256Hex } from "./canonical";
import { assert, BrokerError } from "./errors";
import {
  DIGEST,
  OBSERVATION_KEYS,
  OBSERVATION_MAX_BASE64URL,
  OBSERVATION_MAX_BYTES,
  REQUEST_ID,
  RUNTIME_CLOSURE_CONTROLLER_SERVICE_IDENTITY_HEADER,
  RUNTIME_CLOSURE_CONTROLLER_SERVICE_VERSION_HEADER,
  RUNTIME_CLOSURE_GOVERNANCE_SERVICE_IDENTITY_HEADER,
  RUNTIME_CLOSURE_GOVERNANCE_SERVICE_VERSION_HEADER,
  RUNTIME_CLOSURE_MAX_RAW_BYTES,
  RUNTIME_CLOSURE_MEDIA_TYPE,
  RUNTIME_CLOSURE_OBSERVATION_DIGEST_HEADER,
  RUNTIME_CLOSURE_OBSERVATION_HEADER,
  RUNTIME_CLOSURE_REQUEST_ID_HEADER,
  RUNTIME_CLOSURE_REQUEST_SCHEMA,
  RUNTIME_CLOSURE_RESPONSE_SCHEMA,
  RUNTIME_CLOSURE_RESPONSE_SCHEMA_HEADER,
  RUNTIME_CLOSURE_STREAM_PIPE_POLICY,
  type EncodedRuntimeClosureObservation,
  type RuntimeClosureRequest,
  type RuntimeClosureResponsePins,
  type RuntimeClosureStream,
} from "./runtime-closure-contract";
import {
  decodeBase64url,
  encodeBase64url,
  requireExactInteger,
  requireLiteral,
  service,
  validateServicePin,
} from "./runtime-closure-fields";
import { verifyRuntimeClosureObservationBindings } from "./runtime-closure-bindings";
import { validateRuntimeClosureObservation } from "./runtime-closure-validation";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireObject, requireString } from "./validation";

export {
  RUNTIME_CLOSURE_CONTROLLER_SERVICE_IDENTITY_HEADER,
  RUNTIME_CLOSURE_CONTROLLER_SERVICE_VERSION_HEADER,
  RUNTIME_CLOSURE_GOVERNANCE_SERVICE_IDENTITY_HEADER,
  RUNTIME_CLOSURE_GOVERNANCE_SERVICE_VERSION_HEADER,
  RUNTIME_CLOSURE_MAX_EXPANDED_BYTES,
  RUNTIME_CLOSURE_MAX_MEMBER_BYTES,
  RUNTIME_CLOSURE_MAX_RAW_BYTES,
  RUNTIME_CLOSURE_MEDIA_TYPE,
  RUNTIME_CLOSURE_MEMBER_PATHS,
  RUNTIME_CLOSURE_OBSERVATION_DIGEST_HEADER,
  RUNTIME_CLOSURE_OBSERVATION_HEADER,
  RUNTIME_CLOSURE_OBSERVATION_SCHEMA,
  RUNTIME_CLOSURE_PUBLIC_PATH,
  RUNTIME_CLOSURE_REQUEST_ID_HEADER,
  RUNTIME_CLOSURE_REQUEST_SCHEMA,
  RUNTIME_CLOSURE_RESPONSE_SCHEMA,
  RUNTIME_CLOSURE_RESPONSE_SCHEMA_HEADER,
  RUNTIME_CLOSURE_STREAM_PIPE_POLICY,
} from "./runtime-closure-contract";
export type {
  EncodedRuntimeClosureObservation,
  RuntimeClosureRequest,
  RuntimeClosureResponsePins,
  RuntimeClosureStream,
} from "./runtime-closure-contract";
export { verifyRuntimeClosureObservationBindings } from "./runtime-closure-bindings";
export { validateRuntimeClosureObservation } from "./runtime-closure-validation";

/** Parse the frozen selector. OIDC carries the runtime tag/run/check identity. */
export function parseRuntimeClosureRequest(
  value: unknown,
  requestId: string,
): RuntimeClosureRequest {
  assert(REQUEST_ID.test(requestId), "REQUEST_ID_INVALID");
  const body = exactObject(value, ["release_identity_id", "schema", "schema_version"]);
  requireLiteral(body, "schema", RUNTIME_CLOSURE_REQUEST_SCHEMA);
  requireExactInteger(body, "schema_version", 1);
  return {
    releaseIdentityId: requireString(body, "release_identity_id", 71, DIGEST),
    requestId,
  };
}

/** Exact no-newline canonical request bytes consumed by the controller action. */
export function canonicalRuntimeClosureRequestBytes(input: RuntimeClosureRequest): Uint8Array {
  assert(REQUEST_ID.test(input.requestId), "REQUEST_ID_INVALID");
  assert(DIGEST.test(input.releaseIdentityId), "RUNTIME_CLOSURE_REQUEST_INVALID");
  return canonicalBytes({
    release_identity_id: input.releaseIdentityId,
    schema: RUNTIME_CLOSURE_REQUEST_SCHEMA,
    schema_version: 1,
  });
}

/** Canonicalize the closed provider projection before placing it in a header. */
export async function encodeRuntimeClosureObservation(
  observation: JsonObject,
): Promise<EncodedRuntimeClosureObservation> {
  validateRuntimeClosureObservation(observation);
  await verifyRuntimeClosureObservationBindings(observation);
  const text = canonicalJson(observation);
  const bytes = new TextEncoder().encode(text);
  assert(
    bytes.byteLength > 0 && bytes.byteLength <= OBSERVATION_MAX_BYTES,
    "RUNTIME_CLOSURE_OBSERVATION_SIZE_INVALID",
    500,
  );
  return {
    base64url: encodeBase64url(bytes),
    digest: `sha256:${await sha256Hex(bytes)}`,
    text,
  };
}

/** Decode, canonical-check, and structurally validate a public observation. */
export async function decodeRuntimeClosureObservation(
  encoded: string,
  expectedDigest: string,
  request: RuntimeClosureRequest,
  pins: RuntimeClosureResponsePins,
): Promise<JsonObject> {
  assert(
    /^[A-Za-z0-9_-]{1,16384}$/u.test(encoded) && DIGEST.test(expectedDigest),
    "RUNTIME_CLOSURE_OBSERVATION_HEADER_INVALID",
    503,
  );
  const bytes = decodeBase64url(encoded);
  assert(
    bytes.byteLength <= OBSERVATION_MAX_BYTES,
    "RUNTIME_CLOSURE_OBSERVATION_HEADER_INVALID",
    503,
  );
  assert(
    `sha256:${await sha256Hex(bytes)}` === expectedDigest,
    "RUNTIME_CLOSURE_OBSERVATION_DIGEST_MISMATCH",
    503,
  );
  let text: string;
  let decoded: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    decoded = JSON.parse(text);
  } catch {
    throw new BrokerError("RUNTIME_CLOSURE_OBSERVATION_INVALID", 503, false);
  }
  const observation = exactObject(decoded, OBSERVATION_KEYS);
  assert(text === canonicalJson(observation), "RUNTIME_CLOSURE_OBSERVATION_NONCANONICAL", 503);
  validateRuntimeClosureObservation(observation);
  await verifyRuntimeClosureObservationBindings(observation);
  requireLiteral(observation, "broker_request_id", request.requestId);
  const ledger = requireObject(observation.ledger, "RUNTIME_CLOSURE_OBSERVATION_INVALID");
  requireLiteral(ledger, "release_identity_id", request.releaseIdentityId);
  validateServicePin(service(observation, "controller_run_reader"), pins.controllerRunReader);
  validateServicePin(service(observation, "governance_reader"), pins.governanceReader);
  return observation;
}

/**
 * Re-establish a bounded fixed-length stream at ingress. The archive digest is
 * provider-declared in the observation and independently checked by the
 * controller action while consuming these bytes.
 */
export async function buildRuntimeClosureResponse(
  stream: RuntimeClosureStream,
  pins: RuntimeClosureResponsePins,
  requestId: string,
  pipePolicy: BoundedPipePolicy = RUNTIME_CLOSURE_STREAM_PIPE_POLICY,
): Promise<Response> {
  assert(
    stream.length >= 1 && stream.length <= RUNTIME_CLOSURE_MAX_RAW_BYTES,
    "RUNTIME_CLOSURE_STREAM_LENGTH_INVALID",
    500,
  );
  validateRuntimeClosureObservation(stream.observation);
  await verifyRuntimeClosureObservationBindings(stream.observation);
  const encoded = await encodeRuntimeClosureObservation(stream.observation);
  assert(
    encoded.base64url === stream.observationBase64url &&
      encoded.digest === stream.observationSha256,
    "RUNTIME_CLOSURE_OBSERVATION_DIGEST_MISMATCH",
    500,
  );
  requireLiteral(stream.observation, "broker_request_id", requestId);
  const artifact = requireObject(
    stream.observation.closure_artifact,
    "RUNTIME_CLOSURE_OBSERVATION_INVALID",
  );
  assert(
    requireInteger(artifact, "size_bytes", 1, RUNTIME_CLOSURE_MAX_RAW_BYTES) === stream.length,
    "RUNTIME_CLOSURE_STREAM_LENGTH_MISMATCH",
    500,
  );
  validateServicePin(
    service(stream.observation, "controller_run_reader"),
    pins.controllerRunReader,
  );
  validateServicePin(service(stream.observation, "governance_reader"), pins.governanceReader);
  assert(DIGEST.test(stream.observationSha256), "RUNTIME_CLOSURE_OBSERVATION_INVALID", 500);
  assert(
    /^[A-Za-z0-9_-]{1,16384}$/u.test(stream.observationBase64url) &&
      stream.observationBase64url.length <= OBSERVATION_MAX_BASE64URL,
    "RUNTIME_CLOSURE_OBSERVATION_INVALID",
    500,
  );
  const body = boundedFixedLengthStream(
    stream.body,
    stream.length,
    "RUNTIME_CLOSURE_PRIVATE_BODY",
    pipePolicy,
  );
  return new Response(body, {
    headers: {
      "cache-control": "private, no-store, max-age=0",
      "content-type": RUNTIME_CLOSURE_MEDIA_TYPE,
      [RUNTIME_CLOSURE_CONTROLLER_SERVICE_IDENTITY_HEADER]:
        pins.controllerRunReader.serviceIdentity,
      [RUNTIME_CLOSURE_CONTROLLER_SERVICE_VERSION_HEADER]: pins.controllerRunReader.versionId,
      [RUNTIME_CLOSURE_GOVERNANCE_SERVICE_IDENTITY_HEADER]: pins.governanceReader.serviceIdentity,
      [RUNTIME_CLOSURE_GOVERNANCE_SERVICE_VERSION_HEADER]: pins.governanceReader.versionId,
      [RUNTIME_CLOSURE_OBSERVATION_DIGEST_HEADER]: stream.observationSha256,
      [RUNTIME_CLOSURE_OBSERVATION_HEADER]: stream.observationBase64url,
      [RUNTIME_CLOSURE_REQUEST_ID_HEADER]: requestId,
      [RUNTIME_CLOSURE_RESPONSE_SCHEMA_HEADER]: RUNTIME_CLOSURE_RESPONSE_SCHEMA,
      "x-content-type-options": "nosniff",
    },
    status: 200,
  });
}
