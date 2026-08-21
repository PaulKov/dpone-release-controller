import type { CandidateReaderStream } from "./candidate-reader-client";
import { boundedFixedLengthStream, type BoundedPipePolicy } from "./bounded";
import { assert } from "./errors";
import type { JsonObject, PrivateServicePin } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";
import {
  CANDIDATE_STREAM_PIPE_POLICY,
  type CandidateProviderInput,
} from "./private/candidate-contract";
import {
  CANDIDATE_MEDIA_TYPE,
  CANDIDATE_OBSERVATION_DIGEST_HEADER,
  CANDIDATE_OBSERVATION_HEADER,
  CANDIDATE_RESPONSE_REQUEST_ID_HEADER,
  CANDIDATE_RESPONSE_SCHEMA,
  CANDIDATE_RESPONSE_SCHEMA_HEADER,
  CANDIDATE_SERVICE_IDENTITY_HEADER,
  CANDIDATE_SERVICE_VERSION_HEADER,
} from "./private/candidate-rpc";

export const CANDIDATE_PUBLIC_PATH = "/v1/providers/github/candidate";
export const CANDIDATE_STREAM_REQUEST_SCHEMA = "dpone.release-candidate-stream-request.v1";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SHA1 = /^[0-9a-f]{40}$/u;
const TAG = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;

/** Parses the frozen six-selector public request; provider authority is absent. */
export function parseCandidateStreamRequest(
  value: unknown,
  requestId: string,
): CandidateProviderInput {
  assert(REQUEST_ID.test(requestId), "REQUEST_ID_INVALID");
  const body = exactObject(value, [
    "candidate_artifact_digest",
    "candidate_artifact_id",
    "candidate_run_attempt",
    "candidate_run_id",
    "expected_peeled_commit_sha",
    "schema",
    "schema_version",
    "tag",
  ]);
  requireLiteral(body, "schema", CANDIDATE_STREAM_REQUEST_SCHEMA);
  requireExactInteger(body, "schema_version", 1);
  return {
    artifactDigest: requireString(body, "candidate_artifact_digest", 71, DIGEST),
    artifactId: requireInteger(body, "candidate_artifact_id", 1),
    peeledCommitSha: requireString(body, "expected_peeled_commit_sha", 40, SHA1),
    release: requireString(body, "tag", 64, TAG),
    requestId,
    runAttempt: requireInteger(body, "candidate_run_attempt", 1, 1000),
    runId: requireInteger(body, "candidate_run_id", 1),
  };
}

/**
 * Re-establishes a fixed-length stream at the public Worker boundary. A
 * generic Service Binding response stream is deliberately never trusted to
 * preserve Content-Length metadata across isolates.
 */
export function buildCandidateStreamResponse(
  stream: CandidateReaderStream,
  pin: PrivateServicePin,
  requestId: string,
  pipePolicy: BoundedPipePolicy = CANDIDATE_STREAM_PIPE_POLICY,
): Response {
  assert(
    stream.length >= 1 && stream.length <= 805_306_368,
    "CANDIDATE_STREAM_LENGTH_INVALID",
    500,
  );
  assert(
    requireInteger(stream.observation, "artifact_size_bytes", 1, 805_306_368) === stream.length,
    "CANDIDATE_STREAM_LENGTH_MISMATCH",
    500,
  );
  assert(
    stream.observation.candidate_reader_service_identity === pin.serviceIdentity &&
      stream.observation.candidate_reader_service_version_id === pin.versionId,
    "CANDIDATE_STREAM_SERVICE_MISMATCH",
    500,
  );
  const body = boundedFixedLengthStream(
    stream.body,
    stream.length,
    "CANDIDATE_PRIVATE_BODY",
    pipePolicy,
  );
  return new Response(body, {
    headers: {
      "cache-control": "private, no-store, max-age=0",
      "content-type": CANDIDATE_MEDIA_TYPE,
      [CANDIDATE_OBSERVATION_DIGEST_HEADER]: stream.observationSha256,
      [CANDIDATE_OBSERVATION_HEADER]: stream.observationBase64url,
      [CANDIDATE_RESPONSE_REQUEST_ID_HEADER]: requestId,
      [CANDIDATE_RESPONSE_SCHEMA_HEADER]: CANDIDATE_RESPONSE_SCHEMA,
      [CANDIDATE_SERVICE_IDENTITY_HEADER]: pin.serviceIdentity,
      [CANDIDATE_SERVICE_VERSION_HEADER]: pin.versionId,
      "x-content-type-options": "nosniff",
    },
    status: 200,
  });
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, Math.max(1, expected.length)) === expected,
    "CANDIDATE_STREAM_REQUEST_INVALID",
  );
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "CANDIDATE_STREAM_REQUEST_INVALID",
  );
}
