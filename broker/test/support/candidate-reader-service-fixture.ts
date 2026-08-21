import type { CandidateReaderStream } from "../../src/candidate-reader-client";
import {
  CANDIDATE_MEDIA_TYPE,
  CANDIDATE_OBSERVATION_DIGEST_HEADER,
  CANDIDATE_OBSERVATION_HEADER,
  CANDIDATE_RESPONSE_REQUEST_ID_HEADER,
  CANDIDATE_RESPONSE_SCHEMA,
  CANDIDATE_RESPONSE_SCHEMA_HEADER,
  CANDIDATE_SERVICE_IDENTITY_HEADER,
  CANDIDATE_SERVICE_VERSION_HEADER,
  encodeCandidateObservation,
} from "../../src/private/candidate-rpc";
import type { JsonObject, PrivateServicePin } from "../../src/types";
import { CANDIDATE_NOW, CANDIDATE_ZIP, candidateHarness } from "./candidate-provider-fixture";

export const CANDIDATE_READER_PIN: PrivateServicePin = {
  serviceIdentity:
    "cloudflare-worker:account/candidate-reader-private@candidate-reader-version-0001",
  serviceName: "candidate-reader-private",
  versionId: "candidate-reader-version-0001",
};

export interface CandidateServiceFixture {
  readonly authority: Awaited<ReturnType<typeof candidateHarness>>["authority"];
  readonly input: Awaited<ReturnType<typeof candidateHarness>>["input"];
  readonly observation: JsonObject;
  readonly observationBase64url: string;
  readonly observationSha256: string;
}

export async function candidateServiceFixture(): Promise<CandidateServiceFixture> {
  const harness = await candidateHarness();
  const result = await harness.reader.authorize(harness.input, harness.authority);
  const observation: JsonObject = {
    ...result.observation,
    candidate_reader_service_identity: CANDIDATE_READER_PIN.serviceIdentity,
    candidate_reader_service_version_id: CANDIDATE_READER_PIN.versionId,
  };
  const encoded = await encodeCandidateObservation(observation);
  return {
    authority: harness.authority,
    input: harness.input,
    observation,
    observationBase64url: encoded.base64url,
    observationSha256: encoded.digest,
  };
}

export function candidateServiceResponse(
  fixture: CandidateServiceFixture,
  options: {
    readonly body?: BodyInit;
    readonly headers?: Readonly<Record<string, string>>;
    readonly status?: number;
  } = {},
): Response {
  return new Response(options.body ?? CANDIDATE_ZIP, {
    headers: {
      "cache-control": "private, no-store, max-age=0",
      "content-length": String(CANDIDATE_ZIP.byteLength),
      "content-type": CANDIDATE_MEDIA_TYPE,
      [CANDIDATE_OBSERVATION_DIGEST_HEADER]: fixture.observationSha256,
      [CANDIDATE_OBSERVATION_HEADER]: fixture.observationBase64url,
      [CANDIDATE_RESPONSE_REQUEST_ID_HEADER]: fixture.input.requestId,
      [CANDIDATE_RESPONSE_SCHEMA_HEADER]: CANDIDATE_RESPONSE_SCHEMA,
      [CANDIDATE_SERVICE_IDENTITY_HEADER]: CANDIDATE_READER_PIN.serviceIdentity,
      [CANDIDATE_SERVICE_VERSION_HEADER]: CANDIDATE_READER_PIN.versionId,
      "x-content-type-options": "nosniff",
      ...options.headers,
    },
    status: options.status ?? 200,
  });
}

export function asCandidateReaderStream(fixture: CandidateServiceFixture): CandidateReaderStream {
  const body = new Response(CANDIDATE_ZIP).body;
  if (body === null) throw new Error("candidate stream fixture has no body");
  return {
    body,
    length: CANDIDATE_ZIP.byteLength,
    observation: fixture.observation,
    observationBase64url: fixture.observationBase64url,
    observationSha256: fixture.observationSha256,
  };
}

export const candidateServiceNow = (): number => CANDIDATE_NOW;
