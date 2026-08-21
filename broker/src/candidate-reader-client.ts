import { assert, BrokerError } from "./errors";
import { callPinnedService } from "./service-version";
import type { JsonObject, PrivateServicePin } from "./types";
import {
  type CandidateActivatedAuthority,
  type CandidateProviderInput,
} from "./private/candidate-contract";
import {
  CANDIDATE_OBSERVATION_DIGEST_HEADER,
  CANDIDATE_OBSERVATION_HEADER,
  CANDIDATE_MEDIA_TYPE,
  CANDIDATE_RESPONSE_REQUEST_ID_HEADER,
  CANDIDATE_RESPONSE_SCHEMA,
  CANDIDATE_RESPONSE_SCHEMA_HEADER,
  CANDIDATE_RPC_PATH,
  CANDIDATE_SERVICE_IDENTITY_HEADER,
  CANDIDATE_SERVICE_VERSION_HEADER,
  buildCandidateReaderRpcRequest,
  canonicalCandidateRpcBytes,
  decodeCandidateObservation,
} from "./private/candidate-rpc";

export interface CandidateReaderStream {
  readonly body: ReadableStream<Uint8Array>;
  readonly length: number;
  readonly observationBase64url: string;
  readonly observation: JsonObject;
  readonly observationSha256: string;
}

/**
 * Narrow client for the version-pinned candidate-reader private Worker.
 * Neither installation tokens nor provider-signed URLs cross this boundary.
 */
export class CandidateReaderClient {
  public constructor(
    private readonly service: Fetcher,
    private readonly pin: PrivateServicePin,
    private readonly now: () => number = Date.now,
  ) {}

  public async open(
    input: CandidateProviderInput,
    authority: CandidateActivatedAuthority,
  ): Promise<CandidateReaderStream> {
    const request = { authority, input };
    const body = canonicalCandidateRpcBytes(request);
    const response = await callPinnedService(this.service, this.pin, {
      body: Uint8Array.from(body).buffer,
      headers: {
        accept: CANDIDATE_MEDIA_TYPE,
        "content-length": String(body.byteLength),
        "content-type": "application/json",
        [CANDIDATE_SERVICE_IDENTITY_HEADER]: this.pin.serviceIdentity,
        "x-request-id": input.requestId,
      },
      method: "POST",
      path: CANDIDATE_RPC_PATH,
    });
    try {
      return await this.validateResponse(response, request);
    } catch (error) {
      await response.body?.cancel().catch(() => undefined);
      throw error;
    }
  }

  private async validateResponse(
    response: Response,
    request: {
      readonly authority: CandidateActivatedAuthority;
      readonly input: CandidateProviderInput;
    },
  ): Promise<CandidateReaderStream> {
    if (response.status !== 200) {
      throw new BrokerError(
        "CANDIDATE_READER_FAILED",
        503,
        response.status === 429 || response.status >= 500,
      );
    }
    assert(!response.redirected, "CANDIDATE_READER_REDIRECT_FORBIDDEN", 503);
    assertExactResponseHeaders(response.headers);
    assert(
      response.headers.get("content-type") === CANDIDATE_MEDIA_TYPE &&
        response.headers.get("cache-control") === "private, no-store, max-age=0" &&
        response.headers.get("x-content-type-options") === "nosniff" &&
        !response.headers.has("content-encoding") &&
        !response.headers.has("content-range") &&
        !response.headers.has("transfer-encoding") &&
        !response.headers.has("set-cookie"),
      "CANDIDATE_READER_HEADERS_INVALID",
      503,
    );
    assert(
      response.headers.get(CANDIDATE_RESPONSE_REQUEST_ID_HEADER) === request.input.requestId,
      "CANDIDATE_READER_REQUEST_ID_MISMATCH",
      503,
    );
    assert(
      response.headers.get(CANDIDATE_SERVICE_IDENTITY_HEADER) === this.pin.serviceIdentity,
      "CANDIDATE_READER_SERVICE_IDENTITY_MISMATCH",
      503,
    );
    assert(
      response.headers.get(CANDIDATE_SERVICE_VERSION_HEADER) === this.pin.versionId,
      "SERVICE_VERSION_MISMATCH",
      503,
    );
    assert(
      response.headers.get(CANDIDATE_RESPONSE_SCHEMA_HEADER) === CANDIDATE_RESPONSE_SCHEMA,
      "CANDIDATE_READER_HEADERS_INVALID",
      503,
    );
    const encoded = response.headers.get(CANDIDATE_OBSERVATION_HEADER);
    const digest = response.headers.get(CANDIDATE_OBSERVATION_DIGEST_HEADER);
    assert(encoded !== null && digest !== null, "CANDIDATE_OBSERVATION_HEADER_INVALID", 503);
    const decoded = await decodeCandidateObservation(
      encoded,
      digest,
      request,
      { identity: this.pin.serviceIdentity, versionId: this.pin.versionId },
      this.now(),
    );
    const contentLength = response.headers.get("content-length");
    assert(
      contentLength !== null && /^[1-9][0-9]{0,15}$/u.test(contentLength),
      "CANDIDATE_READER_LENGTH_INVALID",
      503,
    );
    const length = Number(contentLength);
    assert(
      Number.isSafeInteger(length) && length === decoded.sizeBytes && response.body !== null,
      "CANDIDATE_READER_LENGTH_INVALID",
      503,
    );
    return {
      body: response.body,
      length,
      observationBase64url: encoded,
      observation: decoded.observation,
      observationSha256: digest,
    };
  }
}

function assertExactResponseHeaders(headers: Headers): void {
  const allowed = new Set([
    "cache-control",
    "content-length",
    "content-type",
    CANDIDATE_OBSERVATION_DIGEST_HEADER,
    CANDIDATE_OBSERVATION_HEADER,
    CANDIDATE_RESPONSE_REQUEST_ID_HEADER,
    CANDIDATE_RESPONSE_SCHEMA_HEADER,
    CANDIDATE_SERVICE_IDENTITY_HEADER,
    CANDIDATE_SERVICE_VERSION_HEADER,
    "x-content-type-options",
  ]);
  for (const name of headers.keys()) {
    assert(allowed.has(name.toLowerCase()), "CANDIDATE_READER_HEADERS_INVALID", 503);
  }
}

export function candidateReaderRequestBody(
  input: CandidateProviderInput,
  authority: CandidateActivatedAuthority,
): JsonObject {
  return buildCandidateReaderRpcRequest(input, authority);
}
