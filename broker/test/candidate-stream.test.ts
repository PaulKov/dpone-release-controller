import { describe, expect, it } from "vitest";

import { buildCandidateStreamResponse, parseCandidateStreamRequest } from "../src/candidate-stream";
import { decodeCandidateObservation } from "../src/private/candidate-rpc";
import type { JsonObject } from "../src/types";
import contractVector from "./fixtures/release-candidate-stream-v1.json";
import { CANDIDATE_ZIP } from "./support/candidate-provider-fixture";
import {
  CANDIDATE_READER_PIN,
  asCandidateReaderStream,
  candidateServiceFixture,
} from "./support/candidate-reader-service-fixture";

describe("public candidate ZIP stream contract", () => {
  it("consumes the proposed Python contract vector byte-for-byte", async () => {
    const request = contractVector.request;
    const parsed = parseCandidateStreamRequest(request.body, request.headers["x-request-id"]);
    expect(parsed).toEqual({
      artifactDigest: request.body.candidate_artifact_digest,
      artifactId: request.body.candidate_artifact_id,
      peeledCommitSha: request.body.expected_peeled_commit_sha,
      release: request.body.tag,
      requestId: request.headers["x-request-id"],
      runAttempt: request.body.candidate_run_attempt,
      runId: request.body.candidate_run_id,
    });

    const responseHeaders = contractVector.response.headers;
    const decoded = await decodeCandidateObservation(
      responseHeaders["x-dpone-provider-observation"],
      responseHeaders["x-dpone-provider-observation-sha256"],
      {
        authority: {
          policyBlobSha: "c".repeat(40),
          policySha256: tagged("d"),
        },
        input: parsed,
      },
      {
        identity: responseHeaders["x-dpone-candidate-reader-service-identity"],
        versionId: responseHeaders["x-dpone-candidate-reader-service-version-id"],
      },
      Date.parse("2026-08-15T00:00:30Z"),
    );
    expect(decoded.sizeBytes).toBe(Number(responseHeaders["content-length"]));
    expect(decoded.observation.release).toBe(request.body.tag);
  });

  it("rejects selector aliases, unsafe IDs and provider authority", () => {
    const valid = contractVector.request.body as JsonObject;
    const requestId = contractVector.request.headers["x-request-id"];
    for (const invalid of [
      { ...valid, candidate_artifact_id: false },
      { ...valid, candidate_artifact_id: Number.MAX_SAFE_INTEGER + 1 },
      { ...valid, candidate_run_id: 0 },
      { ...valid, app_id: 101 },
      { ...valid, policy_sha256: tagged("d") },
      { ...valid, source_url: "https://evil.invalid" },
    ]) {
      expect(() => parseCandidateStreamRequest(invalid, requestId)).toThrow();
    }
  });

  it("rewraps the private body with only exact public metadata", async () => {
    const fixture = await candidateServiceFixture();
    const response = buildCandidateStreamResponse(
      asCandidateReaderStream(fixture),
      CANDIDATE_READER_PIN,
      fixture.input.requestId,
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("private, no-store, max-age=0");
    expect(response.headers.get("content-type")).toBe(
      "application/vnd.dpone.release-candidate-artifact.v1+zip",
    );
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.has("location")).toBe(false);
    expect(response.headers.has("set-cookie")).toBe(false);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(CANDIDATE_ZIP);
  });

  it("fails before streaming on service or declared-size confusion", async () => {
    const wrongService = await candidateServiceFixture();
    expect(() =>
      buildCandidateStreamResponse(
        asCandidateReaderStream(wrongService),
        { ...CANDIDATE_READER_PIN, versionId: "candidate-reader-version-0002" },
        wrongService.input.requestId,
      ),
    ).toThrow("CANDIDATE_STREAM_SERVICE_MISMATCH");

    const wrongLength = await candidateServiceFixture();
    expect(() =>
      buildCandidateStreamResponse(
        { ...asCandidateReaderStream(wrongLength), length: CANDIDATE_ZIP.byteLength + 1 },
        CANDIDATE_READER_PIN,
        wrongLength.input.requestId,
      ),
    ).toThrow("CANDIDATE_STREAM_LENGTH_MISMATCH");
  });
});

function tagged(character: string): string {
  return `sha256:${character.repeat(64)}`;
}
