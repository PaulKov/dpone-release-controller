import { describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical";
import {
  buildCandidateReaderRpcRequest,
  decodeCandidateObservation,
  encodeCandidateObservation,
  parseCandidateReaderRpcRequest,
} from "../src/private/candidate-rpc";
import { CANDIDATE_NOW, candidateHarness } from "./support/candidate-provider-fixture";

describe("candidate reader closed RPC", () => {
  it("round-trips the exact six selectors plus A1 policy authority", async () => {
    const harness = await candidateHarness();
    const body = buildCandidateReaderRpcRequest(harness.input, harness.authority);
    expect(Object.keys(body).sort()).toEqual([
      "artifact_digest",
      "artifact_id",
      "peeled_commit_sha",
      "policy_blob_sha",
      "policy_sha256",
      "release",
      "request_id",
      "run_attempt",
      "run_id",
      "schema",
      "schema_version",
    ]);
    expect(parseCandidateReaderRpcRequest(JSON.parse(canonicalJson(body)))).toEqual({
      authority: harness.authority,
      input: harness.input,
    });
  });

  it("rejects aliases, unsafe IDs, booleans and caller-selected provider fields", async () => {
    const harness = await candidateHarness();
    const body = buildCandidateReaderRpcRequest(harness.input, harness.authority);
    for (const invalid of [
      { ...body, artifact_id: false },
      { ...body, artifact_id: Number.MAX_SAFE_INTEGER + 1 },
      { ...body, artifact_name: "release-candidates" },
      { ...body, app_id: "101" },
      { ...body, source_url: "https://evil.invalid" },
    ]) {
      expect(() => parseCandidateReaderRpcRequest(invalid)).toThrow();
    }
  });

  it("binds a canonical observation header to every request selector and expiry", async () => {
    const harness = await candidateHarness();
    const result = await harness.reader.authorize(harness.input, harness.authority);
    const service = {
      identity: "cloudflare-worker:account/service@candidate-reader-version-0001",
      versionId: "candidate-reader-version-0001",
    };
    const projected = {
      ...result.observation,
      candidate_reader_service_identity: service.identity,
      candidate_reader_service_version_id: service.versionId,
    };
    const encoded = await encodeCandidateObservation(projected);
    const decoded = await decodeCandidateObservation(
      encoded.base64url,
      encoded.digest,
      { authority: harness.authority, input: harness.input },
      service,
      CANDIDATE_NOW,
    );
    expect(decoded.observation).toEqual(projected);
    expect(decoded.sizeBytes).toBe(4);

    await expect(
      decodeCandidateObservation(
        encoded.base64url,
        "sha256:" + "0".repeat(64),
        { authority: harness.authority, input: harness.input },
        service,
        CANDIDATE_NOW,
      ),
    ).rejects.toThrow("CANDIDATE_OBSERVATION_DIGEST_MISMATCH");
    await expect(
      decodeCandidateObservation(
        encoded.base64url,
        encoded.digest,
        {
          authority: harness.authority,
          input: { ...harness.input, runId: harness.input.runId + 1 },
        },
        service,
        CANDIDATE_NOW,
      ),
    ).rejects.toThrow();
    await expect(
      decodeCandidateObservation(
        encoded.base64url,
        encoded.digest,
        { authority: harness.authority, input: harness.input },
        service,
        Date.parse("2026-08-15T12:00:46Z"),
      ),
    ).rejects.toThrow("CANDIDATE_OBSERVATION_EXPIRY_INVALID");
  });
});
