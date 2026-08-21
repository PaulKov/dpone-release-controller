import { describe, expect, it } from "vitest";

import {
  RUNTIME_CLOSURE_CONTROLLER_SERVICE_IDENTITY_HEADER,
  RUNTIME_CLOSURE_GOVERNANCE_SERVICE_VERSION_HEADER,
  RUNTIME_CLOSURE_MEDIA_TYPE,
  RUNTIME_CLOSURE_OBSERVATION_DIGEST_HEADER,
  RUNTIME_CLOSURE_OBSERVATION_HEADER,
  RUNTIME_CLOSURE_REQUEST_SCHEMA,
  RUNTIME_CLOSURE_RESPONSE_SCHEMA,
  RUNTIME_CLOSURE_RESPONSE_SCHEMA_HEADER,
  buildRuntimeClosureResponse,
  canonicalRuntimeClosureRequestBytes,
  decodeRuntimeClosureObservation,
  encodeRuntimeClosureObservation,
  parseRuntimeClosureRequest,
  verifyRuntimeClosureObservationBindings,
} from "../src/runtime-closure";
import type { JsonObject } from "../src/types";
import {
  CONTROLLER_PIN,
  DIGEST,
  GOVERNANCE_PIN,
  RELEASE_IDENTITY_ID,
  REQUEST_ID,
  SHA,
  validObservation,
} from "./runtime-closure.fixtures";

describe("runtime CLOSED-read frozen transport", () => {
  it("accepts only the canonical one-selector public request", () => {
    const input = parseRuntimeClosureRequest(
      {
        release_identity_id: RELEASE_IDENTITY_ID,
        schema: RUNTIME_CLOSURE_REQUEST_SCHEMA,
        schema_version: 1,
      },
      REQUEST_ID,
    );
    expect(new TextDecoder().decode(canonicalRuntimeClosureRequestBytes(input))).toBe(
      `{"release_identity_id":"${RELEASE_IDENTITY_ID}","schema":"${RUNTIME_CLOSURE_REQUEST_SCHEMA}","schema_version":1}`,
    );
    expect(() =>
      parseRuntimeClosureRequest(
        {
          broker_url: "https://attacker.invalid",
          release_identity_id: RELEASE_IDENTITY_ID,
          schema: RUNTIME_CLOSURE_REQUEST_SCHEMA,
          schema_version: 1,
        },
        REQUEST_ID,
      ),
    ).toThrow("UNKNOWN_FIELD");
  });

  it("canonicalizes, digests and cross-binds the complete provider observation", async () => {
    const observation = await validObservation();
    const encoded = await encodeRuntimeClosureObservation(observation);
    const decoded = await decodeRuntimeClosureObservation(
      encoded.base64url,
      encoded.digest,
      { releaseIdentityId: RELEASE_IDENTITY_ID, requestId: REQUEST_ID },
      { controllerRunReader: CONTROLLER_PIN, governanceReader: GOVERNANCE_PIN },
    );
    expect(decoded).toEqual(observation);
    expect(encoded.digest).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(encoded.text.endsWith("\n")).toBe(false);
  });

  it("re-establishes a bounded fixed-length public stream with an exact header allowlist", async () => {
    const bytes = new TextEncoder().encode("ZIP!");
    const observation = await validObservation(bytes.byteLength);
    const encoded = await encodeRuntimeClosureObservation(observation);
    const response = await buildRuntimeClosureResponse(
      {
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(bytes);
            controller.close();
          },
        }),
        length: bytes.byteLength,
        observation,
        observationBase64url: encoded.base64url,
        observationSha256: encoded.digest,
      },
      { controllerRunReader: CONTROLLER_PIN, governanceReader: GOVERNANCE_PIN },
      REQUEST_ID,
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe(RUNTIME_CLOSURE_MEDIA_TYPE);
    expect(response.headers.get(RUNTIME_CLOSURE_RESPONSE_SCHEMA_HEADER)).toBe(
      RUNTIME_CLOSURE_RESPONSE_SCHEMA,
    );
    expect(response.headers.get(RUNTIME_CLOSURE_OBSERVATION_HEADER)).toBe(encoded.base64url);
    expect(response.headers.get(RUNTIME_CLOSURE_OBSERVATION_DIGEST_HEADER)).toBe(encoded.digest);
    expect(response.headers.get(RUNTIME_CLOSURE_CONTROLLER_SERVICE_IDENTITY_HEADER)).toBe(
      CONTROLLER_PIN.serviceIdentity,
    );
    expect(response.headers.get(RUNTIME_CLOSURE_GOVERNANCE_SERVICE_VERSION_HEADER)).toBe(
      GOVERNANCE_PIN.versionId,
    );
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytes);
  });

  it("rejects a non-adjacent C5/LEASE_RELEASED pair and marker/artifact drift", async () => {
    const nonAdjacent = await validObservation();
    (nonAdjacent.ledger as JsonObject).head_sequence = 116;
    await expect(verifyRuntimeClosureObservationBindings(nonAdjacent)).rejects.toThrow();
    await expect(encodeRuntimeClosureObservation(nonAdjacent)).rejects.toThrow(
      "RUNTIME_CLOSURE_OBSERVATION_INVALID",
    );

    const drifted = await validObservation();
    (drifted.closure_artifact as JsonObject).digest = DIGEST("f");
    await expect(encodeRuntimeClosureObservation(drifted)).rejects.toThrow(
      "RUNTIME_CLOSURE_OBSERVATION_INVALID",
    );
  });

  it("rejects Commit A when it equals controller workflow Commit P", async () => {
    const actionEqualsControllerWorkflow = await validObservation(4, SHA("b"));
    await expect(
      verifyRuntimeClosureObservationBindings(actionEqualsControllerWorkflow),
    ).rejects.toThrow("RUNTIME_CLOSURE_OBSERVATION_INVALID");
  });

  it("reuses the A1 epoch while rejecting release policy/workflow lineage drift", async () => {
    const valid = await validObservation();
    expect((valid.activation as JsonObject).target_policy_commit_sha).not.toBe(
      (valid.runtime as JsonObject).peeled_commit_sha,
    );
    await expect(verifyRuntimeClosureObservationBindings(valid)).resolves.toBeUndefined();

    for (const drift of [
      { policy_blob_sha: SHA("8") },
      { policy_source_commit_sha: SHA("8") },
      { workflow_blob_sha: SHA("8") },
      { workflow_source_commit_sha: SHA("8") },
    ]) {
      const observation = await validObservation();
      Object.assign(observation.runtime as JsonObject, drift);
      await expect(verifyRuntimeClosureObservationBindings(observation)).rejects.toThrow(
        "RUNTIME_CLOSURE_OBSERVATION_INVALID",
      );
    }
  });

  it("rejects a tagged commit that is not contained in the protected default branch", async () => {
    const unmergedTag = await validObservation();
    (unmergedTag.target_lineage as JsonObject).release_merge_base_commit_sha = SHA("8");
    await expect(verifyRuntimeClosureObservationBindings(unmergedTag)).rejects.toThrow(
      "TARGET_LINEAGE_INVALID",
    );
  });

  it("rejects stale and future protected-lineage provider observations", async () => {
    for (const observedAt of ["2026-08-15T11:58:59Z", "2026-08-15T12:00:01Z"]) {
      const observation = await validObservation();
      (observation.target_lineage as JsonObject).observed_at = observedAt;
      await expect(verifyRuntimeClosureObservationBindings(observation)).rejects.toThrow(
        "TARGET_LINEAGE_INVALID",
      );
    }
  });

  it("bounds the provider archive URL to sixty seconds after broker acceptance", async () => {
    await expect(
      encodeRuntimeClosureObservation(
        await validObservation(4, SHA("d"), "2026-08-15T12:00:01Z", "2026-08-15T12:00:00Z"),
      ),
    ).rejects.toThrow("RUNTIME_CLOSURE_OBSERVATION_INVALID");
    await expect(
      encodeRuntimeClosureObservation(
        await validObservation(4, SHA("d"), "2026-08-15T12:00:00Z", "2026-08-15T12:01:01Z"),
      ),
    ).rejects.toThrow("RUNTIME_CLOSURE_OBSERVATION_INVALID");
    const boundary = await encodeRuntimeClosureObservation(
      await validObservation(4, SHA("d"), "2026-08-15T12:00:00Z", "2026-08-15T12:01:00Z"),
    );
    expect(boundary.digest).toMatch(/^sha256:[0-9a-f]{64}$/u);
  });
});
