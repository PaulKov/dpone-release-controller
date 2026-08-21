import { describe, expect, it } from "vitest";

import {
  assertUntrustedProofFresh,
  buildUnpersistedActivationProofCandidate,
  parseCanonicalUntrustedActivationProof,
  parseUntrustedActivationProof,
} from "../src/candidate-public-v2/activation-proof";
import {
  canonicalPublicV2Bytes,
  canonicalPublicV2Snapshot,
} from "../src/candidate-public-v2/canonical";
import { verifySidecarOpening } from "../src/candidate-public-v2/sidecar";
import { objectField } from "../src/candidate-public-v2/validation";
import { buildFullCandidate, digest, nonce, privatePayload } from "./candidate-public-v2-fixtures";

describe("candidate public-v2 activation proof", () => {
  it("derives exact floor-second admission and a 60-second expiry from DI clock", async () => {
    const { proof } = await buildFullCandidate();
    expect(proof.document.admitted_at).toBe("2023-11-14T22:13:20Z");
    expect(proof.document.expires_at).toBe("2023-11-14T22:14:20Z");
    expect(proof.dispatchSafety).toBe("UNPERSISTED_CANDIDATE_NOT_DISPATCH_SAFE");
    expect((await parseCanonicalUntrustedActivationProof(proof.documentBytes)).proof_id).toBe(
      proof.document.proof_id,
    );
    await verifySidecarOpening({
      kind: "ACTIVATION_PROOF",
      opening: proof.opening,
      privatePayloadBytes: proof.privatePayloadBytes,
      publicDocument: proof.document,
    });
  });

  it("ignores caller-shaped time fields and trusts only the injected clock", async () => {
    const { activated, provisioned } = await buildFullCandidate();
    const callerShapedInput = {
      activated: activated.document,
      admittedAt: "2099-01-01T00:00:00Z",
      clock: { nowMs: () => 1_700_000_001_001 },
      nonce: nonce(3),
      privatePayload: privatePayload("ACTIVATION_PROOF"),
      provisioned: provisioned.document,
    };
    const proof = await buildUnpersistedActivationProofCandidate(callerShapedInput);
    expect(proof.document.admitted_at).toBe("2023-11-14T22:13:21Z");
  });

  it("rejects out-of-range clocks with the uniform candidate error", async () => {
    const { activated, provisioned } = await buildFullCandidate();
    await expect(
      buildUnpersistedActivationProofCandidate({
        activated: activated.document,
        clock: { nowMs: () => 8_639_999_999_940_001 },
        nonce: nonce(3),
        privatePayload: privatePayload("ACTIVATION_PROOF"),
        provisioned: provisioned.document,
      }),
    ).rejects.toMatchObject({ code: "PUBLIC_V2_PROOF_NOW_INVALID" });
  });

  it("snapshots embedded A0/A1 and object input before any digest await", async () => {
    const { activated, provisioned } = await buildFullCandidate();
    const originalActivatedId = activated.document.record_id;
    const promise = buildUnpersistedActivationProofCandidate({
      activated: activated.document,
      clock: { nowMs: () => 1_700_000_000_999 },
      nonce: nonce(3),
      privatePayload: privatePayload("ACTIVATION_PROOF"),
      provisioned: provisioned.document,
    });
    activated.document.record_id = digest("f");
    const proof = await promise;
    const activation = objectField(proof.document, "activation", "test");
    expect(objectField(activation, "activated", "test").record_id).toBe(originalActivatedId);

    const mutable = canonicalPublicV2Snapshot(proof.document);
    const parsedPromise = parseUntrustedActivationProof(mutable);
    const mutableActivation = objectField(mutable, "activation", "test");
    objectField(mutableActivation, "activated", "test").record_id = digest("e");
    const parsedActivation = objectField(await parsedPromise, "activation", "test");
    expect(objectField(parsedActivation, "activated", "test").record_id).toBe(originalActivatedId);
  });

  it("rejects TTL tampering and enforces half-open freshness", async () => {
    const { proof } = await buildFullCandidate();
    const tampered = canonicalPublicV2Snapshot(proof.document);
    tampered.expires_at = tampered.admitted_at ?? null;
    await expect(
      parseCanonicalUntrustedActivationProof(canonicalPublicV2Bytes(tampered)),
    ).rejects.toMatchObject({ code: "PUBLIC_V2_PROOF_TTL_INVALID" });

    assertUntrustedProofFresh(proof.document, 1_700_000_020_000);
    expect(() => assertUntrustedProofFresh(proof.document, 1_700_000_080_000)).toThrowError(
      "PUBLIC_V2_PROOF_NOT_FRESH",
    );
  });
});
