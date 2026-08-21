import { describe, expect, it } from "vitest";

import {
  buildUnpersistedActivatedCandidate,
  buildUnpersistedProvisionedCandidate,
  parseCanonicalUntrustedActivationPair,
  parseCanonicalUntrustedProvisionedPublicCore,
  parseUntrustedProvisionedPublicCore,
} from "../src/candidate-public-v2/activation-core";
import {
  canonicalPublicV2Bytes,
  canonicalPublicV2Snapshot,
  parseCanonicalPublicV2,
} from "../src/candidate-public-v2/canonical";
import { verifySidecarOpening } from "../src/candidate-public-v2/sidecar";
import {
  BASELINE_SOURCE,
  BROKER_SOURCE,
  CONTROLLER_SOURCE,
  buildFullCandidate,
  digest,
  nonce,
  privatePayload,
} from "./candidate-public-v2-fixtures";

describe("candidate public-v2 activation cores and sidecars", () => {
  it("round-trips the fused A0/A1 pair while remaining explicitly unpersisted", async () => {
    const { activated, provisioned } = await buildFullCandidate();
    const pair = await parseCanonicalUntrustedActivationPair({
      activated: activated.documentBytes,
      provisioned: provisioned.documentBytes,
    });

    expect(pair.provisioned.record_id).toBe(provisioned.document.record_id);
    expect(pair.activated.previous).toBe(provisioned.document.record_id);
    expect(provisioned.dispatchSafety).toBe("UNPERSISTED_CANDIDATE_NOT_DISPATCH_SAFE");
    expect(activated.dispatchSafety).toBe("UNPERSISTED_CANDIDATE_NOT_DISPATCH_SAFE");
    expect(new TextDecoder().decode(provisioned.documentBytes)).not.toContain(
      "must-never-be-public",
    );
    expect(new TextDecoder().decode(activated.documentBytes)).not.toContain("must-never-be-public");

    await verifySidecarOpening({
      kind: "ACTIVATION_A0",
      opening: provisioned.opening,
      privatePayloadBytes: provisioned.privatePayloadBytes,
      publicDocument: provisioned.document,
    });
    await verifySidecarOpening({
      kind: "ACTIVATION_A1",
      opening: activated.opening,
      privatePayloadBytes: activated.privatePayloadBytes,
      publicDocument: activated.document,
    });
  });

  it("binds to the document commitment as the sole opening authority", async () => {
    const { provisioned } = await buildFullCandidate();
    const conflicting = canonicalPublicV2Snapshot(provisioned.document);
    conflicting.private_sidecar_commitment = digest("f");

    await expect(
      verifySidecarOpening({
        kind: "ACTIVATION_A0",
        opening: provisioned.opening,
        privatePayloadBytes: provisioned.privatePayloadBytes,
        publicDocument: conflicting,
      }),
    ).rejects.toMatchObject({ code: "PUBLIC_V2_COMMITMENT_MISMATCH" });
  });

  it("closes kind-to-private-schema and controller A!=P invariants", async () => {
    await expect(
      buildUnpersistedProvisionedCandidate({
        brokerSource: BROKER_SOURCE,
        controllerSource: CONTROLLER_SOURCE,
        nonce: nonce(1),
        privatePayload: { schema: "attacker.private.v1" },
      }),
    ).rejects.toMatchObject({ code: "PUBLIC_V2_PRIVATE_SCHEMA_MISMATCH" });

    await expect(
      buildUnpersistedProvisionedCandidate({
        brokerSource: BROKER_SOURCE,
        controllerSource: {
          ...CONTROLLER_SOURCE,
          actionBundle: {
            ...CONTROLLER_SOURCE.actionBundle,
            commitSha: CONTROLLER_SOURCE.commitSha,
          },
        },
        nonce: nonce(1),
        privatePayload: privatePayload("ACTIVATION_A0"),
      }),
    ).rejects.toMatchObject({ code: "PUBLIC_V2_A0_ACTION_WORKFLOW_COLLISION" });
  });

  it("salts identical context/payload commitments with private nonces", async () => {
    const common = {
      brokerSource: BROKER_SOURCE,
      controllerSource: CONTROLLER_SOURCE,
      privatePayload: privatePayload("ACTIVATION_A0"),
    };
    const first = await buildUnpersistedProvisionedCandidate({ ...common, nonce: nonce(1) });
    const repeat = await buildUnpersistedProvisionedCandidate({ ...common, nonce: nonce(1) });
    const distinct = await buildUnpersistedProvisionedCandidate({ ...common, nonce: nonce(9) });
    expect(repeat.commitment).toBe(first.commitment);
    expect(repeat.documentBytes).toEqual(first.documentBytes);
    expect(distinct.commitment).not.toBe(first.commitment);
    expect(distinct.nonceFingerprintSha256).not.toBe(first.nonceFingerprintSha256);
  });

  it("takes immutable P/N/document/object snapshots before the first await", async () => {
    const mutableNonce = nonce(1);
    const mutablePayload = privatePayload("ACTIVATION_A0");
    const buildPromise = buildUnpersistedProvisionedCandidate({
      brokerSource: BROKER_SOURCE,
      controllerSource: CONTROLLER_SOURCE,
      nonce: mutableNonce,
      privatePayload: mutablePayload,
    });
    mutableNonce.fill(9);
    mutablePayload.private_canary = "mutated-after-call";
    const provisioned = await buildPromise;
    expect(provisioned.nonceBytes).toEqual(nonce(1));
    expect(new TextDecoder().decode(provisioned.privatePayloadBytes)).toContain(
      "must-never-be-public-ACTIVATION_A0",
    );

    const originalDocumentBytes = Uint8Array.from(provisioned.documentBytes);
    provisioned.document.record_id = digest("f");
    provisioned.opening.schema = "mutated";
    expect(provisioned.documentBytes).toEqual(originalDocumentBytes);
    const reparsed = await parseCanonicalUntrustedProvisionedPublicCore(provisioned.documentBytes);
    await verifySidecarOpening({
      kind: "ACTIVATION_A0",
      opening: parseCanonicalPublicV2(provisioned.openingBytes),
      privatePayloadBytes: provisioned.privatePayloadBytes,
      publicDocument: reparsed,
    });

    const mutableRecord = canonicalPublicV2Snapshot(reparsed);
    const parsePromise = parseUntrustedProvisionedPublicCore(mutableRecord);
    const originalId = mutableRecord.record_id;
    mutableRecord.record_id = digest("e");
    expect((await parsePromise).record_id).toBe(originalId);
  });

  it("snapshots the A0 predecessor before building A1", async () => {
    const provisioned = await buildUnpersistedProvisionedCandidate({
      brokerSource: BROKER_SOURCE,
      controllerSource: CONTROLLER_SOURCE,
      nonce: nonce(1),
      privatePayload: privatePayload("ACTIVATION_A0"),
    });
    const originalId = provisioned.document.record_id;
    const promise = buildUnpersistedActivatedCandidate({
      baselineSource: BASELINE_SOURCE,
      nonce: nonce(2),
      privatePayload: privatePayload("ACTIVATION_A1"),
      provisioned: provisioned.document,
    });
    provisioned.document.record_id = digest("f");
    expect((await promise).document.previous).toBe(originalId);
  });

  it("rejects canonical self-ID tampering", async () => {
    const { provisioned } = await buildFullCandidate();
    const tampered = canonicalPublicV2Snapshot(provisioned.document);
    tampered.record_id = digest("f");
    await expect(
      parseCanonicalUntrustedProvisionedPublicCore(canonicalPublicV2Bytes(tampered)),
    ).rejects.toMatchObject({ code: "PUBLIC_V2_A0_ID_MISMATCH" });
  });
});
