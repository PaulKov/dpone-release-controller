import { describe, expect, it } from "vitest";

import {
  ACTIVATION_PROOF_RECOVERY_SCHEMA,
  ACTIVATION_PROOF_SCHEMA,
  activationProofRecoveryClaimsDigest,
  buildActivationProofRecovery,
} from "../src/activation-proof";
import {
  activatedAuthorityHeadKey,
  activatedAuthorityHeadRecordSha256,
  buildActivatedAuthorityHead,
} from "../src/activated-authority-head";
import { buildCurrentHeadProof } from "../src/activated-authority-head-proof";
import { canonicalBytes, sha256Hex } from "../src/canonical";
import type { JsonObject } from "../src/types";

const NOW = Date.parse("2026-08-15T12:00:30.000Z");
const CURRENT_REQUEST = "activation-proof-recovery-current-0001";
const ORIGINAL_REQUEST = "activation-proof-recovery-original-0001";
const RESERVATION_ID = tagged("8");

describe("activation proof confidential recovery wire", () => {
  it("binds a fresh current-head read to the exact sealed original proof", async () => {
    const input = await recoveryInput();
    const recovery = await buildActivationProofRecovery(input);

    expect(recovery).toMatchObject({
      current_request_id: CURRENT_REQUEST,
      original_request_id: ORIGINAL_REQUEST,
      reservation_id: RESERVATION_ID,
      schema: ACTIVATION_PROOF_RECOVERY_SCHEMA,
      schema_version: 1,
      sealed_result_sha256: input.sealedResultSha256,
    });
    const unsigned = { ...recovery };
    delete unsigned.recovery_sha256;
    expect(recovery.recovery_sha256).toBe(`sha256:${await sha256Hex(canonicalBytes(unsigned))}`);
    await expect(
      activationProofRecoveryClaimsDigest({
        admissionClaimsSha256: tagged("9"),
        currentHead: input.currentHead,
        currentRequestId: CURRENT_REQUEST,
        originalRequestId: ORIGINAL_REQUEST,
        reservationId: RESERVATION_ID,
        sealedResultSha256: input.sealedResultSha256,
      }),
    ).resolves.toMatch(/^sha256:[0-9a-f]{64}$/u);
  });

  it("rejects recovery at the exact sealed-proof expiry boundary", async () => {
    await expect(
      buildActivationProofRecovery({
        ...(await recoveryInput()),
        nowMs: Date.parse("2026-08-15T12:01:00.000Z"),
      }),
    ).rejects.toThrow("ACTIVATION_PROOF_RECOVERY_INVALID");
  });

  it("rejects head drift, request relabeling, and sealed-byte tampering", async () => {
    const input = await recoveryInput();
    const driftedHead = await headProof(CURRENT_REQUEST, 2);
    const cases = [
      { ...input, currentHead: driftedHead },
      { ...input, currentRequestId: ORIGINAL_REQUEST },
      { ...input, sealedResultSha256: tagged("0") },
      {
        ...input,
        originalProof: { ...input.originalProof, controller: { tampered: true } },
      },
    ];
    for (const candidate of cases) {
      await expect(buildActivationProofRecovery(candidate)).rejects.toThrow(
        /ACTIVATION_PROOF_RECOVERY_(?:HEAD_MISMATCH|HEAD_STALE|INVALID)/u,
      );
    }
  });
});

async function recoveryInput() {
  const originalProof = await sealedProof();
  return {
    currentHead: await headProof(CURRENT_REQUEST, 1, "2026-08-15T12:00:29.500Z"),
    currentRequestId: CURRENT_REQUEST,
    nowMs: NOW,
    originalProof,
    originalRequestId: ORIGINAL_REQUEST,
    reservationId: RESERVATION_ID,
    sealedResultSha256: `sha256:${await sha256Hex(canonicalBytes(originalProof))}`,
  };
}

async function sealedProof(): Promise<JsonObject> {
  const body: JsonObject = {
    activated: {},
    activated_authority_head: await headProof(ORIGINAL_REQUEST, 1, "2026-08-15T11:59:59.500Z"),
    admitted_at: "2026-08-15T12:00:00Z",
    controller: {},
    expires_at: "2026-08-15T12:01:00Z",
    provisioned: {},
    request_id: ORIGINAL_REQUEST,
    schema: ACTIVATION_PROOF_SCHEMA,
    schema_version: 1,
  };
  return {
    ...body,
    proof_sha256: `sha256:${await sha256Hex(canonicalBytes(body))}`,
  };
}

async function headProof(
  requestId: string,
  seed: number,
  observedAt = "2026-08-15T12:00:29.500Z",
): Promise<JsonObject> {
  const ingress = `00000000-0000-0000-0000-${String(seed).padStart(12, "0")}`;
  const activatedDigest = tagged(seed === 1 ? "2" : "3");
  const head = await buildActivatedAuthorityHead({
    activatedRecordId: tagged(seed === 1 ? "4" : "5"),
    activatedRecordSha256: activatedDigest,
    activatedServiceAuthoritiesSha256: tagged(seed === 1 ? "6" : "7"),
    activatedWorm: {
      digest: activatedDigest,
      key: `receipts/v1/activation/${ingress}/1-${activatedDigest.slice(7)}.json`,
      retentionUntil: "2034-08-15T12:00:00.000Z",
      versionId: `activation-version-${seed}`,
    },
    committedAt: "2026-08-15T11:59:00.000Z",
    generation: 1,
    ingressWorkerVersionId: ingress,
    previous: "GENESIS",
  });
  return buildCurrentHeadProof({
    brokerAcceptedAt: observedAt,
    head,
    observedAt,
    requestId,
    requestedAt: new Date(Date.parse(observedAt) - 250).toISOString(),
    worm: {
      digest: await activatedAuthorityHeadRecordSha256(head),
      key: await activatedAuthorityHeadKey(head),
      retentionUntil: "2034-08-15T12:00:00.000Z",
      versionId: `head-version-${seed}`,
    },
  });
}

function tagged(character: string): string {
  return `sha256:${character.repeat(64)}`;
}
