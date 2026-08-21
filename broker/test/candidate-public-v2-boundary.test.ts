import { describe, expect, it } from "vitest";

import { buildUnpersistedActivationProofCandidate } from "../src/candidate-public-v2/activation-proof";
import { CandidatePublicV2Error } from "../src/candidate-public-v2/error";
import {
  PRIVATE_PAYLOAD_SCHEMAS,
  parseOpening,
  parseSidecar,
  stripCommittedDocument,
} from "../src/candidate-public-v2/sidecar";
import * as trustRuntime from "../src/candidate-public-v2/trust";
import { SIDECAR_KINDS, type SidecarKind } from "../src/candidate-public-v2/types";
import { buildFullCandidate, nonce, privatePayload } from "./candidate-public-v2-fixtures";

function leakingProxy(): object {
  return new Proxy(
    {},
    {
      ownKeys: () => {
        throw new Error("PRIVATE_CANARY");
      },
    },
  );
}

function expectCandidateCode(action: () => unknown, code: string): void {
  try {
    action();
    throw new Error("expected candidate error");
  } catch (error) {
    expect(error).toBeInstanceOf(CandidatePublicV2Error);
    expect((error as CandidatePublicV2Error).code).toBe(code);
    expect((error as Error).message).not.toContain("PRIVATE_CANARY");
  }
}

describe("candidate public-v2 trust and uniform-error boundary", () => {
  it("has one closed runtime sidecar-kind authority", () => {
    expect([...SIDECAR_KINDS].sort()).toEqual(Object.keys(PRIVATE_PAYLOAD_SCHEMAS).sort());
  });

  it("normalizes proxy and forged-kind failures without leaking canaries", async () => {
    expectCandidateCode(() => parseOpening(leakingProxy()), "PUBLIC_V2_CANONICAL_OBJECT_INVALID");
    expectCandidateCode(() => parseSidecar(leakingProxy()), "PUBLIC_V2_CANONICAL_OBJECT_INVALID");
    const { provisioned } = await buildFullCandidate();
    expectCandidateCode(
      () => stripCommittedDocument(provisioned.document, "FORGED" as SidecarKind),
      "PUBLIC_V2_SIDECAR_KIND_INVALID",
    );
    expectCandidateCode(
      () => stripCommittedDocument(leakingProxy() as never, "ACTIVATION_A0"),
      "PUBLIC_V2_CANONICAL_OBJECT_INVALID",
    );
  });

  it("normalizes an injected clock exception", async () => {
    const { activated, provisioned } = await buildFullCandidate();
    await expect(
      buildUnpersistedActivationProofCandidate({
        activated: activated.document,
        clock: {
          nowMs: () => {
            throw new Error("PRIVATE_CANARY");
          },
        },
        nonce: nonce(3),
        privatePayload: privatePayload("ACTIVATION_PROOF"),
        provisioned: provisioned.document,
      }),
    ).rejects.toMatchObject({ code: "PUBLIC_V2_PROOF_NOW_INVALID" });
  });

  it("exports no Accepted runtime constructor or upgrade", async () => {
    const { archive, provisioned } = await buildFullCandidate();
    expect(Object.keys(trustRuntime)).toEqual([]);
    expect(Object.hasOwn(provisioned.document, "accepted")).toBe(false);
    expect(Object.hasOwn(archive, "accepted")).toBe(false);
    expect(provisioned.dispatchSafety).toBe("UNPERSISTED_CANDIDATE_NOT_DISPATCH_SAFE");
  });
});
