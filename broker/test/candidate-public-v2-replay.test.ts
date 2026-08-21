import { describe, expect, it } from "vitest";

import {
  assertExactCandidateReplay,
  snapshotCandidateReplayMaterial,
  transitionCandidateReplay,
  type CandidateReplayState,
} from "../src/candidate-public-v2/replay-state";
import { buildFullCandidate, nonce } from "./candidate-public-v2-fixtures";

describe("candidate public-v2 pure replay model", () => {
  it("permits only the ordered private-WORM then public-effect path", () => {
    let state: CandidateReplayState = "RESERVED_NO_EFFECT";
    for (const event of [
      "FREEZE_PRIVATE",
      "START_PRIVATE_WORM",
      "CONFIRM_PRIVATE_WORM",
      "FREEZE_PUBLIC",
      "START_PUBLIC_EFFECT",
      "CONFIRM_PUBLIC_EFFECT",
    ] as const) {
      state = transitionCandidateReplay(state, event);
    }
    expect(state).toBe("CONFIRMED");
    expect(() => transitionCandidateReplay("CONFIRMED", "CANCEL")).toThrowError(
      "PUBLIC_V2_REPLAY_TRANSITION_INVALID",
    );
    expect(() => transitionCandidateReplay("PRIVATE_FROZEN", "CANCEL")).toThrowError(
      "PUBLIC_V2_REPLAY_TRANSITION_INVALID",
    );
    expect(transitionCandidateReplay("RESERVED_NO_EFFECT", "CANCEL")).toBe("CANCELLED");
  });

  it("holds ambiguous effects and resumes only the same phase", () => {
    expect(transitionCandidateReplay("PRIVATE_WORM_IN_FLIGHT", "HOLD_PRIVATE")).toBe(
      "HOLD_PRIVATE",
    );
    expect(transitionCandidateReplay("HOLD_PRIVATE", "RETRY_PRIVATE_WORM")).toBe(
      "PRIVATE_WORM_IN_FLIGHT",
    );
    expect(transitionCandidateReplay("PUBLIC_EFFECT_IN_FLIGHT", "HOLD_PUBLIC")).toBe("HOLD_PUBLIC");
    expect(transitionCandidateReplay("HOLD_PUBLIC", "START_PUBLIC_RECONCILE")).toBe(
      "PUBLIC_RECONCILE_IN_FLIGHT",
    );
    expect(
      transitionCandidateReplay("PUBLIC_RECONCILE_IN_FLIGHT", "CONFIRM_PUBLIC_RECONCILE"),
    ).toBe("CONFIRMED");
    expect(() => transitionCandidateReplay("HOLD_PUBLIC", "START_PUBLIC_EFFECT")).toThrowError(
      "PUBLIC_V2_REPLAY_TRANSITION_INVALID",
    );
    expect(() => transitionCandidateReplay("HOLD_PRIVATE", "START_PUBLIC_EFFECT")).toThrowError(
      "PUBLIC_V2_REPLAY_TRANSITION_INVALID",
    );
  });

  it("snapshots N/P/opening/document synchronously and replays byte-for-byte", async () => {
    const { provisioned } = await buildFullCandidate();
    const mutableNonce = nonce(1);
    const mutableDocument = Uint8Array.from(provisioned.documentBytes);
    const mutableOpening = Uint8Array.from(provisioned.openingBytes);
    const mutablePayload = Uint8Array.from(provisioned.privatePayloadBytes);
    const promise = snapshotCandidateReplayMaterial({
      documentBytes: mutableDocument,
      kind: "ACTIVATION_A0",
      nonceBytes: mutableNonce,
      openingBytes: mutableOpening,
      privatePayloadBytes: mutablePayload,
    });
    mutableNonce.fill(9);
    mutableDocument.fill(0);
    mutableOpening.fill(0);
    mutablePayload.fill(0);
    const reserved = await promise;
    const retry = await snapshotCandidateReplayMaterial({
      documentBytes: provisioned.documentBytes,
      kind: "ACTIVATION_A0",
      nonceBytes: nonce(1),
      openingBytes: provisioned.openingBytes,
      privatePayloadBytes: provisioned.privatePayloadBytes,
    });
    expect(reserved.dispatchSafety).toBe("PURE_MODEL_NOT_PERSISTENCE_AUTHORITY");
    expect(() => assertExactCandidateReplay(reserved, retry)).not.toThrow();

    const changedNonce = await snapshotCandidateReplayMaterial({
      documentBytes: provisioned.documentBytes,
      kind: "ACTIVATION_A0",
      nonceBytes: nonce(2),
      openingBytes: provisioned.openingBytes,
      privatePayloadBytes: provisioned.privatePayloadBytes,
    });
    expect(() => assertExactCandidateReplay(reserved, changedNonce)).toThrowError(
      "PUBLIC_V2_REPLAY_MATERIAL_MISMATCH",
    );
  });
});
