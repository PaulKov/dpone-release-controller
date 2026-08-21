import { copyPrivateNonce, copyPublicV2Bytes } from "./bytes";
import { candidateAssert } from "./error";
import { sha256Tagged } from "./identity";
import { SIDECAR_KINDS, type DigestSha256, type SidecarKind } from "./types";

export type CandidateReplayState =
  | "RESERVED_NO_EFFECT"
  | "PRIVATE_FROZEN"
  | "PRIVATE_WORM_IN_FLIGHT"
  | "HOLD_PRIVATE"
  | "PRIVATE_WORM_CONFIRMED"
  | "PUBLIC_FROZEN"
  | "PUBLIC_EFFECT_IN_FLIGHT"
  | "HOLD_PUBLIC"
  | "PUBLIC_RECONCILE_IN_FLIGHT"
  | "CONFIRMED"
  | "CANCELLED";

export type CandidateReplayEvent =
  | "FREEZE_PRIVATE"
  | "START_PRIVATE_WORM"
  | "CONFIRM_PRIVATE_WORM"
  | "HOLD_PRIVATE"
  | "RETRY_PRIVATE_WORM"
  | "FREEZE_PUBLIC"
  | "START_PUBLIC_EFFECT"
  | "CONFIRM_PUBLIC_EFFECT"
  | "HOLD_PUBLIC"
  | "START_PUBLIC_RECONCILE"
  | "CONFIRM_PUBLIC_RECONCILE"
  | "CANCEL";

type CandidateReplayTransition = `${CandidateReplayState}:${CandidateReplayEvent}`;

const TRANSITIONS: Readonly<Partial<Record<CandidateReplayTransition, CandidateReplayState>>> =
  Object.freeze({
    "HOLD_PRIVATE:RETRY_PRIVATE_WORM": "PRIVATE_WORM_IN_FLIGHT",
    "HOLD_PUBLIC:START_PUBLIC_RECONCILE": "PUBLIC_RECONCILE_IN_FLIGHT",
    "PRIVATE_FROZEN:START_PRIVATE_WORM": "PRIVATE_WORM_IN_FLIGHT",
    "PRIVATE_WORM_CONFIRMED:FREEZE_PUBLIC": "PUBLIC_FROZEN",
    "PRIVATE_WORM_IN_FLIGHT:CONFIRM_PRIVATE_WORM": "PRIVATE_WORM_CONFIRMED",
    "PRIVATE_WORM_IN_FLIGHT:HOLD_PRIVATE": "HOLD_PRIVATE",
    "PUBLIC_EFFECT_IN_FLIGHT:CONFIRM_PUBLIC_EFFECT": "CONFIRMED",
    "PUBLIC_EFFECT_IN_FLIGHT:HOLD_PUBLIC": "HOLD_PUBLIC",
    "PUBLIC_FROZEN:START_PUBLIC_EFFECT": "PUBLIC_EFFECT_IN_FLIGHT",
    "PUBLIC_RECONCILE_IN_FLIGHT:CONFIRM_PUBLIC_RECONCILE": "CONFIRMED",
    "PUBLIC_RECONCILE_IN_FLIGHT:HOLD_PUBLIC": "HOLD_PUBLIC",
    "RESERVED_NO_EFFECT:CANCEL": "CANCELLED",
    "RESERVED_NO_EFFECT:FREEZE_PRIVATE": "PRIVATE_FROZEN",
  });

export interface CandidateReplayMaterial {
  readonly dispatchSafety: "PURE_MODEL_NOT_PERSISTENCE_AUTHORITY";
  readonly documentBytes: Uint8Array;
  readonly kind: SidecarKind;
  readonly nonceBytes: Uint8Array;
  readonly nonceFingerprintSha256: DigestSha256;
  readonly openingBytes: Uint8Array;
  readonly privatePayloadBytes: Uint8Array;
}

/** Invalid, skipped, backward, or post-effect cancellation transitions fail closed. */
export function transitionCandidateReplay(
  state: CandidateReplayState,
  event: CandidateReplayEvent,
): CandidateReplayState {
  const key: CandidateReplayTransition = `${state}:${event}`;
  const next = TRANSITIONS[key];
  candidateAssert(next !== undefined, "PUBLIC_V2_REPLAY_TRANSITION_INVALID");
  return next;
}

/**
 * Snapshot the exact retry material. Raw SHA-256(N) is only a confidential
 * candidate fingerprint; this pure model defines no durable uniqueness key.
 */
export async function snapshotCandidateReplayMaterial(input: {
  readonly documentBytes: Uint8Array;
  readonly kind: SidecarKind;
  readonly nonceBytes: Uint8Array;
  readonly openingBytes: Uint8Array;
  readonly privatePayloadBytes: Uint8Array;
}): Promise<CandidateReplayMaterial> {
  candidateAssert(SIDECAR_KINDS.includes(input.kind), "PUBLIC_V2_REPLAY_KIND_INVALID");
  const nonceBytes = copyPrivateNonce(input.nonceBytes);
  const documentBytes = copyPublicV2Bytes(input.documentBytes);
  const openingBytes = copyPublicV2Bytes(input.openingBytes);
  const privatePayloadBytes = copyPublicV2Bytes(
    input.privatePayloadBytes,
    "PUBLIC_V2_PRIVATE_PAYLOAD_SIZE_INVALID",
  );
  return {
    dispatchSafety: "PURE_MODEL_NOT_PERSISTENCE_AUTHORITY",
    documentBytes,
    kind: input.kind,
    nonceBytes,
    nonceFingerprintSha256: await sha256Tagged(nonceBytes),
    openingBytes,
    privatePayloadBytes,
  };
}

/** Every retry must replay byte-for-byte material, never regenerate its nonce. */
export function assertExactCandidateReplay(
  reserved: CandidateReplayMaterial,
  retry: CandidateReplayMaterial,
): void {
  candidateAssert(reserved.kind === retry.kind, "PUBLIC_V2_REPLAY_KIND_MISMATCH");
  candidateAssert(
    reserved.nonceFingerprintSha256 === retry.nonceFingerprintSha256 &&
      equalBytes(reserved.nonceBytes, retry.nonceBytes) &&
      equalBytes(reserved.privatePayloadBytes, retry.privatePayloadBytes) &&
      equalBytes(reserved.openingBytes, retry.openingBytes) &&
      equalBytes(reserved.documentBytes, retry.documentBytes),
    "PUBLIC_V2_REPLAY_MATERIAL_MISMATCH",
  );
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}
