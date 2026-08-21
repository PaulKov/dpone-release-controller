import type { CandidateJsonObject } from "./types";

declare const UNTRUSTED_PUBLIC_V2: unique symbol;

/**
 * Syntax, hashes and private openings never confer broker authorship.
 *
 * This candidate package intentionally exports no Accepted type or constructor.
 * A future authenticated transport adapter must own that separate boundary.
 */
export type UntrustedPublicV2<Kind extends string> = CandidateJsonObject & {
  readonly [UNTRUSTED_PUBLIC_V2]: Kind;
};

export type UntrustedProvisionedPublicCore = UntrustedPublicV2<"ACTIVATION_A0">;
export type UntrustedActivatedPublicCore = UntrustedPublicV2<"ACTIVATION_A1">;
export type UntrustedActivationProof = UntrustedPublicV2<"ACTIVATION_PROOF">;
export type UntrustedRuntimeClosure = UntrustedPublicV2<"RUNTIME_CLOSURE">;
