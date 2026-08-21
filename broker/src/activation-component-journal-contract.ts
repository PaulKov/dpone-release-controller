import type {
  ActivationComponentDescriptor,
  ActivationComponentDigestInput,
  PreparedActivationComponentEnvelope,
} from "./activation-component-contract";
import type {
  PreparedWormExactObjectEffect,
  WormExactObjectEffectPins,
} from "./worm-exact-object-effect-contract";

export const ACTIVATION_COMPONENT_JOURNAL_TTL_MS = 900_000;
export const ACTIVATION_COMPONENT_JOURNAL_MAX_LIVE_SESSIONS = 4;
export const ACTIVATION_COMPONENT_JOURNAL_MAX_LIFETIME_SESSIONS = 8;

export type ActivationComponentJournalSessionState =
  | "ABANDONED"
  | "PROVISIONAL"
  | "REJECTED"
  | "SELECTED"
  | "STAGED"
  | "SUPERSEDED";

export type ActivationComponentJournalTerminalCode =
  | "ACTIVATION_COMPONENT_SESSION_EXPIRED"
  | "ACTIVATION_COMPONENT_SESSION_SUPERSEDED"
  | "ACTIVATION_COMPONENT_SET_SEMANTIC_INVALID";

export type ActivationComponentJournalHoldCode =
  | "ACTIVATION_COMPONENT_MANIFEST_VERSION_CONFLICT"
  | "ACTIVATION_COMPONENT_WORM_VERSION_CONFLICT";

export interface ActivationComponentJournalSession {
  readonly descriptor: ActivationComponentDescriptor;
  readonly freshUntil: string;
  readonly generation: number;
  readonly journalOrdinal: number;
  readonly predecessorSessionId: string | null;
  readonly sessionId: string;
  readonly stagedCount: number;
  readonly state: ActivationComponentJournalSessionState;
  readonly terminalCode: ActivationComponentJournalTerminalCode | null;
}

export interface ActivationComponentJournalInitialInput {
  readonly components: readonly ActivationComponentDigestInput[];
}

export interface ActivationComponentJournalReissueInput {
  readonly predecessorDescriptorId: string;
  readonly predecessorDescriptorSha256: string;
  readonly predecessorSessionId: string;
}

/**
 * Exact structural objects passed to the closed kind/coherence validator.
 * The store gives the validator fresh owned copies and re-reads SQL afterwards.
 */
export interface ActivationComponentSetSemanticInput {
  readonly descriptor: ActivationComponentDescriptor;
  readonly envelopes: readonly PreparedActivationComponentEnvelope[];
}

/**
 * Closed local verdict. ACCEPT carries the exact WORM authorities derived from
 * the same validated component inventory; journal callers never provide pins.
 */
export type ActivationComponentSetSemanticDecision =
  | {
      readonly outcome: "ACCEPT";
      readonly pins: WormExactObjectEffectPins;
    }
  | { readonly outcome: "REJECT" };

/**
 * Pure local validation seam, optionally async; no provider or remote effect belongs here.
 * Only ClosedActivationComponentSetSemanticValidator can mint an authorizing ACCEPT;
 * decorators may delay or pass that exact capability through, while REJECT is structural.
 */
export interface ActivationComponentSetSemanticValidator {
  validate(
    input: ActivationComponentSetSemanticInput,
  ): ActivationComponentSetSemanticDecision | Promise<ActivationComponentSetSemanticDecision>;
}

export interface SealedActivationComponentSet {
  readonly effects: readonly PreparedWormExactObjectEffect[];
  readonly pins: WormExactObjectEffectPins;
  readonly session: ActivationComponentJournalSession;
}

/** Only component effects that still need an exact generic-effect result. */
export interface UnresolvedActivationComponentEffects {
  readonly effects: readonly PreparedWormExactObjectEffect[];
  readonly pins: WormExactObjectEffectPins;
  readonly session: ActivationComponentJournalSession;
}

/** Deterministic manifest effect sealed after all 15 component results. */
export interface SealedActivationComponentManifest {
  readonly effect: PreparedWormExactObjectEffect;
  readonly pins: WormExactObjectEffectPins;
  readonly session: ActivationComponentJournalSession;
}

export interface ConfirmedActivationComponentJournalDescriptor {
  readonly committedAt: string;
  readonly descriptorId: string;
  readonly descriptorSha256: string;
  readonly setId: string;
  readonly workerVersionId: string;
}

export interface ConfirmedActivationComponentJournalSession {
  readonly freshUntil: string;
  readonly generation: number;
  readonly journalOrdinal: number;
  readonly predecessorSessionId: string | null;
  readonly sessionId: string;
  readonly state: "SELECTED";
}

/**
 * Final local-journal authority. Exact pointer bytes are freshly owned on every read.
 * This proves the selected journal chain, not resolved component semantics or operation binding.
 * Consumers must pass the value through the private-brand snapshot boundary before use.
 */
export interface ConfirmedActivationComponentJournalAuthority {
  readonly canonicalDescriptorBytes: Uint8Array;
  readonly canonicalPointerBytes: Uint8Array;
  readonly descriptor: ConfirmedActivationComponentJournalDescriptor;
  readonly pins: WormExactObjectEffectPins;
  readonly pointerSha256: string;
  readonly session: ConfirmedActivationComponentJournalSession;
  readonly trust: "CONFIRMED_JOURNAL";
}

export interface HeldActivationComponentJournalAuthority {
  readonly holdCode: ActivationComponentJournalHoldCode;
  readonly session: ActivationComponentJournalSession;
}

export type ActivationComponentManifestSeal =
  | {
      readonly authority: ConfirmedActivationComponentJournalAuthority;
      readonly outcome: "CONFIRMED";
    }
  | { readonly outcome: "HOLD"; readonly held: HeldActivationComponentJournalAuthority }
  | { readonly outcome: "SEALED"; readonly sealed: SealedActivationComponentManifest };

export type ActivationComponentManifestConfirmation =
  | {
      readonly authority: ConfirmedActivationComponentJournalAuthority;
      readonly outcome: "CONFIRMED";
    }
  | { readonly held: HeldActivationComponentJournalAuthority; readonly outcome: "HOLD" };

export type ActivationComponentSetSelection =
  | {
      readonly outcome: "REJECTED";
      readonly session: ActivationComponentJournalSession;
    }
  | {
      readonly outcome: "SEALED";
      readonly sealed: SealedActivationComponentSet;
    };
