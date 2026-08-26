import { assertExactObjectAbsent, reconcileExactObject } from "./b2-exact-reconciliation";
import type { B2VersionObserver, B2Writer } from "./b2";
import { BrokerError } from "./errors";
import type { ActivationWorm } from "./types";
import {
  effectError,
  type ConfirmedWormExactObjectEffect,
  type WormExactObjectEffectAction,
  type WormExactObjectEffectInput,
  type WormExactObjectEffectPins,
  type WormExactObjectEffectSnapshot,
} from "./worm-exact-object-effect-contract";

const MAX_TRANSITIONS = 8;

/** Minimal durable boundary required by the pure runner. */
export interface WormExactObjectEffectJournal {
  accept(
    effectId: string,
    pins: WormExactObjectEffectPins,
    writerVersionId: string,
  ): Promise<void> | void;
  confirm(
    effectId: string,
    pins: WormExactObjectEffectPins,
    worm: ActivationWorm,
  ): Promise<void> | void;
  confirmed(
    effectId: string,
    pins: WormExactObjectEffectPins,
  ): ConfirmedWormExactObjectEffect | Promise<ConfirmedWormExactObjectEffect>;
  hold(effectId: string, pins: WormExactObjectEffectPins, code: string): Promise<void> | void;
  markAbsent(
    effectId: string,
    pins: WormExactObjectEffectPins,
    inventoryDigest: string,
  ): Promise<void> | void;
  markDispatchedHold(effectId: string, pins: WormExactObjectEffectPins): Promise<void> | void;
  next(
    effectId: string,
    pins: WormExactObjectEffectPins,
  ): Promise<WormExactObjectEffectAction> | WormExactObjectEffectAction;
  seal(
    input: WormExactObjectEffectInput,
  ): Promise<WormExactObjectEffectSnapshot> | WormExactObjectEffectSnapshot;
}

/**
 * Runs one exact object effect. Once the journal yields DISPATCH, every later
 * branch is observer-only, including writer exceptions and response loss.
 */
export class WormExactObjectEffectRunner {
  public constructor(
    private readonly journal: WormExactObjectEffectJournal,
    private readonly writer: B2Writer,
    private readonly observer: B2VersionObserver,
  ) {}

  public async execute(input: WormExactObjectEffectInput): Promise<ConfirmedWormExactObjectEffect> {
    const sealed = await this.journal.seal(input);
    for (let transition = 0; transition < MAX_TRANSITIONS; transition += 1) {
      const action = await this.journal.next(sealed.effectId, sealed.pins);
      if (action.action === "COMPLETE") {
        return this.journal.confirmed(sealed.effectId, sealed.pins);
      }
      if (action.action === "STOP_HOLD") {
        throw effectError(action.effect.holdCode ?? "WORM_EXACT_OBJECT_EFFECT_HOLD");
      }
      if (action.action === "CHECK_ABSENCE") {
        await this.checkAbsence(action.effect);
        continue;
      }
      if (action.action === "DISPATCH") {
        await this.dispatchOnce(action.effect);
        continue;
      }
      await this.reconcile(action.effect);
    }
    throw effectError("WORM_EXACT_OBJECT_EFFECT_TRANSITION_LIMIT", true);
  }

  private async checkAbsence(effect: WormExactObjectEffectSnapshot): Promise<void> {
    const exact = await exactInput(effect);
    try {
      const inventoryDigest = await assertExactObjectAbsent({
        ...exact,
        observer: this.observer,
      });
      await this.journal.markAbsent(effect.effectId, effect.pins, inventoryDigest);
    } catch (error) {
      const normalized = normalizeObserverError(error);
      if (!normalized.retryable) {
        await this.journal.hold(effect.effectId, effect.pins, normalized.code);
      }
      throw normalized;
    }
  }

  private async dispatchOnce(effect: WormExactObjectEffectSnapshot): Promise<void> {
    const exact = await exactInput(effect);
    try {
      const written = await this.writer.uploadExact({
        canonicalBytes: exact.bytes,
        contentSha1: exact.contentSha1,
        digest: exact.digest,
        key: exact.key,
      });
      await this.journal.accept(effect.effectId, effect.pins, written.versionId);
    } catch {
      // IN_FLIGHT was durable before this call. Any exception is ambiguous and
      // intentionally falls through to observer-only reconciliation.
    }
  }

  private async reconcile(effect: WormExactObjectEffectSnapshot): Promise<void> {
    const exact = await exactInput(effect);
    try {
      const worm = await reconcileExactObject({ ...exact, observer: this.observer });
      await this.journal.confirm(effect.effectId, effect.pins, worm);
    } catch (error) {
      const normalized = normalizeObserverError(error);
      if (normalized.retryable) {
        await this.journal.markDispatchedHold(effect.effectId, effect.pins);
      } else {
        await this.journal.hold(effect.effectId, effect.pins, normalized.code);
      }
      throw normalized;
    }
  }
}

async function exactInput(effect: WormExactObjectEffectSnapshot): Promise<{
  readonly bytes: Uint8Array;
  readonly committedAt: string;
  readonly contentSha1: string;
  readonly digest: string;
  readonly key: string;
}> {
  const bytes = Uint8Array.from(effect.canonicalBytes);
  return {
    bytes,
    committedAt: effect.committedAt,
    contentSha1: await sha1Hex(bytes),
    digest: effect.digest,
    key: effect.key,
  };
}

async function sha1Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", Uint8Array.from(bytes).buffer);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function normalizeObserverError(value: unknown): BrokerError {
  return value instanceof BrokerError
    ? value
    : new BrokerError("WORM_EXACT_OBJECT_EFFECT_OBSERVER_UNAVAILABLE", 503, true);
}
