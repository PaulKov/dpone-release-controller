import { ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES } from "./activation-component-contract";
import type { ActivationComponentSetSemanticDecision } from "./activation-component-journal-contract";
import { BrokerError } from "./errors";
import { ownExactUint8Array } from "./exact-uint8array";
import type {
  PreparedWormExactObjectEffect,
  WormExactObjectEffectPins,
} from "./worm-exact-object-effect-contract";

const JOURNAL_PIN_FIELDS = [
  "executorServiceIdentity",
  "executorVersionId",
  "observerServiceIdentity",
  "observerVersionId",
] as const;
export function componentJournalError(code: string, status = 409): BrokerError {
  return new BrokerError(code, status, false);
}

/** Own an exact native byte view without trusting overridable accessors or iterators. */
export function boundedJournalBytes(input: unknown): Uint8Array {
  return ownExactUint8Array(input, {
    code: "ACTIVATION_COMPONENT_JOURNAL_BYTES_INVALID",
    invalidStatus: 409,
    maximum: ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
    minimum: 1,
    sizeStatus: 413,
  });
}

/** Own the exact four data-only service pins before any asynchronous operation. */
export function snapshotJournalPins(pins: unknown): WormExactObjectEffectPins {
  try {
    if (
      pins === null ||
      typeof pins !== "object" ||
      Reflect.getPrototypeOf(pins) !== Object.prototype
    ) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_PIN_INVALID");
    }
    const keys = Reflect.ownKeys(pins);
    if (
      keys.length !== JOURNAL_PIN_FIELDS.length ||
      keys.some((key) => typeof key !== "string" || !JOURNAL_PIN_FIELDS.includes(key as never))
    ) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_PIN_INVALID");
    }
    const values = JOURNAL_PIN_FIELDS.map((field) => {
      const descriptor = Reflect.getOwnPropertyDescriptor(pins, field);
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_PIN_INVALID");
      }
      return descriptor.value as unknown;
    });
    const snapshot = Object.freeze({
      executorServiceIdentity: values[0],
      executorVersionId: values[1],
      observerServiceIdentity: values[2],
      observerVersionId: values[3],
    });
    assertJournalPins(snapshot);
    // This rejects Proxy exotica after accessors and non-data fields were excluded.
    structuredClone(pins);
    return snapshot;
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_PIN_INVALID");
  }
}

/** Parse the sole structural verdict that cannot authorize a journal effect. */
export function snapshotJournalSemanticRejection(
  input: unknown,
): Extract<ActivationComponentSetSemanticDecision, { readonly outcome: "REJECT" }> {
  try {
    if (
      input === null ||
      typeof input !== "object" ||
      Reflect.getPrototypeOf(input) !== Object.prototype
    ) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_VALIDATOR_INVALID", 500);
    }
    const fields = Reflect.ownKeys(input);
    const outcomeDescriptor = Reflect.getOwnPropertyDescriptor(input, "outcome");
    if (
      outcomeDescriptor === undefined ||
      !("value" in outcomeDescriptor) ||
      !outcomeDescriptor.enumerable
    ) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_VALIDATOR_INVALID", 500);
    }
    if (outcomeDescriptor.value !== "REJECT" || fields.length !== 1 || fields[0] !== "outcome") {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_VALIDATOR_INVALID", 500);
    }
    structuredClone(input);
    return Object.freeze({ outcome: "REJECT" });
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_VALIDATOR_INVALID", 500);
  }
}

export function snapshotJournalEffect(
  effect: PreparedWormExactObjectEffect,
): PreparedWormExactObjectEffect {
  return Object.freeze({
    canonicalBytes: boundedJournalBytes(effect.canonicalBytes),
    committedAt: effect.committedAt,
    digest: effect.digest,
    effectId: effect.effectId,
    key: effect.key,
    pins: snapshotJournalPins(effect.pins),
  });
}

function assertJournalPins(
  pins: Readonly<Record<(typeof JOURNAL_PIN_FIELDS)[number], unknown>>,
): asserts pins is WormExactObjectEffectPins {
  const version = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;
  const identity =
    /^cloudflare-worker:[0-9a-f]{32}\/[a-z][a-z0-9-]{0,62}@[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;
  if (
    typeof pins.executorServiceIdentity !== "string" ||
    typeof pins.executorVersionId !== "string" ||
    typeof pins.observerServiceIdentity !== "string" ||
    typeof pins.observerVersionId !== "string" ||
    !version.test(pins.executorVersionId) ||
    !version.test(pins.observerVersionId) ||
    !identity.test(pins.executorServiceIdentity) ||
    !identity.test(pins.observerServiceIdentity) ||
    !pins.executorServiceIdentity.endsWith(`@${pins.executorVersionId}`) ||
    !pins.observerServiceIdentity.endsWith(`@${pins.observerVersionId}`) ||
    pins.executorServiceIdentity === pins.observerServiceIdentity
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_PIN_INVALID");
  }
}
