import { isAllowedB2ExactKey } from "./b2-key";
import { canonicalBytes, sha256Hex, timingSafeEqual } from "./canonical";
import { BrokerError } from "./errors";
import type { ActivationWorm, JsonObject } from "./types";

export const WORM_EXACT_OBJECT_EFFECT_SCHEMA = "dpone.worm-exact-object-effect.v1";
export const WORM_EXACT_OBJECT_MAX_BYTES = 65_536;

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const VERSION = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;
const SERVICE_IDENTITY =
  /^cloudflare-worker:[0-9a-f]{32}\/[a-z][a-z0-9-]{0,62}@[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;

export type WormExactObjectEffectStatus =
  | "ABSENT"
  | "ACCEPTED"
  | "CONFIRMED"
  | "DISPATCHED_HOLD"
  | "HOLD"
  | "IN_FLIGHT"
  | "PREPARED";

/** Immutable Cloudflare identities authorized to execute and observe an effect. */
export interface WormExactObjectEffectPins {
  readonly executorServiceIdentity: string;
  readonly executorVersionId: string;
  readonly observerServiceIdentity: string;
  readonly observerVersionId: string;
}

/** Exact caller intent. `canonicalBytes` may be arbitrary immutable object bytes. */
export interface WormExactObjectEffectInput {
  readonly canonicalBytes: Uint8Array;
  readonly committedAt: string;
  readonly digest: string;
  readonly key: string;
  readonly pins: WormExactObjectEffectPins;
}

/** Validated, defensively copied identity ready for durable sealing. */
export interface PreparedWormExactObjectEffect extends WormExactObjectEffectInput {
  readonly effectId: string;
}

/** Stored view returned to the runner; every byte array is a fresh copy. */
export interface WormExactObjectEffectSnapshot extends PreparedWormExactObjectEffect {
  readonly absenceInventoryDigest: string | null;
  readonly holdCode: string | null;
  readonly status: WormExactObjectEffectStatus;
  readonly writerVersionId: string | null;
  readonly worm: ActivationWorm | null;
}

export interface ConfirmedWormExactObjectEffect {
  readonly absenceInventoryDigest: string;
  readonly committedAt: string;
  readonly digest: string;
  readonly effectId: string;
  readonly key: string;
  readonly pins: WormExactObjectEffectPins;
  readonly status: "CONFIRMED";
  readonly worm: ActivationWorm;
}

export interface WormExactObjectEffectAction {
  readonly action: "CHECK_ABSENCE" | "COMPLETE" | "DISPATCH" | "RECONCILE" | "STOP_HOLD";
  readonly effect: WormExactObjectEffectSnapshot;
}

/** Closed object-key policy injected only by a reviewed protocol adapter. */
export type WormExactObjectKeyPolicy = (key: string) => boolean;

/**
 * Copies and validates exact bytes before hashing, then derives the stable
 * effect identity from every field that may alter the object or its trust path.
 */
export async function prepareWormExactObjectEffect(
  input: WormExactObjectEffectInput,
): Promise<PreparedWormExactObjectEffect> {
  return prepareWormExactObjectEffectWithKeyPolicy(input, isAllowedB2ExactKey);
}

/** Shared preparation core; runtime callers should use the default v1-policy wrapper above. */
export async function prepareWormExactObjectEffectWithKeyPolicy(
  input: WormExactObjectEffectInput,
  keyPolicy: WormExactObjectKeyPolicy,
): Promise<PreparedWormExactObjectEffect> {
  if (
    input.canonicalBytes.byteLength < 1 ||
    input.canonicalBytes.byteLength > WORM_EXACT_OBJECT_MAX_BYTES
  ) {
    throw effectError("WORM_EXACT_OBJECT_EFFECT_INPUT_INVALID");
  }
  const exactBytes = Uint8Array.from(input.canonicalBytes);
  const pins = copyAndValidatePins(input.pins);
  const committedAt = canonicalEffectTimestamp(input.committedAt);
  const digest = input.digest;
  const key = input.key;
  let allowedKey: boolean;
  try {
    allowedKey = keyPolicy(key);
  } catch {
    throw effectError("WORM_EXACT_OBJECT_EFFECT_INPUT_INVALID");
  }
  if (!DIGEST.test(digest) || !allowedKey) {
    throw effectError("WORM_EXACT_OBJECT_EFFECT_INPUT_INVALID");
  }
  const computedDigest = `sha256:${await sha256Hex(exactBytes)}`;
  if (!timingSafeEqual(computedDigest, digest)) {
    throw effectError("WORM_EXACT_OBJECT_EFFECT_DIGEST_MISMATCH");
  }
  const identity: JsonObject = {
    body_bytes: exactBytes.byteLength,
    committed_at: committedAt,
    digest,
    executor_service_identity: pins.executorServiceIdentity,
    executor_version_id: pins.executorVersionId,
    key,
    observer_service_identity: pins.observerServiceIdentity,
    observer_version_id: pins.observerVersionId,
    schema: WORM_EXACT_OBJECT_EFFECT_SCHEMA,
  };
  return {
    canonicalBytes: exactBytes,
    committedAt,
    digest,
    effectId: `sha256:${await sha256Hex(canonicalBytes(identity))}`,
    key,
    pins,
  };
}

export function assertWormExactObjectEffectPins(pins: WormExactObjectEffectPins): void {
  copyAndValidatePins(pins);
}

export function canonicalEffectTimestamp(value: string): string {
  const milliseconds = Date.parse(value);
  if (
    value.length !== 24 ||
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds).toISOString() !== value
  ) {
    throw effectError("WORM_EXACT_OBJECT_EFFECT_TIME_INVALID");
  }
  return value;
}

export function effectError(code: string, retryable = false): BrokerError {
  return new BrokerError(code, retryable ? 503 : 409, retryable);
}

function copyAndValidatePins(pins: WormExactObjectEffectPins): WormExactObjectEffectPins {
  const copied = {
    executorServiceIdentity: pins.executorServiceIdentity,
    executorVersionId: pins.executorVersionId,
    observerServiceIdentity: pins.observerServiceIdentity,
    observerVersionId: pins.observerVersionId,
  };
  if (
    !VERSION.test(copied.executorVersionId) ||
    !VERSION.test(copied.observerVersionId) ||
    !SERVICE_IDENTITY.test(copied.executorServiceIdentity) ||
    !SERVICE_IDENTITY.test(copied.observerServiceIdentity) ||
    !copied.executorServiceIdentity.endsWith(`@${copied.executorVersionId}`) ||
    !copied.observerServiceIdentity.endsWith(`@${copied.observerVersionId}`) ||
    copied.executorServiceIdentity === copied.observerServiceIdentity
  ) {
    throw effectError("WORM_EXACT_OBJECT_EFFECT_PIN_INVALID");
  }
  return Object.freeze(copied);
}
