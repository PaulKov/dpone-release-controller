import {
  ACTIVATION_COMPONENT_ENVELOPE_MAX_BYTES,
  ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
  type PreparedActivationComponentEnvelope,
  type PreparedActivationComponentManifest,
} from "./activation-component-contract";
import { parseActivationComponentSetDescriptor } from "./activation-component-descriptor";
import { parseActivationComponentEnvelope } from "./activation-component-envelope";
import { componentError } from "./activation-component-codec";
import { parseActivationComponentManifest } from "./activation-component-manifest-codec";
import { ownExactUint8Array } from "./exact-uint8array";
import {
  assertWormExactObjectEffectPins,
  prepareWormExactObjectEffectWithKeyPolicy,
  WORM_EXACT_OBJECT_MAX_BYTES,
  type ConfirmedWormExactObjectEffect,
  type PreparedWormExactObjectEffect,
  type WormExactObjectEffectPins,
} from "./worm-exact-object-effect-contract";
import { parseWormExactObjectEffectResult } from "./worm-exact-object-effect-result";

const CONFIRMATION_INVALID = "ACTIVATION_COMPONENT_CONFIRMATION_INVALID";
const confirmationBrand: unique symbol = Symbol("ConfirmedActivationComponentObject");

interface ConfirmedActivationComponentObjectBase {
  readonly confirmed: ConfirmedWormExactObjectEffect;
  readonly effect: PreparedWormExactObjectEffect;
  readonly resultBytes: Uint8Array;
  readonly [confirmationBrand]: true;
}

export interface ConfirmedActivationComponentEnvelopeObject
  extends ConfirmedActivationComponentObjectBase {
  readonly objectType: "COMPONENT";
}

export interface ConfirmedActivationComponentManifestObject
  extends ConfirmedActivationComponentObjectBase {
  readonly objectType: "MANIFEST";
}

export type ConfirmedActivationComponentObject =
  | ConfirmedActivationComponentEnvelopeObject
  | ConfirmedActivationComponentManifestObject;

/** Derive the exact generic effect plan for one descriptor-bound component envelope. */
export async function prepareActivationComponentEnvelopeEffect(
  descriptorBytes: Uint8Array,
  canonicalEnvelopeBytes: Uint8Array,
  pins: WormExactObjectEffectPins,
): Promise<PreparedWormExactObjectEffect> {
  const descriptorSnapshot = confirmationBytes(
    descriptorBytes,
    ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
  );
  const envelopeSnapshot = confirmationBytes(
    canonicalEnvelopeBytes,
    ACTIVATION_COMPONENT_ENVELOPE_MAX_BYTES,
  );
  const pinsSnapshot = snapshotPins(pins);
  const descriptor = await parseActivationComponentSetDescriptor(descriptorSnapshot);
  const envelope = await parseActivationComponentEnvelope(
    envelopeSnapshot,
    descriptor.canonicalBytes,
  );
  return prepareCandidateEffect(envelope, descriptor.committedAt, pinsSnapshot);
}

/** Bind an exact WORM result to the sealed component effect and return an opaque confirmation. */
export async function confirmActivationComponentEnvelopeObject(
  descriptorBytes: Uint8Array,
  sealedEffect: PreparedWormExactObjectEffect,
  canonicalResultBytes: Uint8Array,
): Promise<ConfirmedActivationComponentEnvelopeObject> {
  const descriptorSnapshot = confirmationBytes(
    descriptorBytes,
    ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
  );
  const effectSnapshot = snapshotEffect(sealedEffect);
  const resultSnapshot = confirmationBytes(canonicalResultBytes, WORM_EXACT_OBJECT_MAX_BYTES);
  const expected = await prepareActivationComponentEnvelopeEffect(
    descriptorSnapshot,
    effectSnapshot.canonicalBytes,
    effectSnapshot.pins,
  );
  assertSameEffect(effectSnapshot, expected);
  return confirmedObject(
    "COMPONENT",
    expected,
    resultSnapshot,
    parseWormExactObjectEffectResult(resultSnapshot, expected),
  );
}

/** Derive the exact generic effect plan for the separately sealed component manifest. */
export async function prepareActivationComponentManifestEffect(
  canonicalManifestBytes: Uint8Array,
  pins: WormExactObjectEffectPins,
): Promise<PreparedWormExactObjectEffect> {
  const manifestSnapshot = confirmationBytes(
    canonicalManifestBytes,
    ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
  );
  const pinsSnapshot = snapshotPins(pins);
  const manifest = await parseActivationComponentManifest(manifestSnapshot);
  return prepareCandidateEffect(manifest, manifest.committedAt, pinsSnapshot);
}

/** Bind an exact WORM result to the sealed manifest effect and return an opaque confirmation. */
export async function confirmActivationComponentManifestObject(
  sealedEffect: PreparedWormExactObjectEffect,
  canonicalResultBytes: Uint8Array,
): Promise<ConfirmedActivationComponentManifestObject> {
  const effectSnapshot = snapshotEffect(sealedEffect);
  const resultSnapshot = confirmationBytes(canonicalResultBytes, WORM_EXACT_OBJECT_MAX_BYTES);
  const expected = await prepareActivationComponentManifestEffect(
    effectSnapshot.canonicalBytes,
    effectSnapshot.pins,
  );
  assertSameEffect(effectSnapshot, expected);
  return confirmedObject(
    "MANIFEST",
    expected,
    resultSnapshot,
    parseWormExactObjectEffectResult(resultSnapshot, expected),
  );
}

/** Re-own a branded confirmation before an asynchronous authoritative builder uses it. */
export function snapshotConfirmedActivationComponentObject(
  input: unknown,
): ConfirmedActivationComponentObject {
  if (
    input === null ||
    typeof input !== "object" ||
    !(confirmationBrand in input) ||
    input[confirmationBrand] !== true
  ) {
    throw componentError(CONFIRMATION_INVALID);
  }
  const confirmedInput = input as ConfirmedActivationComponentObject;
  return freezeConfirmation(
    confirmedInput.objectType,
    snapshotEffect(confirmedInput.effect),
    confirmationBytes(confirmedInput.resultBytes, WORM_EXACT_OBJECT_MAX_BYTES),
    freezeConfirmed(confirmedInput.confirmed),
  );
}

function prepareCandidateEffect(
  exact: PreparedActivationComponentEnvelope | PreparedActivationComponentManifest,
  committedAt: string,
  pins: WormExactObjectEffectPins,
): Promise<PreparedWormExactObjectEffect> {
  return prepareWormExactObjectEffectWithKeyPolicy(
    {
      canonicalBytes: exact.canonicalBytes,
      committedAt,
      digest: "envelopeSha256" in exact ? exact.envelopeSha256 : exact.manifestSha256,
      key: exact.key,
      pins,
    },
    (key) => key === exact.key,
  );
}

function confirmedObject<T extends "COMPONENT" | "MANIFEST">(
  objectType: T,
  effect: PreparedWormExactObjectEffect,
  resultBytes: Uint8Array,
  confirmed: ConfirmedWormExactObjectEffect,
): T extends "COMPONENT"
  ? ConfirmedActivationComponentEnvelopeObject
  : ConfirmedActivationComponentManifestObject {
  return freezeConfirmation(objectType, effect, resultBytes, confirmed) as T extends "COMPONENT"
    ? ConfirmedActivationComponentEnvelopeObject
    : ConfirmedActivationComponentManifestObject;
}

function freezeConfirmation(
  objectType: "COMPONENT" | "MANIFEST",
  effect: PreparedWormExactObjectEffect,
  resultBytes: Uint8Array,
  confirmed: ConfirmedWormExactObjectEffect,
): ConfirmedActivationComponentObject {
  const common = {
    [confirmationBrand]: true,
    confirmed: freezeConfirmed(confirmed),
    effect: freezeEffect(effect),
    resultBytes: confirmationBytes(resultBytes, WORM_EXACT_OBJECT_MAX_BYTES),
  } as const;
  return objectType === "COMPONENT"
    ? Object.freeze({ ...common, objectType: "COMPONENT" as const })
    : Object.freeze({ ...common, objectType: "MANIFEST" as const });
}

function freezeEffect(effect: PreparedWormExactObjectEffect): PreparedWormExactObjectEffect {
  return Object.freeze({
    canonicalBytes: confirmationBytes(effect.canonicalBytes, WORM_EXACT_OBJECT_MAX_BYTES),
    committedAt: effect.committedAt,
    digest: effect.digest,
    effectId: effect.effectId,
    key: effect.key,
    pins: Object.freeze({ ...effect.pins }),
  });
}

function freezeConfirmed(
  confirmed: ConfirmedWormExactObjectEffect,
): ConfirmedWormExactObjectEffect {
  return Object.freeze({
    ...confirmed,
    pins: Object.freeze({ ...confirmed.pins }),
    worm: Object.freeze({ ...confirmed.worm }),
  });
}

function snapshotEffect(effect: PreparedWormExactObjectEffect): PreparedWormExactObjectEffect {
  return {
    canonicalBytes: confirmationBytes(effect.canonicalBytes, WORM_EXACT_OBJECT_MAX_BYTES),
    committedAt: effect.committedAt,
    digest: effect.digest,
    effectId: effect.effectId,
    key: effect.key,
    pins: { ...effect.pins },
  };
}

function snapshotPins(pins: WormExactObjectEffectPins): WormExactObjectEffectPins {
  assertWormExactObjectEffectPins(pins);
  return Object.freeze({
    executorServiceIdentity: pins.executorServiceIdentity,
    executorVersionId: pins.executorVersionId,
    observerServiceIdentity: pins.observerServiceIdentity,
    observerVersionId: pins.observerVersionId,
  });
}

function assertSameEffect(
  stored: PreparedWormExactObjectEffect,
  rebuilt: PreparedWormExactObjectEffect,
): void {
  if (
    stored.effectId !== rebuilt.effectId ||
    stored.committedAt !== rebuilt.committedAt ||
    stored.digest !== rebuilt.digest ||
    stored.key !== rebuilt.key ||
    stored.pins.executorServiceIdentity !== rebuilt.pins.executorServiceIdentity ||
    stored.pins.executorVersionId !== rebuilt.pins.executorVersionId ||
    stored.pins.observerServiceIdentity !== rebuilt.pins.observerServiceIdentity ||
    stored.pins.observerVersionId !== rebuilt.pins.observerVersionId ||
    !sameBytes(stored.canonicalBytes, rebuilt.canonicalBytes)
  ) {
    throw componentError(CONFIRMATION_INVALID);
  }
}

function confirmationBytes(input: unknown, maximum: number): Uint8Array {
  return ownExactUint8Array(input, {
    code: CONFIRMATION_INVALID,
    invalidStatus: 409,
    maximum,
    minimum: 1,
    sizeStatus: 413,
  });
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}
