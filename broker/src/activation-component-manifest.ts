import { canonicalBytes } from "./canonical";
import { componentError } from "./activation-component-codec";
import {
  ACTIVATION_COMPONENT_KINDS,
  ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
  type ActivationComponentKind,
  type PreparedActivationComponentEnvelope,
  type PreparedActivationComponentManifest,
  type PreparedActivationComponentManifestPointer,
} from "./activation-component-contract";
import {
  confirmActivationComponentEnvelopeObject,
  confirmActivationComponentManifestObject,
  snapshotConfirmedActivationComponentObject,
  type ConfirmedActivationComponentEnvelopeObject,
  type ConfirmedActivationComponentManifestObject,
} from "./activation-component-confirmation";
import { parseActivationComponentSetDescriptor } from "./activation-component-descriptor";
import { parseActivationComponentEnvelope } from "./activation-component-envelope";
import { ownExactUint8Array } from "./exact-uint8array";
import {
  assembleActivationComponentManifest,
  parseActivationComponentManifest,
} from "./activation-component-manifest-codec";
import type { ActivationWorm } from "./types";
import {
  activationComponentWormJson,
  assertUniqueActivationComponentWorms,
  copyActivationComponentWorm,
  parseActivationComponentManifestPointer,
  validateActivationComponentWorm,
  validateActivationManifestWorm,
} from "./activation-component-manifest-worm";

export { parseActivationComponentManifest } from "./activation-component-manifest-codec";
export {
  activationComponentManifestWormKey,
  parseActivationComponentManifestPointer,
} from "./activation-component-manifest-worm";

const MANIFEST_INVALID = "ACTIVATION_COMPONENT_MANIFEST_INVALID";

/** Build the exact manifest only from the descriptor and revalidated generic-effect results. */
export async function buildActivationComponentManifest(
  descriptorBytes: Uint8Array,
  inputs: readonly ConfirmedActivationComponentEnvelopeObject[],
): Promise<PreparedActivationComponentManifest> {
  if (inputs.length !== ACTIVATION_COMPONENT_KINDS.length) throw componentError(MANIFEST_INVALID);
  const descriptorSnapshot = manifestBytes(descriptorBytes);
  const confirmationSnapshots = inputs.map((input) => {
    const confirmed = snapshotConfirmedActivationComponentObject(input);
    if (confirmed.objectType !== "COMPONENT") throw componentError(MANIFEST_INVALID);
    return confirmed;
  });
  const descriptor = await parseActivationComponentSetDescriptor(descriptorSnapshot);
  const parsed = await Promise.all(
    confirmationSnapshots.map(async (snapshot) => {
      const reconfirmed = await confirmActivationComponentEnvelopeObject(
        descriptor.canonicalBytes,
        snapshot.effect,
        snapshot.resultBytes,
      );
      return {
        envelope: await parseActivationComponentEnvelope(
          reconfirmed.effect.canonicalBytes,
          descriptor.canonicalBytes,
        ),
        worm: copyActivationComponentWorm(reconfirmed.confirmed.worm),
      };
    }),
  );
  const byKind = new Map<
    ActivationComponentKind,
    { readonly envelope: PreparedActivationComponentEnvelope; readonly worm: ActivationWorm }
  >();
  for (const candidate of parsed) {
    if (byKind.has(candidate.envelope.componentKind)) throw componentError(MANIFEST_INVALID);
    byKind.set(candidate.envelope.componentKind, candidate);
  }
  const components = Object.freeze(
    ACTIVATION_COMPONENT_KINDS.map((componentKind) => {
      const candidate = byKind.get(componentKind);
      if (candidate === undefined) throw componentError(MANIFEST_INVALID);
      const worm = validateActivationComponentWorm(candidate.worm, candidate.envelope, descriptor);
      return Object.freeze({
        componentId: candidate.envelope.componentId,
        componentKind,
        envelopeSha256: candidate.envelope.envelopeSha256,
        payloadSha256: candidate.envelope.payloadSha256,
        worm,
      });
    }),
  );
  assertUniqueActivationComponentWorms(components);
  return assembleActivationComponentManifest(descriptor, components);
}

/** Seal the manifest itself; this exact pointer, not an inline manifest, belongs in compact A0. */
export async function buildActivationComponentManifestPointer(
  input: ConfirmedActivationComponentManifestObject,
): Promise<PreparedActivationComponentManifestPointer> {
  const confirmed = snapshotConfirmedActivationComponentObject(input);
  if (confirmed.objectType !== "MANIFEST") throw componentError(MANIFEST_INVALID);
  const reconfirmed = await confirmActivationComponentManifestObject(
    confirmed.effect,
    confirmed.resultBytes,
  );
  const parsed = await parseActivationComponentManifest(
    manifestBytes(reconfirmed.effect.canonicalBytes),
  );
  const worm = validateActivationManifestWorm(reconfirmed.confirmed.worm, parsed);
  return parseActivationComponentManifestPointer(
    canonicalBytes({
      manifest_id: parsed.manifestId,
      manifest_sha256: parsed.manifestSha256,
      worm: activationComponentWormJson(worm),
    }),
  );
}

function manifestBytes(input: unknown): Uint8Array {
  return ownExactUint8Array(input, {
    code: MANIFEST_INVALID,
    invalidStatus: 409,
    maximum: ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
    minimum: 1,
    sizeStatus: 413,
  });
}
