import { canonicalBytes, sha256Hex } from "../src/canonical";
import {
  confirmActivationComponentEnvelopeObject,
  confirmActivationComponentManifestObject,
  prepareActivationComponentEnvelopeEffect,
  prepareActivationComponentManifestEffect,
  type ConfirmedActivationComponentEnvelopeObject,
  type ConfirmedActivationComponentManifestObject,
} from "../src/activation-component-confirmation";
import {
  ACTIVATION_COMPONENT_KINDS,
  type ActivationComponentKind,
  type ActivationComponentPayloadInput,
} from "../src/activation-component-contract";
import { buildActivationComponentSetDescriptor } from "../src/activation-component-descriptor";
import { buildActivationComponentEnvelope } from "../src/activation-component-envelope";
import { buildActivationComponentManifest } from "../src/activation-component-manifest";
import type { ActivationWorm, JsonObject } from "../src/types";
import type {
  ConfirmedWormExactObjectEffect,
  PreparedWormExactObjectEffect,
  WormExactObjectEffectPins,
} from "../src/worm-exact-object-effect-contract";
import { buildWormExactObjectEffectResult } from "../src/worm-exact-object-effect-result";

export const COMPONENT_WORKER_VERSION = "11111111-1111-4111-8111-111111111111";
export const COMPONENT_COMMITTED_AT = "2026-08-19T12:00:00.000Z";
export const COMPONENT_RETENTION_UNTIL = "2034-08-20T12:00:00.000Z";
const EXECUTOR_VERSION = "22222222-2222-4222-8222-222222222222";
const OBSERVER_VERSION = "33333333-3333-4333-8333-333333333333";
export const COMPONENT_EFFECT_PINS: WormExactObjectEffectPins = Object.freeze({
  executorServiceIdentity: `cloudflare-worker:${"a".repeat(32)}/worm-mirror@${EXECUTOR_VERSION}`,
  executorVersionId: EXECUTOR_VERSION,
  observerServiceIdentity: `cloudflare-worker:${"a".repeat(32)}/b2-observer@${OBSERVER_VERSION}`,
  observerVersionId: OBSERVER_VERSION,
});

export interface ActivationComponentFixture {
  readonly descriptor: Awaited<ReturnType<typeof buildActivationComponentSetDescriptor>>;
  readonly envelopes: readonly Awaited<ReturnType<typeof buildActivationComponentEnvelope>>[];
  readonly manifest: Awaited<ReturnType<typeof buildActivationComponentManifest>>;
  readonly componentConfirmations: readonly ConfirmedActivationComponentEnvelopeObject[];
  readonly manifestConfirmation: ConfirmedActivationComponentManifestObject;
  readonly payloads: readonly ActivationComponentPayloadInput[];
}

export async function activationComponentFixture(): Promise<ActivationComponentFixture> {
  const payloads = componentPayloads();
  const descriptor = await descriptorForPayloads(payloads);
  const envelopes = await Promise.all(
    payloads.map(({ canonicalPayloadBytes, componentKind }) =>
      buildActivationComponentEnvelope(
        descriptor.canonicalBytes,
        componentKind,
        canonicalPayloadBytes,
      ),
    ),
  );
  const componentConfirmations = await Promise.all(
    envelopes.map((envelope, index) =>
      confirmedComponentEnvelope(descriptor.canonicalBytes, envelope, index),
    ),
  );
  const manifest = await buildActivationComponentManifest(
    descriptor.canonicalBytes,
    componentConfirmations,
  );
  return {
    componentConfirmations,
    descriptor,
    envelopes,
    manifest,
    manifestConfirmation: await confirmedComponentManifest(manifest),
    payloads,
  };
}

export function componentPayloads(): readonly ActivationComponentPayloadInput[] {
  return ACTIVATION_COMPONENT_KINDS.map((componentKind, index) => ({
    canonicalPayloadBytes: canonicalBytes({
      component_kind: componentKind,
      evidence_sha256: tagged(100 + index),
      ordinal: index,
      schema: `dpone.fixture.${componentKind}.v1`,
      schema_version: 1,
    }),
    componentKind,
  }));
}

export async function descriptorForPayloads(
  payloads: readonly ActivationComponentPayloadInput[],
  committedAt = COMPONENT_COMMITTED_AT,
) {
  return buildActivationComponentSetDescriptor({
    committedAt,
    components: await Promise.all(
      payloads.map(async ({ canonicalPayloadBytes, componentKind }) => ({
        componentKind,
        payloadSha256: `sha256:${await sha256Hex(canonicalPayloadBytes)}`,
      })),
    ),
    workerVersionId: COMPONENT_WORKER_VERSION,
  });
}

export async function descriptorWithPayload(
  componentKind: ActivationComponentKind,
  canonicalPayloadBytes: Uint8Array,
) {
  const payloads = componentPayloads().map((input) =>
    input.componentKind === componentKind ? { canonicalPayloadBytes, componentKind } : input,
  );
  return descriptorForPayloads(payloads);
}

export function componentWorm(
  envelope: Awaited<ReturnType<typeof buildActivationComponentEnvelope>>,
  index: number,
): ActivationWorm {
  return {
    digest: envelope.envelopeSha256,
    key: envelope.key,
    retentionUntil: COMPONENT_RETENTION_UNTIL,
    versionId: `4_z-activation-component-${String(index).padStart(2, "0")}`,
  };
}

export function manifestWorm(
  manifest: Awaited<ReturnType<typeof buildActivationComponentManifest>>,
): ActivationWorm {
  return {
    digest: manifest.manifestSha256,
    key: manifest.key,
    retentionUntil: COMPONENT_RETENTION_UNTIL,
    versionId: "4_z-activation-component-manifest-0001",
  };
}

export async function confirmedComponentEnvelope(
  descriptorBytes: Uint8Array,
  envelope: Awaited<ReturnType<typeof buildActivationComponentEnvelope>>,
  index: number,
  versionId = `4_z-activation-component-${String(index).padStart(2, "0")}`,
): Promise<ConfirmedActivationComponentEnvelopeObject> {
  const effect = await prepareActivationComponentEnvelopeEffect(
    descriptorBytes,
    envelope.canonicalBytes,
    COMPONENT_EFFECT_PINS,
  );
  return confirmActivationComponentEnvelopeObject(
    descriptorBytes,
    effect,
    resultBytes(effect, { ...componentWorm(envelope, index), versionId }, 500 + index),
  );
}

export async function confirmedComponentManifest(
  manifest: Awaited<ReturnType<typeof buildActivationComponentManifest>>,
): Promise<ConfirmedActivationComponentManifestObject> {
  const effect = await prepareActivationComponentManifestEffect(
    manifest.canonicalBytes,
    COMPONENT_EFFECT_PINS,
  );
  return confirmActivationComponentManifestObject(
    effect,
    resultBytes(effect, manifestWorm(manifest), 900),
  );
}

export function resultBytes(
  effect: PreparedWormExactObjectEffect,
  worm: ActivationWorm,
  absenceOrdinal: number,
): Uint8Array {
  const confirmed: ConfirmedWormExactObjectEffect = {
    absenceInventoryDigest: tagged(absenceOrdinal),
    committedAt: effect.committedAt,
    digest: effect.digest,
    effectId: effect.effectId,
    key: effect.key,
    pins: effect.pins,
    status: "CONFIRMED",
    worm,
  };
  return buildWormExactObjectEffectResult(confirmed);
}

export function decoded(bytes: Uint8Array): JsonObject {
  return JSON.parse(new TextDecoder().decode(bytes)) as JsonObject;
}

export function tagged(value: number): string {
  return `sha256:${value.toString(16).padStart(64, "0")}`;
}
