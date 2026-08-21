import { describe, expect, it } from "vitest";

import {
  confirmActivationComponentEnvelopeObject,
  confirmActivationComponentManifestObject,
  prepareActivationComponentEnvelopeEffect,
  prepareActivationComponentManifestEffect,
} from "../src/activation-component-confirmation";
import { canonicalBytes } from "../src/canonical";
import { activationJsonBudget } from "../src/activation-component-codec";
import { ACTIVATION_COMPONENT_KINDS } from "../src/activation-component-contract";
import {
  buildActivationComponentManifest,
  buildActivationComponentManifestPointer,
  parseActivationComponentManifest,
  parseActivationComponentManifestPointer,
} from "../src/activation-component-manifest";
import {
  validateActivationComponentWorm,
  validateActivationManifestWorm,
} from "../src/activation-component-manifest-worm";
import { prepareWormExactObjectEffect } from "../src/worm-exact-object-effect-contract";
import {
  COMPONENT_COMMITTED_AT,
  COMPONENT_EFFECT_PINS,
  COMPONENT_RETENTION_UNTIL,
  activationComponentFixture,
  confirmedComponentEnvelope,
  decoded,
  resultBytes,
} from "./activation-component-manifest.fixtures";

describe("activation component manifest", () => {
  it("builds and parses one deterministic sealed-roster manifest", async () => {
    const fixture = await activationComponentFixture();
    const parsed = await parseActivationComponentManifest(fixture.manifest.canonicalBytes);

    expect(parsed.canonicalBytes).toEqual(fixture.manifest.canonicalBytes);
    expect(parsed).toMatchObject({
      committedAt: COMPONENT_COMMITTED_AT,
      descriptorId: fixture.descriptor.descriptorId,
      descriptorSha256: fixture.descriptor.descriptorSha256,
      setId: fixture.descriptor.setId,
      trust: "UNTRUSTED",
    });
    expect(parsed.components.map(({ componentKind }) => componentKind)).toEqual(
      ACTIVATION_COMPONENT_KINDS,
    );
    const budget = activationJsonBudget(decoded(parsed.canonicalBytes));
    expect(budget).toMatchObject({ bytes: parsed.canonicalBytes.byteLength });
    expect(budget.nodes).toBeLessThanOrEqual(512);
    expect(budget.depth).toBeLessThanOrEqual(16);
    expect(parsed.canonicalBytes.byteLength).toBeLessThanOrEqual(65_536);
    expect({
      bytes: parsed.canonicalBytes.byteLength,
      manifestId: parsed.manifestId,
      manifestSha256: parsed.manifestSha256,
      nodes: budget.nodes,
    }).toEqual({
      bytes: 13_504,
      manifestId: "sha256:c87034d32bcc99e88274f2e3852fc2cc8d73736bf3d97ebaf6cb3a19b18eefee",
      manifestSha256: "sha256:2393ccebc40393dabcf37a04b4b85a4d49f52e924c51bb656e97e7b3f7781640",
      nodes: 162,
    });
  });

  it("is independent of upload completion order but rejects missing or duplicate kinds", async () => {
    const fixture = await activationComponentFixture();
    const reversed = await buildActivationComponentManifest(
      fixture.descriptor.canonicalBytes,
      [...fixture.componentConfirmations].reverse(),
    );
    expect(reversed.canonicalBytes).toEqual(fixture.manifest.canonicalBytes);

    await expect(
      buildActivationComponentManifest(
        fixture.descriptor.canonicalBytes,
        fixture.componentConfirmations.slice(0, -1),
      ),
    ).rejects.toThrow("ACTIVATION_COMPONENT_MANIFEST_INVALID");
    await expect(
      buildActivationComponentManifest(fixture.descriptor.canonicalBytes, [
        ...fixture.componentConfirmations.slice(0, -1),
        requireDefined(fixture.componentConfirmations[0], "missing first component confirmation"),
      ]),
    ).rejects.toThrow("ACTIVATION_COMPONENT_MANIFEST_INVALID");
  });

  it("owns every branded effect and result before the first asynchronous parse", async () => {
    const fixture = await activationComponentFixture();
    const first = requireDefined(
      fixture.componentConfirmations[0],
      "missing first component confirmation",
    );
    const promise = buildActivationComponentManifest(
      fixture.descriptor.canonicalBytes,
      fixture.componentConfirmations,
    );
    first.effect.canonicalBytes.fill(0);
    first.resultBytes.fill(0);
    expect((await promise).canonicalBytes).toEqual(fixture.manifest.canonicalBytes);
  });

  it("owns component and manifest execution pins before the first asynchronous parse", async () => {
    const fixture = await activationComponentFixture();
    const envelope = requireDefined(fixture.envelopes[0], "missing component envelope");
    const componentPins = { ...COMPONENT_EFFECT_PINS };
    const preparingComponent = prepareActivationComponentEnvelopeEffect(
      fixture.descriptor.canonicalBytes,
      envelope.canonicalBytes,
      componentPins,
    );
    componentPins.executorServiceIdentity = "attacker";
    componentPins.executorVersionId = "attacker";
    await expect(preparingComponent).resolves.toMatchObject({ pins: COMPONENT_EFFECT_PINS });

    const manifestPins = { ...COMPONENT_EFFECT_PINS };
    const preparingManifest = prepareActivationComponentManifestEffect(
      fixture.manifest.canonicalBytes,
      manifestPins,
    );
    manifestPins.observerServiceIdentity = "attacker";
    manifestPins.observerVersionId = "attacker";
    await expect(preparingManifest).resolves.toMatchObject({ pins: COMPONENT_EFFECT_PINS });
  });

  it("rejects post-confirm byte mutation, result transplants, and duplicate WORM versions", async () => {
    const fixture = await activationComponentFixture();
    const mutated = requireDefined(
      fixture.componentConfirmations[0],
      "missing first component confirmation",
    );
    mutated.resultBytes.fill(0);
    await expect(
      buildActivationComponentManifest(
        fixture.descriptor.canonicalBytes,
        fixture.componentConfirmations,
      ),
    ).rejects.toThrow(/ACTIVATION_COMPONENT_|WORM_EXACT_OBJECT_EFFECT_/u);

    const fresh = await activationComponentFixture();
    const first = requireDefined(
      fresh.componentConfirmations[0],
      "missing first component confirmation",
    );
    const second = requireDefined(
      fresh.componentConfirmations[1],
      "missing second component confirmation",
    );
    await expect(prepareWormExactObjectEffect(first.effect)).rejects.toThrow(
      "WORM_EXACT_OBJECT_EFFECT_INPUT_INVALID",
    );
    await expect(
      confirmActivationComponentEnvelopeObject(
        fresh.descriptor.canonicalBytes,
        first.effect,
        second.resultBytes,
      ),
    ).rejects.toThrow(/WORM_EXACT_OBJECT_EFFECT_RESULT_(?:BINDING_)?INVALID/u);

    const duplicateVersion = await confirmedComponentEnvelope(
      fresh.descriptor.canonicalBytes,
      requireDefined(fresh.envelopes[1], "missing second component envelope"),
      1,
      first.confirmed.worm.versionId,
    );
    const duplicateConfirmations = [...fresh.componentConfirmations];
    duplicateConfirmations[1] = duplicateVersion;
    await expect(
      buildActivationComponentManifest(fresh.descriptor.canonicalBytes, duplicateConfirmations),
    ).rejects.toThrow("ACTIVATION_COMPONENT_MANIFEST_INVALID");

    const unbranded = {
      confirmed: first.confirmed,
      effect: first.effect,
      objectType: first.objectType,
      resultBytes: first.resultBytes,
    } as typeof first;
    const unbrandedInputs = [...fresh.componentConfirmations];
    unbrandedInputs[0] = unbranded;
    await expect(
      buildActivationComponentManifest(fresh.descriptor.canonicalBytes, unbrandedInputs),
    ).rejects.toThrow("ACTIVATION_COMPONENT_CONFIRMATION_INVALID");
  });

  it("seals the manifest separately and emits only its exact compact-A0 pointer", async () => {
    const fixture = await activationComponentFixture();
    const pointerPromise = buildActivationComponentManifestPointer(fixture.manifestConfirmation);
    fixture.manifestConfirmation.effect.canonicalBytes.fill(0);
    fixture.manifestConfirmation.resultBytes.fill(0);
    const pointer = await pointerPromise;
    expect(parseActivationComponentManifestPointer(pointer.canonicalBytes)).toEqual(pointer);
    expect(pointer).toMatchObject({
      manifestId: fixture.manifest.manifestId,
      manifestSha256: fixture.manifest.manifestSha256,
      trust: "UNTRUSTED",
    });
    expect(pointer.document).toEqual({
      manifest_id: fixture.manifest.manifestId,
      manifest_sha256: fixture.manifest.manifestSha256,
      worm: {
        digest: fixture.manifest.manifestSha256,
        key: fixture.manifest.key,
        retention_until: COMPONENT_RETENTION_UNTIL,
        version_id: "4_z-activation-component-manifest-0001",
      },
    });
    expect(Object.isFrozen(pointer)).toBe(true);
    expect(Object.isFrozen(pointer.document)).toBe(true);
    expect(Object.isFrozen(pointer.document.worm)).toBe(true);

    const traversal = structuredClone(pointer.document);
    const traversalWorm = traversal.worm;
    if (
      traversalWorm === null ||
      traversalWorm === undefined ||
      typeof traversalWorm !== "object" ||
      Array.isArray(traversalWorm)
    ) {
      throw new Error("fixture manifest WORM missing");
    }
    traversalWorm.key =
      `receipts/v2/activation-component-manifests/../${fixture.manifest.manifestId.slice(7)}/` +
      `${fixture.manifest.manifestSha256.slice(7)}.json`;
    expect(() => parseActivationComponentManifestPointer(canonicalBytes(traversal))).toThrow(
      "ACTIVATION_COMPONENT_MANIFEST_INVALID",
    );
  });

  it("rejects altered manifest bytes, invalid retention, and post-confirm mutation", async () => {
    const fixture = await activationComponentFixture();
    const altered = decoded(fixture.manifest.canonicalBytes);
    altered.component_set_committed_at = "2026-08-19T12:00:01.000Z";
    await expect(
      parseActivationComponentManifest(new TextEncoder().encode(JSON.stringify(altered))),
    ).rejects.toThrow("ACTIVATION_COMPONENT_MANIFEST_INVALID");

    const invalidComponentWorm = {
      ...requireDefined(fixture.componentConfirmations[0], "missing component confirmation")
        .confirmed.worm,
      retentionUntil: "not-a-date",
    };
    const componentEffect = requireDefined(
      fixture.componentConfirmations[0],
      "missing component confirmation",
    ).effect;
    await expect(
      confirmActivationComponentEnvelopeObject(
        fixture.descriptor.canonicalBytes,
        componentEffect,
        resultBytes(componentEffect, invalidComponentWorm, 999),
      ),
    ).rejects.toThrow("WORM_EXACT_OBJECT_EFFECT_TIME_INVALID");

    const manifestEffect = fixture.manifestConfirmation.effect;
    const invalidManifestWorm = {
      ...fixture.manifestConfirmation.confirmed.worm,
      retentionUntil: "not-a-date",
    };
    await expect(
      confirmActivationComponentManifestObject(
        manifestEffect,
        resultBytes(manifestEffect, invalidManifestWorm, 1_000),
      ),
    ).rejects.toThrow("WORM_EXACT_OBJECT_EFFECT_TIME_INVALID");

    const fresh = await activationComponentFixture();
    fresh.manifestConfirmation.effect.canonicalBytes.fill(0);
    await expect(
      buildActivationComponentManifestPointer(fresh.manifestConfirmation),
    ).rejects.toThrow(/ACTIVATION_COMPONENT_|WORM_EXACT_OBJECT_EFFECT_/u);
  });

  it("rejects noncanonical timestamps before retention arithmetic in untrusted scalar parsing", async () => {
    const fixture = await activationComponentFixture();
    const component = requireDefined(fixture.envelopes[0], "missing component envelope");
    const invalidComponentWorm = {
      ...requireDefined(fixture.componentConfirmations[0], "missing component confirmation")
        .confirmed.worm,
      retentionUntil: "not-a-timestamp",
    };
    expect(() =>
      validateActivationComponentWorm(invalidComponentWorm, component, fixture.descriptor),
    ).toThrow("ACTIVATION_COMPONENT_MANIFEST_INVALID");
    expect(() =>
      validateActivationManifestWorm(
        { ...fixture.manifestConfirmation.confirmed.worm, retentionUntil: "not-a-timestamp" },
        fixture.manifest,
      ),
    ).toThrow("ACTIVATION_COMPONENT_MANIFEST_INVALID");
  });
});

function requireDefined<T>(value: T | undefined, message: string): T {
  if (value === undefined) throw new Error(message);
  return value;
}
