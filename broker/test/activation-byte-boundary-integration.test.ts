import { beforeAll, describe, expect, it } from "vitest";

import { buildActivationComponentEnvelope } from "../src/activation-component-envelope";
import { ConfidentialActivationComponentResolver } from "../src/activation-component-resolver";
import { boundedOperationSnapshot } from "../src/activation-operation-store-validation";
import { componentPayloads, descriptorForPayloads } from "./activation-component-manifest.fixtures";
import {
  fixtureReader,
  productionResolverFixture,
  type ActivationComponentResolverFixture,
} from "./activation-component-resolver.fixtures";

describe("unified activation byte ownership boundary", () => {
  let resolverFixture: ActivationComponentResolverFixture;

  beforeAll(async () => {
    resolverFixture = await productionResolverFixture();
  });

  it("owns descriptor and payload bytes synchronously before component hashing", async () => {
    const payloads = componentPayloads();
    const descriptor = await descriptorForPayloads(payloads);
    const first = payloads[0];
    if (first === undefined) throw new Error("component payload fixture missing");
    const baseline = await buildActivationComponentEnvelope(
      descriptor.canonicalBytes,
      first.componentKind,
      first.canonicalPayloadBytes,
    );
    const mutableDescriptor = Uint8Array.from(descriptor.canonicalBytes);
    const mutablePayload = Uint8Array.from(first.canonicalPayloadBytes);

    const building = buildActivationComponentEnvelope(
      mutableDescriptor,
      first.componentKind,
      mutablePayload,
    );
    mutableDescriptor.fill(0);
    mutablePayload.fill(0);

    expect((await building).canonicalBytes).toEqual(baseline.canonicalBytes);
  });

  it("ignores decorated component bytes without evaluating their properties", async () => {
    const payloads = componentPayloads();
    const descriptor = await descriptorForPayloads(payloads);
    const first = payloads[0];
    if (first === undefined) throw new Error("component payload fixture missing");
    let getterCalls = 0;
    const decorated = Uint8Array.from(first.canonicalPayloadBytes);
    Object.defineProperty(decorated, Symbol.iterator, {
      get() {
        getterCalls += 1;
        throw new Error("decorated iterator must not execute");
      },
    });

    const baseline = await buildActivationComponentEnvelope(
      descriptor.canonicalBytes,
      first.componentKind,
      first.canonicalPayloadBytes,
    );
    await expect(
      buildActivationComponentEnvelope(descriptor.canonicalBytes, first.componentKind, decorated),
    ).resolves.toMatchObject({ envelopeSha256: baseline.envelopeSha256 });
    expect(getterCalls).toBe(0);
  });

  it("ignores a decorated resolver pointer without evaluating its properties", async () => {
    const reader = fixtureReader(resolverFixture);
    const resolver = new ConfidentialActivationComponentResolver(
      reader,
      resolverFixture.source.source.config,
    );
    let getterCalls = 0;
    const decorated = Uint8Array.from(resolverFixture.pointerBytes);
    Object.defineProperty(decorated, "hidden", {
      get() {
        getterCalls += 1;
        throw new Error("decorated pointer getter must not execute");
      },
    });

    await expect(resolver.resolve(decorated)).resolves.toMatchObject({
      trust: "RESOLVED_SEMANTICS",
    });
    expect(getterCalls).toBe(0);
    expect(reader.trace).toHaveLength(2);
  });

  it("applies operation-store size policy before any caller iterator", () => {
    let iteratorCalls = 0;
    const oversized = new Uint8Array(65_537);
    Object.defineProperty(oversized, "byteLength", { value: 1 });
    Object.defineProperty(oversized, Symbol.iterator, {
      get() {
        iteratorCalls += 1;
        throw new Error("operation iterator must not execute");
      },
    });

    expect(() => boundedOperationSnapshot(oversized, 65_536)).toThrowError(
      expect.objectContaining({
        code: "ACTIVATION_OPERATION_SLOT_SIZE_INVALID",
        status: 413,
      }),
    );
    expect(iteratorCalls).toBe(0);
  });
});
