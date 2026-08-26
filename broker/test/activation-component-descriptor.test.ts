import { describe, expect, it } from "vitest";

import { canonicalBytes, sha256Hex } from "../src/canonical";
import { activationJsonBudget } from "../src/activation-component-codec";
import {
  ACTIVATION_COMPONENT_KINDS,
  ACTIVATION_COMPONENT_PAYLOAD_MAX_NODES,
} from "../src/activation-component-contract";
import {
  buildActivationComponentSetDescriptor,
  parseActivationComponentSetDescriptor,
} from "../src/activation-component-descriptor";
import {
  activationComponentWormKey,
  buildActivationComponentEnvelope,
  parseActivationComponentEnvelope,
} from "../src/activation-component-envelope";
import type { JsonObject } from "../src/types";
import {
  COMPONENT_COMMITTED_AT,
  COMPONENT_WORKER_VERSION,
  componentPayloads,
  decoded,
  descriptorForPayloads,
  descriptorWithPayload,
} from "./activation-component-manifest.fixtures";

describe("activation component descriptor and envelope", () => {
  it("derives deterministic descriptor and component identities from an ordered closed roster", async () => {
    const payloads = componentPayloads();
    const descriptor = await descriptorForPayloads(payloads);
    const shuffled = await descriptorForPayloads([...payloads].reverse());
    const parsed = await parseActivationComponentSetDescriptor(descriptor.canonicalBytes);

    expect(shuffled.canonicalBytes).toEqual(descriptor.canonicalBytes);
    expect(parsed).toMatchObject({
      committedAt: COMPONENT_COMMITTED_AT,
      descriptorId: descriptor.descriptorId,
      descriptorSha256: descriptor.descriptorSha256,
      setId: descriptor.setId,
      trust: "UNTRUSTED",
      workerVersionId: COMPONENT_WORKER_VERSION,
    });
    expect(parsed.components.map(({ componentKind }) => componentKind)).toEqual(
      ACTIVATION_COMPONENT_KINDS,
    );

    const firstPayload = requireDefined(payloads[0], "missing first component payload");
    const envelope = await buildActivationComponentEnvelope(
      descriptor.canonicalBytes,
      firstPayload.componentKind,
      firstPayload.canonicalPayloadBytes,
    );
    expect(
      await parseActivationComponentEnvelope(envelope.canonicalBytes, descriptor.canonicalBytes),
    ).toEqual(envelope);
    const budget = activationJsonBudget(decoded(envelope.canonicalBytes));
    expect(budget.nodes).toBeLessThan(400);
    expect(budget.depth).toBeLessThanOrEqual(16);
    expect(budget.maxStringBytes).toBeLessThanOrEqual(32_768);
    expect({
      componentId: envelope.componentId,
      descriptorId: descriptor.descriptorId,
      descriptorSha256: descriptor.descriptorSha256,
      setId: descriptor.setId,
    }).toEqual({
      componentId: "sha256:44ab6f4f902f20694f707af3673eb4c210f99469c49559f3a23cca8fb33f2cee",
      descriptorId: "sha256:ac87a7545cc86e96c8a7ac33af8d695f47a4f2d9eb4e71b08d7b1548673b1dc7",
      descriptorSha256: "sha256:ad0999f304dd470401a1ca86e155226221d2754d8f038474881b9ee1dfa5fae0",
      setId: "sha256:08278ef70d8a4db20990b43c140d2e034497637374d9eb95847a001e2d999a5b",
    });
  });

  it("changes descriptor and object keys when the broker-frozen clock changes", async () => {
    const payloads = componentPayloads();
    const first = await descriptorForPayloads(payloads);
    const second = await descriptorForPayloads(payloads, "2026-08-19T12:00:01.000Z");
    expect(second.setId).toBe(first.setId);
    expect(second.descriptorId).not.toBe(first.descriptorId);
    expect(second.descriptorSha256).not.toBe(first.descriptorSha256);

    const input = requireDefined(payloads[0], "missing first component payload");
    const firstEnvelope = await buildActivationComponentEnvelope(
      first.canonicalBytes,
      input.componentKind,
      input.canonicalPayloadBytes,
    );
    const secondEnvelope = await buildActivationComponentEnvelope(
      second.canonicalBytes,
      input.componentKind,
      input.canonicalPayloadBytes,
    );
    expect(secondEnvelope.componentId).not.toBe(firstEnvelope.componentId);
    expect(secondEnvelope.key).not.toBe(firstEnvelope.key);
  });

  it("rejects a missing, duplicate, or digest-drifted descriptor roster", async () => {
    const payloads = componentPayloads();
    const digests = await payloadDigests(payloads);
    await expect(
      buildActivationComponentSetDescriptor({
        committedAt: COMPONENT_COMMITTED_AT,
        components: digests.slice(0, -1),
        workerVersionId: COMPONENT_WORKER_VERSION,
      }),
    ).rejects.toThrow("ACTIVATION_COMPONENT_DESCRIPTOR_INVALID");
    await expect(
      buildActivationComponentSetDescriptor({
        committedAt: COMPONENT_COMMITTED_AT,
        components: [
          ...digests.slice(0, -1),
          requireDefined(digests[0], "missing first component digest"),
        ],
        workerVersionId: COMPONENT_WORKER_VERSION,
      }),
    ).rejects.toThrow("ACTIVATION_COMPONENT_DESCRIPTOR_INVALID");

    const descriptor = await descriptorForPayloads(payloads);
    const changedPayload = canonicalBytes({ changed: true });
    await expect(
      buildActivationComponentEnvelope(descriptor.canonicalBytes, "admin_access", changedPayload),
    ).rejects.toThrow("ACTIVATION_COMPONENT_PAYLOAD_CONFLICT");
  });

  it("owns descriptor and payload inputs before asynchronous hashing", async () => {
    const payloads = componentPayloads();
    const digests = await payloadDigests(payloads);
    const descriptorPromise = buildActivationComponentSetDescriptor({
      committedAt: COMPONENT_COMMITTED_AT,
      components: digests,
      workerVersionId: COMPONENT_WORKER_VERSION,
    });
    const firstDigest = requireDefined(digests[0], "missing first component digest");
    firstDigest.payloadSha256 = "sha256:" + "f".repeat(64);
    const descriptor = await descriptorPromise;

    const firstPayload = requireDefined(payloads[0], "missing first component payload");
    const payload = Uint8Array.from(firstPayload.canonicalPayloadBytes);
    const original = Uint8Array.from(payload);
    const envelopePromise = buildActivationComponentEnvelope(
      descriptor.canonicalBytes,
      firstPayload.componentKind,
      payload,
    );
    payload.fill(0);
    const envelope = await envelopePromise;
    expect(envelope.payloadSha256).toBe(`sha256:${await sha256Hex(original)}`);
  });

  it("enforces byte, node, depth, string, canonical, and final-envelope budgets", async () => {
    const atNodeLimit = canonicalBytes({ items: Array.from({ length: 382 }, () => 0) });
    expect(activationJsonBudget(decoded(atNodeLimit)).nodes).toBe(
      ACTIVATION_COMPONENT_PAYLOAD_MAX_NODES,
    );
    const descriptor = await descriptorWithPayload("admin_access", atNodeLimit);
    const envelope = await buildActivationComponentEnvelope(
      descriptor.canonicalBytes,
      "admin_access",
      atNodeLimit,
    );
    expect(activationJsonBudget(decoded(envelope.canonicalBytes)).nodes).toBeLessThan(400);

    for (const invalid of [
      canonicalBytes({ items: Array.from({ length: 383 }, () => 0) }),
      canonicalBytes({ first: "x".repeat(30_000), second: "y".repeat(30_000) }),
      canonicalBytes({ value: "x".repeat(32_769) }),
      canonicalBytes(nestedPayload(14)),
      new TextEncoder().encode(JSON.stringify({ ["k".repeat(32_769)]: true })),
      new TextEncoder().encode('{"z":1,"a":2}'),
    ]) {
      const invalidDescriptor = await descriptorWithPayload("admin_access", invalid);
      await expect(
        buildActivationComponentEnvelope(invalidDescriptor.canonicalBytes, "admin_access", invalid),
      ).rejects.toThrow("ACTIVATION_COMPONENT_ENVELOPE_INVALID");
    }
  });

  it("rejects deeply nested bounded JSON with a typed error before recursive canonicalization", async () => {
    const nested = new TextEncoder().encode(
      `{"items":${"[".repeat(20_000)}0${"]".repeat(20_000)}}`,
    );
    expect(nested.byteLength).toBeLessThan(65_536);
    const descriptor = await descriptorWithPayload("admin_access", nested);
    await expect(
      buildActivationComponentEnvelope(descriptor.canonicalBytes, "admin_access", nested),
    ).rejects.toMatchObject({
      code: "ACTIVATION_COMPONENT_ENVELOPE_INVALID",
      status: 413,
    });
  });

  it("rejects untrusted worker text in the exported key helper", () => {
    expect(() =>
      activationComponentWormKey(
        "../../attacker",
        "sha256:" + "1".repeat(64),
        "sha256:" + "2".repeat(64),
        "sha256:" + "3".repeat(64),
        "admin_access",
        "sha256:" + "4".repeat(64),
      ),
    ).toThrow("ACTIVATION_COMPONENT_ENVELOPE_INVALID");
  });
});

async function payloadDigests(payloads: ReturnType<typeof componentPayloads>) {
  return Promise.all(
    payloads.map(async ({ canonicalPayloadBytes, componentKind }) => ({
      componentKind,
      payloadSha256: `sha256:${await sha256Hex(canonicalPayloadBytes)}`,
    })),
  );
}

function nestedPayload(wrappers: number): JsonObject {
  let value: JsonObject = { value: "leaf" };
  for (let index = 0; index < wrappers; index += 1) value = { nested: value };
  return value;
}

function requireDefined<T>(value: T | undefined, message: string): T {
  if (value === undefined) throw new Error(message);
  return value;
}
