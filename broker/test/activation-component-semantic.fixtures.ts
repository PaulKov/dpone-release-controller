import { canonicalBytes, sha256Hex } from "../src/canonical";
import type {
  ActivationComponentKind,
  ActivationComponentPayloadInput,
  PreparedActivationComponentEnvelope,
} from "../src/activation-component-contract";
import { buildActivationComponentSetDescriptor } from "../src/activation-component-descriptor";
import { buildActivationComponentEnvelope } from "../src/activation-component-envelope";
import type { ActivationComponentSetSemanticInput } from "../src/activation-component-journal-contract";
import type { JsonObject } from "../src/types";
import {
  productionValidA0Fixture,
  type ProductionValidA0Fixture,
} from "./activation-component-payload.fixtures";

export interface ProductionValidComponentSetFixture {
  readonly input: ActivationComponentSetSemanticInput;
  readonly source: ProductionValidA0Fixture;
}

/** Build the exact descriptor/envelope roster from the production-valid staged A0 fixture. */
export async function productionValidComponentSetFixture(): Promise<ProductionValidComponentSetFixture> {
  const source = await productionValidA0Fixture();
  return componentSetFixture(source, source.componentPayloads);
}

/** Rebuild the complete exact roster after changing one confidential component payload. */
export async function mutatedComponentSetFixture(
  componentKind: ActivationComponentKind,
  mutate: (document: JsonObject) => void,
  source?: ProductionValidA0Fixture,
): Promise<ProductionValidComponentSetFixture> {
  const ownedSource = source ?? (await productionValidA0Fixture());
  const payloads = ownedSource.componentPayloads.map((payload) => {
    if (payload.componentKind !== componentKind) return snapshotPayload(payload);
    const document = decodePayload(payload.canonicalPayloadBytes);
    mutate(document);
    return { canonicalPayloadBytes: canonicalBytes(document), componentKind };
  });
  return componentSetFixture(ownedSource, payloads);
}

export function decodePayload(bytes: Uint8Array): JsonObject {
  const value = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("activation component fixture payload is not an object");
  }
  return value as JsonObject;
}

async function componentSetFixture(
  source: ProductionValidA0Fixture,
  payloads: readonly ActivationComponentPayloadInput[],
): Promise<ProductionValidComponentSetFixture> {
  const descriptor = await buildActivationComponentSetDescriptor({
    committedAt: source.request.observedAt,
    components: await Promise.all(
      payloads.map(async ({ canonicalPayloadBytes, componentKind }) => ({
        componentKind,
        payloadSha256: `sha256:${await sha256Hex(canonicalPayloadBytes)}`,
      })),
    ),
    workerVersionId: source.config.workerVersionId,
  });
  const envelopes: readonly PreparedActivationComponentEnvelope[] = await Promise.all(
    payloads.map(({ canonicalPayloadBytes, componentKind }) =>
      buildActivationComponentEnvelope(
        descriptor.canonicalBytes,
        componentKind,
        canonicalPayloadBytes,
      ),
    ),
  );
  return {
    input: Object.freeze({ descriptor, envelopes: Object.freeze(envelopes) }),
    source,
  };
}

function snapshotPayload(input: ActivationComponentPayloadInput): ActivationComponentPayloadInput {
  return {
    canonicalPayloadBytes: Uint8Array.from(input.canonicalPayloadBytes),
    componentKind: input.componentKind,
  };
}
