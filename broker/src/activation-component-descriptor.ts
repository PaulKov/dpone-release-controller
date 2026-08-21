import { canonicalBytes, sha256Hex } from "./canonical";
import {
  activationLiteral,
  activationString,
  activationTimestamp,
  ACTIVATION_COMPONENT_DIGEST,
  ACTIVATION_COMPONENT_WORKER_VERSION,
  componentError,
  decodeBoundedActivationObject,
  exactActivationObject,
} from "./activation-component-codec";
import {
  ACTIVATION_COMPONENT_DESCRIPTOR_SCHEMA,
  ACTIVATION_COMPONENT_KINDS,
  ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
  ACTIVATION_COMPONENT_MANIFEST_MAX_NODES,
  ACTIVATION_COMPONENT_MAX_DEPTH,
  ACTIVATION_COMPONENT_MAX_STRING_BYTES,
  ACTIVATION_COMPONENT_PROFILE,
  ACTIVATION_COMPONENT_SEQUENCE,
  type ActivationComponentDescriptor,
  type ActivationComponentDigestInput,
  type ActivationComponentKind,
} from "./activation-component-contract";
import { digestDomain } from "./identity";
import type { JsonObject } from "./types";

const DESCRIPTOR_FIELDS = [
  "activation_sequence",
  "component_profile",
  "component_set_committed_at",
  "component_set_id",
  "components",
  "descriptor_id",
  "schema",
  "schema_version",
  "worker_version_id",
] as const;
const ENTRY_FIELDS = ["component_kind", "payload_sha256"] as const;
const DESCRIPTOR_INVALID = "ACTIVATION_COMPONENT_DESCRIPTOR_INVALID";

export interface ActivationComponentDescriptorInput {
  readonly committedAt: string;
  readonly components: readonly ActivationComponentDigestInput[];
  readonly workerVersionId: string;
}

/** Build the small descriptor that must be persisted before any component effect. */
export async function buildActivationComponentSetDescriptor(
  input: ActivationComponentDescriptorInput,
): Promise<ActivationComponentDescriptor> {
  const committedAt = activationTimestamp(input.committedAt, DESCRIPTOR_INVALID);
  if (!ACTIVATION_COMPONENT_WORKER_VERSION.test(input.workerVersionId)) {
    throw componentError(DESCRIPTOR_INVALID);
  }
  const workerVersionId = input.workerVersionId;
  const components = orderedDigestRoster(input.components);
  const identity: JsonObject = {
    activation_sequence: ACTIVATION_COMPONENT_SEQUENCE,
    component_profile: ACTIVATION_COMPONENT_PROFILE,
    components: rosterJson(components),
    worker_version_id: workerVersionId,
  };
  const setId = await digestDomain("dpone.activation-component-set.v2", identity);
  const core: JsonObject = {
    activation_sequence: ACTIVATION_COMPONENT_SEQUENCE,
    component_profile: ACTIVATION_COMPONENT_PROFILE,
    component_set_committed_at: committedAt,
    component_set_id: setId,
    components: rosterJson(components),
    schema: ACTIVATION_COMPONENT_DESCRIPTOR_SCHEMA,
    schema_version: 2,
    worker_version_id: workerVersionId,
  };
  const descriptorId = await digestDomain("dpone.activation-component-set-descriptor.v2", core);
  const canonical = canonicalBytes({ ...core, descriptor_id: descriptorId });
  if (canonical.byteLength > ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES || canonical.byteLength < 1) {
    throw componentError(DESCRIPTOR_INVALID, 413);
  }
  return freezeDescriptor({
    canonicalBytes: canonical,
    committedAt,
    components,
    descriptorId,
    descriptorSha256: `sha256:${await sha256Hex(canonical)}`,
    setId,
    trust: "UNTRUSTED",
    workerVersionId,
  });
}

/** Parse structural identity only. Payload semantics remain explicitly untrusted. */
export async function parseActivationComponentSetDescriptor(
  input: Uint8Array,
): Promise<ActivationComponentDescriptor> {
  const decoded = decodeBoundedActivationObject(
    input,
    {
      bytes: ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
      depth: ACTIVATION_COMPONENT_MAX_DEPTH,
      maxStringBytes: ACTIVATION_COMPONENT_MAX_STRING_BYTES,
      nodes: ACTIVATION_COMPONENT_MANIFEST_MAX_NODES,
    },
    DESCRIPTOR_INVALID,
  );
  const document = exactActivationObject(decoded.value, DESCRIPTOR_FIELDS, DESCRIPTOR_INVALID);
  activationLiteral(document, "schema", ACTIVATION_COMPONENT_DESCRIPTOR_SCHEMA, DESCRIPTOR_INVALID);
  activationLiteral(document, "schema_version", 2, DESCRIPTOR_INVALID);
  activationLiteral(
    document,
    "activation_sequence",
    ACTIVATION_COMPONENT_SEQUENCE,
    DESCRIPTOR_INVALID,
  );
  activationLiteral(
    document,
    "component_profile",
    ACTIVATION_COMPONENT_PROFILE,
    DESCRIPTOR_INVALID,
  );
  const entries = document.components;
  if (!Array.isArray(entries) || entries.length !== ACTIVATION_COMPONENT_KINDS.length) {
    throw componentError(DESCRIPTOR_INVALID);
  }
  const components = entries.map((candidate, index) => {
    const entry = exactActivationObject(candidate, ENTRY_FIELDS, DESCRIPTOR_INVALID);
    const expectedKind = ACTIVATION_COMPONENT_KINDS[index];
    if (expectedKind === undefined || entry.component_kind !== expectedKind) {
      throw componentError(DESCRIPTOR_INVALID);
    }
    return {
      componentKind: expectedKind,
      payloadSha256: activationString(
        entry,
        "payload_sha256",
        ACTIVATION_COMPONENT_DIGEST,
        DESCRIPTOR_INVALID,
      ),
    };
  });
  const rebuilt = await buildActivationComponentSetDescriptor({
    committedAt: activationString(
      document,
      "component_set_committed_at",
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u,
      DESCRIPTOR_INVALID,
    ),
    components,
    workerVersionId: activationString(
      document,
      "worker_version_id",
      ACTIVATION_COMPONENT_WORKER_VERSION,
      DESCRIPTOR_INVALID,
    ),
  });
  if (!sameBytes(rebuilt.canonicalBytes, decoded.bytes)) throw componentError(DESCRIPTOR_INVALID);
  return rebuilt;
}

export function descriptorPayloadDigest(
  descriptor: ActivationComponentDescriptor,
  componentKind: ActivationComponentKind,
): string {
  const entry = descriptor.components.find(
    (candidate) => candidate.componentKind === componentKind,
  );
  if (entry === undefined) throw componentError(DESCRIPTOR_INVALID, 500);
  return entry.payloadSha256;
}

function orderedDigestRoster(
  input: readonly ActivationComponentDigestInput[],
): readonly ActivationComponentDigestInput[] {
  if (input.length !== ACTIVATION_COMPONENT_KINDS.length) throw componentError(DESCRIPTOR_INVALID);
  const byKind = new Map<ActivationComponentKind, string>();
  for (const candidate of input) {
    if (
      !ACTIVATION_COMPONENT_KINDS.includes(candidate.componentKind) ||
      !ACTIVATION_COMPONENT_DIGEST.test(candidate.payloadSha256) ||
      byKind.has(candidate.componentKind)
    ) {
      throw componentError(DESCRIPTOR_INVALID);
    }
    byKind.set(candidate.componentKind, candidate.payloadSha256);
  }
  return Object.freeze(
    ACTIVATION_COMPONENT_KINDS.map((componentKind) => {
      const payloadSha256 = byKind.get(componentKind);
      if (payloadSha256 === undefined) throw componentError(DESCRIPTOR_INVALID);
      return Object.freeze({ componentKind, payloadSha256 });
    }),
  );
}

function rosterJson(components: readonly ActivationComponentDigestInput[]): JsonObject[] {
  return components.map(({ componentKind, payloadSha256 }) => ({
    component_kind: componentKind,
    payload_sha256: payloadSha256,
  }));
}

function freezeDescriptor(value: ActivationComponentDescriptor): ActivationComponentDescriptor {
  return Object.freeze({
    ...value,
    canonicalBytes: Uint8Array.from(value.canonicalBytes),
    components: Object.freeze(value.components.map((entry) => Object.freeze({ ...entry }))),
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
