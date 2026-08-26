import { canonicalBytes, sha256Hex } from "./canonical";
import {
  activationJsonBudget,
  activationLiteral,
  ACTIVATION_COMPONENT_DIGEST,
  ACTIVATION_COMPONENT_WORKER_VERSION,
  componentError,
  decodeBoundedActivationObject,
  exactActivationObject,
} from "./activation-component-codec";
import {
  ACTIVATION_COMPONENT_ENVELOPE_MAX_BYTES,
  ACTIVATION_COMPONENT_ENVELOPE_MAX_NODES,
  ACTIVATION_COMPONENT_ENVELOPE_SCHEMA,
  ACTIVATION_COMPONENT_KINDS,
  ACTIVATION_COMPONENT_MAX_DEPTH,
  ACTIVATION_COMPONENT_MAX_STRING_BYTES,
  ACTIVATION_COMPONENT_PAYLOAD_MAX_BYTES,
  ACTIVATION_COMPONENT_PAYLOAD_MAX_NODES,
  ACTIVATION_COMPONENT_PROFILE,
  ACTIVATION_COMPONENT_SEQUENCE,
  type ActivationComponentKind,
  type PreparedActivationComponentEnvelope,
} from "./activation-component-contract";
import {
  descriptorPayloadDigest,
  parseActivationComponentSetDescriptor,
} from "./activation-component-descriptor";
import { digestDomain } from "./identity";
import { ownExactUint8Array } from "./exact-uint8array";
import type { JsonObject } from "./types";

const ENVELOPE_FIELDS = [
  "activation_sequence",
  "component_id",
  "component_kind",
  "component_profile",
  "component_set_descriptor_id",
  "component_set_descriptor_sha256",
  "component_set_id",
  "payload",
  "payload_sha256",
  "schema",
  "schema_version",
  "worker_version_id",
] as const;
const ENVELOPE_INVALID = "ACTIVATION_COMPONENT_ENVELOPE_INVALID";

/** Build one self-describing component only after its exact descriptor is frozen. */
export async function buildActivationComponentEnvelope(
  descriptorBytes: Uint8Array,
  componentKind: ActivationComponentKind,
  canonicalPayloadBytes: Uint8Array,
): Promise<PreparedActivationComponentEnvelope> {
  if (!ACTIVATION_COMPONENT_KINDS.includes(componentKind)) {
    throw componentError(ENVELOPE_INVALID);
  }
  const descriptorSnapshot = envelopeBytes(
    descriptorBytes,
    ACTIVATION_COMPONENT_ENVELOPE_MAX_BYTES,
  );
  const payload = decodeBoundedActivationObject(
    canonicalPayloadBytes,
    {
      bytes: ACTIVATION_COMPONENT_PAYLOAD_MAX_BYTES,
      depth: ACTIVATION_COMPONENT_MAX_DEPTH - 2,
      maxStringBytes: ACTIVATION_COMPONENT_MAX_STRING_BYTES,
      nodes: ACTIVATION_COMPONENT_PAYLOAD_MAX_NODES,
    },
    ENVELOPE_INVALID,
  );
  const descriptor = await parseActivationComponentSetDescriptor(descriptorSnapshot);
  const payloadSha256 = `sha256:${await sha256Hex(payload.bytes)}`;
  if (payloadSha256 !== descriptorPayloadDigest(descriptor, componentKind)) {
    throw componentError("ACTIVATION_COMPONENT_PAYLOAD_CONFLICT");
  }
  const componentId = await activationComponentId(
    descriptor.workerVersionId,
    descriptor.setId,
    descriptor.descriptorId,
    descriptor.descriptorSha256,
    componentKind,
    payloadSha256,
  );
  const document: JsonObject = {
    activation_sequence: ACTIVATION_COMPONENT_SEQUENCE,
    component_id: componentId,
    component_kind: componentKind,
    component_profile: ACTIVATION_COMPONENT_PROFILE,
    component_set_descriptor_id: descriptor.descriptorId,
    component_set_descriptor_sha256: descriptor.descriptorSha256,
    component_set_id: descriptor.setId,
    payload: payload.value,
    payload_sha256: payloadSha256,
    schema: ACTIVATION_COMPONENT_ENVELOPE_SCHEMA,
    schema_version: 2,
    worker_version_id: descriptor.workerVersionId,
  };
  const canonical = canonicalBytes(document);
  const budget = activationJsonBudget(document);
  if (
    canonical.byteLength > ACTIVATION_COMPONENT_ENVELOPE_MAX_BYTES ||
    budget.depth > ACTIVATION_COMPONENT_MAX_DEPTH ||
    budget.maxStringBytes > ACTIVATION_COMPONENT_MAX_STRING_BYTES ||
    budget.nodes > ACTIVATION_COMPONENT_ENVELOPE_MAX_NODES
  ) {
    throw componentError(ENVELOPE_INVALID, 413);
  }
  const envelopeSha256 = `sha256:${await sha256Hex(canonical)}`;
  return Object.freeze({
    canonicalBytes: Uint8Array.from(canonical),
    componentId,
    componentKind,
    envelopeSha256,
    key: activationComponentWormKey(
      descriptor.workerVersionId,
      descriptor.setId,
      descriptor.descriptorId,
      descriptor.descriptorSha256,
      componentKind,
      componentId,
    ),
    payloadSha256,
    trust: "UNTRUSTED" as const,
  });
}

/** Recompute every generic binding; the kind-specific payload is still untrusted. */
export async function parseActivationComponentEnvelope(
  canonicalEnvelopeBytes: Uint8Array,
  descriptorBytes: Uint8Array,
): Promise<PreparedActivationComponentEnvelope> {
  const envelopeSnapshot = envelopeBytes(
    canonicalEnvelopeBytes,
    ACTIVATION_COMPONENT_ENVELOPE_MAX_BYTES,
  );
  const descriptorSnapshot = envelopeBytes(
    descriptorBytes,
    ACTIVATION_COMPONENT_ENVELOPE_MAX_BYTES,
  );
  const decoded = decodeBoundedActivationObject(
    envelopeSnapshot,
    {
      bytes: ACTIVATION_COMPONENT_ENVELOPE_MAX_BYTES,
      depth: ACTIVATION_COMPONENT_MAX_DEPTH,
      maxStringBytes: ACTIVATION_COMPONENT_MAX_STRING_BYTES,
      nodes: ACTIVATION_COMPONENT_ENVELOPE_MAX_NODES,
    },
    ENVELOPE_INVALID,
  );
  const document = exactActivationObject(decoded.value, ENVELOPE_FIELDS, ENVELOPE_INVALID);
  activationLiteral(document, "schema", ACTIVATION_COMPONENT_ENVELOPE_SCHEMA, ENVELOPE_INVALID);
  activationLiteral(document, "schema_version", 2, ENVELOPE_INVALID);
  activationLiteral(
    document,
    "activation_sequence",
    ACTIVATION_COMPONENT_SEQUENCE,
    ENVELOPE_INVALID,
  );
  activationLiteral(document, "component_profile", ACTIVATION_COMPONENT_PROFILE, ENVELOPE_INVALID);
  const componentKind = document.component_kind;
  if (
    typeof componentKind !== "string" ||
    !ACTIVATION_COMPONENT_KINDS.includes(componentKind as ActivationComponentKind)
  ) {
    throw componentError(ENVELOPE_INVALID);
  }
  const payload = document.payload;
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    throw componentError(ENVELOPE_INVALID);
  }
  const rebuilt = await buildActivationComponentEnvelope(
    descriptorSnapshot,
    componentKind as ActivationComponentKind,
    canonicalBytes(payload),
  );
  if (!sameBytes(rebuilt.canonicalBytes, decoded.bytes)) throw componentError(ENVELOPE_INVALID);
  return rebuilt;
}

export function activationComponentWormKey(
  workerVersionId: string,
  setId: string,
  descriptorId: string,
  descriptorSha256: string,
  componentKind: ActivationComponentKind,
  componentId: string,
): string {
  if (
    !ACTIVATION_COMPONENT_WORKER_VERSION.test(workerVersionId) ||
    ![setId, descriptorId, descriptorSha256, componentId].every((value) =>
      ACTIVATION_COMPONENT_DIGEST.test(value),
    ) ||
    !ACTIVATION_COMPONENT_KINDS.includes(componentKind)
  ) {
    throw componentError(ENVELOPE_INVALID);
  }
  return [
    "receipts",
    "v2",
    "activation-components",
    workerVersionId,
    setId.slice("sha256:".length),
    descriptorId.slice("sha256:".length),
    descriptorSha256.slice("sha256:".length),
    componentKind,
    `${componentId.slice("sha256:".length)}.json`,
  ].join("/");
}

export function activationComponentId(
  workerVersionId: string,
  setId: string,
  descriptorId: string,
  descriptorSha256: string,
  componentKind: ActivationComponentKind,
  payloadSha256: string,
): Promise<string> {
  return digestDomain("dpone.activation-component.v2", {
    activation_sequence: ACTIVATION_COMPONENT_SEQUENCE,
    component_kind: componentKind,
    component_profile: ACTIVATION_COMPONENT_PROFILE,
    component_set_descriptor_id: descriptorId,
    component_set_descriptor_sha256: descriptorSha256,
    component_set_id: setId,
    payload_sha256: payloadSha256,
    worker_version_id: workerVersionId,
  });
}

function envelopeBytes(input: unknown, maximum: number): Uint8Array {
  return ownExactUint8Array(input, {
    code: ENVELOPE_INVALID,
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
