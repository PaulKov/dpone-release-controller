import { APP_PERMISSIONS, PROJECTS } from "./activation-contract";
import {
  decodeBoundedActivationObject,
  exactActivationObject,
  componentError,
} from "./activation-component-codec";
import {
  ACTIVATION_COMPONENT_ENVELOPE_MAX_BYTES,
  ACTIVATION_COMPONENT_ENVELOPE_MAX_NODES,
  ACTIVATION_COMPONENT_KINDS,
  ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
  ACTIVATION_COMPONENT_MAX_DEPTH,
  ACTIVATION_COMPONENT_MAX_STRING_BYTES,
  type ActivationComponentKind,
} from "./activation-component-contract";
import type { ActivationComponentSetSemanticInput } from "./activation-component-journal-contract";
import type {
  ActivationComponentPayloadMap,
  ParsedActivationComponentPayloadSet,
} from "./activation-component-payload-contract";
import {
  ADMIN_ACCESS_FIELDS,
  AUTHORITY_HEADER_FIELDS,
  AUTHORITY_INVENTORY_ROW_FIELDS,
  AUTHORITY_NETWORK_FIELDS,
  B2_FIELDS,
  BOOTSTRAP_DEPLOYMENT_MEMBER_FIELDS,
  BROKER_CORE_FIELDS,
  CONTROLLER_FIELDS,
  CONTROLLER_GOVERNANCE_FIELDS,
  FINAL_DEPLOYMENT_MEMBER_FIELDS,
  NORMALIZED_DEPLOYMENT_ROW_FIELDS,
  NORMALIZED_GITHUB_APP_FIELDS,
  OIDC_FIELDS,
  TARGET_GOVERNANCE_FIELDS,
} from "./activation-component-payload-fields";
import { parseActivationComponentSetDescriptor } from "./activation-component-descriptor";
import { parseActivationComponentEnvelope } from "./activation-component-envelope";
import { ownExactUint8Array } from "./exact-uint8array";
import { RECEIPT_ROLE_BINDINGS } from "./service-authority-expectation";
import { SERVICE_AUTHORITY_ROLES } from "./service-authority";
import type { JsonObject, JsonValue } from "./types";

const PAYLOAD_INVALID = "ACTIVATION_COMPONENT_PAYLOAD_INVALID";
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

/** Reparse the complete exact roster and return only owned, recursively frozen payloads. */
export async function parseActivationComponentPayloadSet(
  input: ActivationComponentSetSemanticInput,
): Promise<ParsedActivationComponentPayloadSet> {
  const descriptorBytes = payloadBytes(
    input.descriptor.canonicalBytes,
    ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
  );
  if (input.envelopes.length !== ACTIVATION_COMPONENT_KINDS.length) {
    throw componentError(PAYLOAD_INVALID);
  }
  const envelopeBytes = input.envelopes.map((envelope) =>
    payloadBytes(envelope.canonicalBytes, ACTIVATION_COMPONENT_ENVELOPE_MAX_BYTES),
  );
  const descriptor = await parseActivationComponentSetDescriptor(descriptorBytes);
  const payloads: Partial<Record<ActivationComponentKind, JsonObject>> = {};
  for (let ordinal = 0; ordinal < ACTIVATION_COMPONENT_KINDS.length; ordinal += 1) {
    const componentKind = ACTIVATION_COMPONENT_KINDS[ordinal];
    const bytes = envelopeBytes[ordinal];
    if (componentKind === undefined || bytes === undefined) throw componentError(PAYLOAD_INVALID);
    const envelope = await parseActivationComponentEnvelope(bytes, descriptor.canonicalBytes);
    if (envelope.componentKind !== componentKind) throw componentError(PAYLOAD_INVALID);
    const decoded = decodeBoundedActivationObject(
      bytes,
      {
        bytes: ACTIVATION_COMPONENT_ENVELOPE_MAX_BYTES,
        depth: ACTIVATION_COMPONENT_MAX_DEPTH,
        maxStringBytes: ACTIVATION_COMPONENT_MAX_STRING_BYTES,
        nodes: ACTIVATION_COMPONENT_ENVELOPE_MAX_NODES,
      },
      PAYLOAD_INVALID,
    );
    const document = exactActivationObject(decoded.value, ENVELOPE_FIELDS, PAYLOAD_INVALID);
    payloads[componentKind] = freezeJson(parsePayload(componentKind, document.payload));
  }
  return Object.freeze({
    descriptor,
    payloads: Object.freeze(payloads) as ActivationComponentPayloadMap,
    trust: "UNTRUSTED" as const,
  });
}

function parsePayload(componentKind: ActivationComponentKind, value: unknown): JsonObject {
  switch (componentKind) {
    case "admin_access":
      return exactActivationObject(value, ADMIN_ACCESS_FIELDS, PAYLOAD_INVALID);
    case "b2":
      return exactActivationObject(value, B2_FIELDS, PAYLOAD_INVALID);
    case "broker_core":
      return exactActivationObject(value, BROKER_CORE_FIELDS, PAYLOAD_INVALID);
    case "controller":
      return exactActivationObject(value, CONTROLLER_FIELDS, PAYLOAD_INVALID);
    case "controller_governance":
      return exactActivationObject(value, CONTROLLER_GOVERNANCE_FIELDS, PAYLOAD_INVALID);
    case "github_apps":
      return parseApps(value);
    case "oidc":
      return exactActivationObject(value, OIDC_FIELDS, PAYLOAD_INVALID);
    case "service_authority_header":
      return exactActivationObject(value, AUTHORITY_HEADER_FIELDS, PAYLOAD_INVALID);
    case "service_authority_inventory":
      return parseInventory(value);
    case "service_authority_a0_deployments":
    case "service_authority_a1_deployments":
      return parseDeployments(value);
    case "service_authority_network":
      return exactActivationObject(value, AUTHORITY_NETWORK_FIELDS, PAYLOAD_INVALID);
    case "service_authority_receipt_bindings":
      return parseReceiptBindings(value);
    case "target_governance":
      return exactActivationObject(value, TARGET_GOVERNANCE_FIELDS, PAYLOAD_INVALID);
    case "trusted_publishers":
      return parseTrustedPublishers(value);
  }
}

function parseApps(value: unknown): JsonObject {
  const apps = exactActivationObject(value, Object.keys(APP_PERMISSIONS), PAYLOAD_INVALID);
  for (const role of Object.keys(APP_PERMISSIONS)) {
    exactActivationObject(apps[role], NORMALIZED_GITHUB_APP_FIELDS, PAYLOAD_INVALID);
  }
  return apps;
}

function parseInventory(value: unknown): JsonObject {
  const wrapper = exactActivationObject(value, ["authorities"], PAYLOAD_INVALID);
  const rows = exactArray(wrapper.authorities, SERVICE_AUTHORITY_ROLES.length);
  rows.forEach((row) =>
    exactActivationObject(row, AUTHORITY_INVENTORY_ROW_FIELDS, PAYLOAD_INVALID),
  );
  return wrapper;
}

function parseDeployments(value: unknown): JsonObject {
  const wrapper = exactActivationObject(value, ["deployments"], PAYLOAD_INVALID);
  const rows = exactArray(wrapper.deployments, SERVICE_AUTHORITY_ROLES.length);
  rows.forEach((candidate) => {
    const row = exactActivationObject(candidate, NORMALIZED_DEPLOYMENT_ROW_FIELDS, PAYLOAD_INVALID);
    if (
      !Array.isArray(row.deployment_versions) ||
      row.deployment_versions.length < 1 ||
      row.deployment_versions.length > 2
    ) {
      throw componentError(PAYLOAD_INVALID);
    }
    row.deployment_versions.forEach((member) => {
      if (member === null || typeof member !== "object" || Array.isArray(member)) {
        throw componentError(PAYLOAD_INVALID);
      }
      const artifactKind = member.artifact_kind;
      exactActivationObject(
        member,
        artifactKind === "FINAL_AUTHORITY"
          ? FINAL_DEPLOYMENT_MEMBER_FIELDS
          : artifactKind === "BOOTSTRAP_DENY"
            ? BOOTSTRAP_DEPLOYMENT_MEMBER_FIELDS
            : [],
        PAYLOAD_INVALID,
      );
    });
  });
  return wrapper;
}

function parseReceiptBindings(value: unknown): JsonObject {
  const wrapper = exactActivationObject(value, ["receipt_role_bindings"], PAYLOAD_INVALID);
  const rows = exactArray(wrapper.receipt_role_bindings, RECEIPT_ROLE_BINDINGS.length);
  rows.forEach((row) =>
    exactActivationObject(row, ["service_authority_role", "service_role"], PAYLOAD_INVALID),
  );
  return wrapper;
}

function parseTrustedPublishers(value: unknown): JsonObject {
  const wrapper = exactActivationObject(value, ["publishers"], PAYLOAD_INVALID);
  const publishers = exactArray(wrapper.publishers, PROJECTS.length);
  publishers.forEach((publisher) =>
    exactActivationObject(
      publisher,
      [
        "environment",
        "evidence_receipt_id",
        "evidence_sha256",
        "project",
        "repository",
        "workflow_path",
      ],
      PAYLOAD_INVALID,
    ),
  );
  return wrapper;
}

function exactArray(value: JsonValue | undefined, length: number): JsonValue[] {
  if (!Array.isArray(value) || value.length !== length) throw componentError(PAYLOAD_INVALID);
  return value;
}

function payloadBytes(input: unknown, maximum: number): Uint8Array {
  return ownExactUint8Array(input, {
    code: PAYLOAD_INVALID,
    invalidStatus: 409,
    maximum,
    minimum: 1,
    sizeStatus: 413,
  });
}

function freezeJson<T extends JsonValue>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const child of Array.isArray(value) ? value : Object.values(value)) freezeJson(child);
    Object.freeze(value);
  }
  return value;
}
