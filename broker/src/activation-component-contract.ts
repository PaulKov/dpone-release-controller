import type { ActivationWorm, JsonObject } from "./types";

export const ACTIVATION_COMPONENT_PROFILE = "A0_INPUT_V1" as const;
export const ACTIVATION_COMPONENT_SEQUENCE = 0 as const;
export const ACTIVATION_COMPONENT_DESCRIPTOR_SCHEMA =
  "dpone.release-activation-component-set-descriptor.v2";
export const ACTIVATION_COMPONENT_ENVELOPE_SCHEMA = "dpone.release-activation-component.v2";
export const ACTIVATION_COMPONENT_MANIFEST_SCHEMA =
  "dpone.release-activation-component-manifest.v2";

export const ACTIVATION_COMPONENT_PAYLOAD_MAX_BYTES = 60_000;
export const ACTIVATION_COMPONENT_PAYLOAD_MAX_NODES = 384;
export const ACTIVATION_COMPONENT_ENVELOPE_MAX_BYTES = 65_536;
export const ACTIVATION_COMPONENT_ENVELOPE_MAX_NODES = 399;
export const ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES = 65_536;
export const ACTIVATION_COMPONENT_MANIFEST_MAX_NODES = 512;
export const ACTIVATION_COMPONENT_MAX_DEPTH = 16;
export const ACTIVATION_COMPONENT_MAX_STRING_BYTES = 32_768;

/** Closed A0 input roster. Array-valued inputs live inside kind-specific object payloads. */
export const ACTIVATION_COMPONENT_KINDS = Object.freeze([
  "admin_access",
  "b2",
  "broker_core",
  "controller",
  "controller_governance",
  "github_apps",
  "oidc",
  "service_authority_header",
  "service_authority_inventory",
  "service_authority_a0_deployments",
  "service_authority_a1_deployments",
  "service_authority_network",
  "service_authority_receipt_bindings",
  "target_governance",
  "trusted_publishers",
] as const);

export type ActivationComponentKind = (typeof ACTIVATION_COMPONENT_KINDS)[number];

export interface ActivationComponentDigestInput {
  readonly componentKind: ActivationComponentKind;
  readonly payloadSha256: string;
}

export interface ActivationComponentPayloadInput {
  readonly canonicalPayloadBytes: Uint8Array;
  readonly componentKind: ActivationComponentKind;
}

export interface ActivationComponentDescriptor {
  readonly canonicalBytes: Uint8Array;
  readonly committedAt: string;
  readonly components: readonly ActivationComponentDigestInput[];
  readonly descriptorId: string;
  readonly descriptorSha256: string;
  readonly setId: string;
  readonly trust: "UNTRUSTED";
  readonly workerVersionId: string;
}

export interface PreparedActivationComponentEnvelope {
  readonly canonicalBytes: Uint8Array;
  readonly componentId: string;
  readonly componentKind: ActivationComponentKind;
  readonly envelopeSha256: string;
  readonly key: string;
  readonly payloadSha256: string;
  readonly trust: "UNTRUSTED";
}

export interface ActivationComponentManifestEntry {
  readonly componentId: string;
  readonly componentKind: ActivationComponentKind;
  readonly envelopeSha256: string;
  readonly payloadSha256: string;
  readonly worm: ActivationWorm;
}

export interface PreparedActivationComponentManifest {
  readonly canonicalBytes: Uint8Array;
  readonly committedAt: string;
  readonly components: readonly ActivationComponentManifestEntry[];
  readonly descriptorId: string;
  readonly descriptorSha256: string;
  readonly key: string;
  readonly manifestId: string;
  readonly manifestSha256: string;
  readonly setId: string;
  readonly trust: "UNTRUSTED";
  readonly workerVersionId: string;
}

export interface PreparedActivationComponentManifestPointer {
  readonly canonicalBytes: Uint8Array;
  readonly document: JsonObject;
  readonly manifestId: string;
  readonly manifestSha256: string;
  readonly setId: string;
  readonly trust: "UNTRUSTED";
  readonly workerVersionId: string;
  readonly worm: ActivationWorm;
}
