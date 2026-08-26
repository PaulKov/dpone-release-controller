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
  ACTIVATION_COMPONENT_KINDS,
  ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
  ACTIVATION_COMPONENT_MANIFEST_MAX_NODES,
  ACTIVATION_COMPONENT_MANIFEST_SCHEMA,
  ACTIVATION_COMPONENT_MAX_DEPTH,
  ACTIVATION_COMPONENT_MAX_STRING_BYTES,
  ACTIVATION_COMPONENT_PROFILE,
  ACTIVATION_COMPONENT_SEQUENCE,
  type ActivationComponentManifestEntry,
  type PreparedActivationComponentManifest,
} from "./activation-component-contract";
import { buildActivationComponentSetDescriptor } from "./activation-component-descriptor";
import { activationComponentId, activationComponentWormKey } from "./activation-component-envelope";
import { digestDomain } from "./identity";
import type { JsonObject } from "./types";
import {
  activationComponentManifestWormKey,
  activationComponentWormJson,
  assertUniqueActivationComponentWorms,
  copyActivationComponentWorm,
  parseActivationComponentWorm,
} from "./activation-component-manifest-worm";

const MANIFEST_FIELDS = [
  "activation_sequence",
  "component_profile",
  "component_set_committed_at",
  "component_set_descriptor_id",
  "component_set_descriptor_sha256",
  "component_set_id",
  "components",
  "manifest_id",
  "schema",
  "schema_version",
  "worker_version_id",
] as const;
const ENTRY_FIELDS = [
  "component_id",
  "component_kind",
  "envelope_sha256",
  "payload_sha256",
  "worm",
] as const;
const MANIFEST_INVALID = "ACTIVATION_COMPONENT_MANIFEST_INVALID";

/** Parse generic integrity only; callers must resolve and kind-parse all components. */
export async function parseActivationComponentManifest(
  canonicalManifestBytes: Uint8Array,
): Promise<PreparedActivationComponentManifest> {
  const decoded = decodeBoundedActivationObject(
    canonicalManifestBytes,
    {
      bytes: ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
      depth: ACTIVATION_COMPONENT_MAX_DEPTH,
      maxStringBytes: ACTIVATION_COMPONENT_MAX_STRING_BYTES,
      nodes: ACTIVATION_COMPONENT_MANIFEST_MAX_NODES,
    },
    MANIFEST_INVALID,
  );
  const document = exactActivationObject(decoded.value, MANIFEST_FIELDS, MANIFEST_INVALID);
  activationLiteral(document, "schema", ACTIVATION_COMPONENT_MANIFEST_SCHEMA, MANIFEST_INVALID);
  activationLiteral(document, "schema_version", 2, MANIFEST_INVALID);
  activationLiteral(
    document,
    "activation_sequence",
    ACTIVATION_COMPONENT_SEQUENCE,
    MANIFEST_INVALID,
  );
  activationLiteral(document, "component_profile", ACTIVATION_COMPONENT_PROFILE, MANIFEST_INVALID);
  const workerVersionId = activationString(
    document,
    "worker_version_id",
    ACTIVATION_COMPONENT_WORKER_VERSION,
    MANIFEST_INVALID,
  );
  const committedAt = activationTimestamp(
    activationString(
      document,
      "component_set_committed_at",
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u,
      MANIFEST_INVALID,
    ),
    MANIFEST_INVALID,
  );
  const entries = document.components;
  if (!Array.isArray(entries) || entries.length !== ACTIVATION_COMPONENT_KINDS.length) {
    throw componentError(MANIFEST_INVALID);
  }
  const parsedEntries: ActivationComponentManifestEntry[] = [];
  for (let index = 0; index < entries.length; index += 1) {
    const expectedKind = ACTIVATION_COMPONENT_KINDS[index];
    if (expectedKind === undefined) throw componentError(MANIFEST_INVALID);
    const entry = exactActivationObject(entries[index], ENTRY_FIELDS, MANIFEST_INVALID);
    if (entry.component_kind !== expectedKind) throw componentError(MANIFEST_INVALID);
    parsedEntries.push({
      componentId: activationString(
        entry,
        "component_id",
        ACTIVATION_COMPONENT_DIGEST,
        MANIFEST_INVALID,
      ),
      componentKind: expectedKind,
      envelopeSha256: activationString(
        entry,
        "envelope_sha256",
        ACTIVATION_COMPONENT_DIGEST,
        MANIFEST_INVALID,
      ),
      payloadSha256: activationString(
        entry,
        "payload_sha256",
        ACTIVATION_COMPONENT_DIGEST,
        MANIFEST_INVALID,
      ),
      worm: parseActivationComponentWorm(entry.worm, committedAt),
    });
  }
  const descriptor = await buildActivationComponentSetDescriptor({
    committedAt,
    components: parsedEntries.map(({ componentKind, payloadSha256 }) => ({
      componentKind,
      payloadSha256,
    })),
    workerVersionId,
  });
  if (
    document.component_set_id !== descriptor.setId ||
    document.component_set_descriptor_id !== descriptor.descriptorId ||
    document.component_set_descriptor_sha256 !== descriptor.descriptorSha256
  ) {
    throw componentError(MANIFEST_INVALID);
  }
  for (const entry of parsedEntries) {
    if (
      entry.componentId !==
        (await activationComponentId(
          workerVersionId,
          descriptor.setId,
          descriptor.descriptorId,
          descriptor.descriptorSha256,
          entry.componentKind,
          entry.payloadSha256,
        )) ||
      entry.worm.digest !== entry.envelopeSha256 ||
      entry.worm.key !==
        activationComponentWormKey(
          workerVersionId,
          descriptor.setId,
          descriptor.descriptorId,
          descriptor.descriptorSha256,
          entry.componentKind,
          entry.componentId,
        )
    ) {
      throw componentError(MANIFEST_INVALID);
    }
  }
  assertUniqueActivationComponentWorms(parsedEntries);
  const rebuilt = await assembleActivationComponentManifest(
    descriptor,
    Object.freeze(parsedEntries),
  );
  if (!sameBytes(rebuilt.canonicalBytes, decoded.bytes)) throw componentError(MANIFEST_INVALID);
  return rebuilt;
}

export async function assembleActivationComponentManifest(
  descriptor: Awaited<ReturnType<typeof buildActivationComponentSetDescriptor>>,
  components: readonly ActivationComponentManifestEntry[],
): Promise<PreparedActivationComponentManifest> {
  const core: JsonObject = {
    activation_sequence: ACTIVATION_COMPONENT_SEQUENCE,
    component_profile: ACTIVATION_COMPONENT_PROFILE,
    component_set_committed_at: descriptor.committedAt,
    component_set_descriptor_id: descriptor.descriptorId,
    component_set_descriptor_sha256: descriptor.descriptorSha256,
    component_set_id: descriptor.setId,
    components: components.map(entryJson),
    schema: ACTIVATION_COMPONENT_MANIFEST_SCHEMA,
    schema_version: 2,
    worker_version_id: descriptor.workerVersionId,
  };
  const manifestId = await digestDomain("dpone.activation-component-manifest.v2", core);
  const canonical = canonicalBytes({ ...core, manifest_id: manifestId });
  if (canonical.byteLength > ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES) {
    throw componentError(MANIFEST_INVALID, 413);
  }
  const manifestSha256 = `sha256:${await sha256Hex(canonical)}`;
  return Object.freeze({
    canonicalBytes: Uint8Array.from(canonical),
    committedAt: descriptor.committedAt,
    components: Object.freeze(components.map((entry) => freezeEntry(entry))),
    descriptorId: descriptor.descriptorId,
    descriptorSha256: descriptor.descriptorSha256,
    key: activationComponentManifestWormKey(
      descriptor.workerVersionId,
      descriptor.setId,
      manifestId,
      manifestSha256,
    ),
    manifestId,
    manifestSha256,
    setId: descriptor.setId,
    trust: "UNTRUSTED" as const,
    workerVersionId: descriptor.workerVersionId,
  });
}

function entryJson(entry: ActivationComponentManifestEntry): JsonObject {
  return {
    component_id: entry.componentId,
    component_kind: entry.componentKind,
    envelope_sha256: entry.envelopeSha256,
    payload_sha256: entry.payloadSha256,
    worm: activationComponentWormJson(entry.worm),
  };
}

function freezeEntry(entry: ActivationComponentManifestEntry): ActivationComponentManifestEntry {
  return Object.freeze({
    ...entry,
    worm: Object.freeze(copyActivationComponentWorm(entry.worm)),
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
