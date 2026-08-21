import {
  activationString,
  activationTimestamp,
  ACTIVATION_COMPONENT_DIGEST,
  ACTIVATION_COMPONENT_WORKER_VERSION,
  ACTIVATION_COMPONENT_WORM_VERSION,
  componentError,
  decodeBoundedActivationObject,
  exactActivationObject,
} from "./activation-component-codec";
import type {
  ActivationComponentDescriptor,
  ActivationComponentManifestEntry,
  PreparedActivationComponentManifestPointer,
  PreparedActivationComponentEnvelope,
  PreparedActivationComponentManifest,
} from "./activation-component-contract";
import {
  ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
  ACTIVATION_COMPONENT_MANIFEST_MAX_NODES,
  ACTIVATION_COMPONENT_MAX_DEPTH,
  ACTIVATION_COMPONENT_MAX_STRING_BYTES,
} from "./activation-component-contract";
import { activationComponentWormKey } from "./activation-component-envelope";
import type { ActivationWorm, JsonObject } from "./types";

const WORM_FIELDS = ["digest", "key", "retention_until", "version_id"] as const;
const POINTER_FIELDS = ["manifest_id", "manifest_sha256", "worm"] as const;
const MANIFEST_INVALID = "ACTIVATION_COMPONENT_MANIFEST_INVALID";
const RETENTION_MILLISECONDS = 2557 * 86_400_000;

export function activationComponentManifestWormKey(
  workerVersionId: string,
  setId: string,
  manifestId: string,
  manifestSha256: string,
): string {
  if (
    !ACTIVATION_COMPONENT_WORKER_VERSION.test(workerVersionId) ||
    ![setId, manifestId, manifestSha256].every((value) => ACTIVATION_COMPONENT_DIGEST.test(value))
  ) {
    throw componentError(MANIFEST_INVALID);
  }
  return [
    "receipts",
    "v2",
    "activation-component-manifests",
    workerVersionId,
    setId.slice("sha256:".length),
    manifestId.slice("sha256:".length),
    `${manifestSha256.slice("sha256:".length)}.json`,
  ].join("/");
}

export function validateActivationComponentWorm(
  wormInput: ActivationWorm,
  envelope: PreparedActivationComponentEnvelope,
  descriptor: ActivationComponentDescriptor,
): ActivationWorm {
  const worm = copyActivationComponentWorm(wormInput);
  if (
    worm.digest !== envelope.envelopeSha256 ||
    worm.key !== envelope.key ||
    worm.key !==
      activationComponentWormKey(
        descriptor.workerVersionId,
        descriptor.setId,
        descriptor.descriptorId,
        descriptor.descriptorSha256,
        envelope.componentKind,
        envelope.componentId,
      )
  ) {
    throw componentError(MANIFEST_INVALID);
  }
  assertActivationComponentRetention(worm, descriptor.committedAt);
  return Object.freeze(worm);
}

export function validateActivationManifestWorm(
  wormInput: ActivationWorm,
  manifest: PreparedActivationComponentManifest,
): ActivationWorm {
  const worm = copyActivationComponentWorm(wormInput);
  if (worm.digest !== manifest.manifestSha256 || worm.key !== manifest.key) {
    throw componentError(MANIFEST_INVALID);
  }
  assertActivationComponentRetention(worm, manifest.committedAt);
  return Object.freeze(worm);
}

export function parseActivationComponentWorm(value: unknown, committedAt: string): ActivationWorm {
  const object = exactActivationObject(value, WORM_FIELDS, MANIFEST_INVALID);
  const worm = {
    digest: activationString(object, "digest", ACTIVATION_COMPONENT_DIGEST, MANIFEST_INVALID),
    key: activationString(
      object,
      "key",
      /^receipts\/v2\/activation-components\/[a-z0-9_./-]{1,500}\.json$/u,
      MANIFEST_INVALID,
    ),
    retentionUntil: activationTimestamp(
      activationString(
        object,
        "retention_until",
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u,
        MANIFEST_INVALID,
      ),
      MANIFEST_INVALID,
    ),
    versionId: activationString(
      object,
      "version_id",
      ACTIVATION_COMPONENT_WORM_VERSION,
      MANIFEST_INVALID,
    ),
  };
  assertActivationComponentRetention(worm, committedAt);
  return Object.freeze(worm);
}

export function assertUniqueActivationComponentWorms(
  components: readonly ActivationComponentManifestEntry[],
): void {
  const keys = components.map(({ worm }) => worm.key);
  const versions = components.map(({ worm }) => worm.versionId);
  const ids = components.map(({ componentId }) => componentId);
  if (
    new Set(keys).size !== keys.length ||
    new Set(versions).size !== versions.length ||
    new Set(ids).size !== ids.length
  ) {
    throw componentError(MANIFEST_INVALID);
  }
}

/** Validate the self-contained compact-A0 pointer before any resolver fetch. */
export function parseActivationComponentManifestPointer(
  canonicalPointerBytes: Uint8Array,
): PreparedActivationComponentManifestPointer {
  const decoded = decodeBoundedActivationObject(
    canonicalPointerBytes,
    {
      bytes: ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
      depth: ACTIVATION_COMPONENT_MAX_DEPTH,
      maxStringBytes: ACTIVATION_COMPONENT_MAX_STRING_BYTES,
      nodes: ACTIVATION_COMPONENT_MANIFEST_MAX_NODES,
    },
    MANIFEST_INVALID,
  );
  const pointer = exactActivationObject(decoded.value, POINTER_FIELDS, MANIFEST_INVALID);
  const manifestId = activationString(
    pointer,
    "manifest_id",
    ACTIVATION_COMPONENT_DIGEST,
    MANIFEST_INVALID,
  );
  const manifestSha256 = activationString(
    pointer,
    "manifest_sha256",
    ACTIVATION_COMPONENT_DIGEST,
    MANIFEST_INVALID,
  );
  const worm = exactActivationObject(pointer.worm, WORM_FIELDS, MANIFEST_INVALID);
  const parsedWorm = {
    digest: activationString(worm, "digest", ACTIVATION_COMPONENT_DIGEST, MANIFEST_INVALID),
    key: activationString(
      worm,
      "key",
      /^receipts\/v2\/[a-z0-9/_-]{1,500}\.json$/u,
      MANIFEST_INVALID,
    ),
    retentionUntil: activationTimestamp(
      activationString(
        worm,
        "retention_until",
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u,
        MANIFEST_INVALID,
      ),
      MANIFEST_INVALID,
    ),
    versionId: activationString(
      worm,
      "version_id",
      ACTIVATION_COMPONENT_WORM_VERSION,
      MANIFEST_INVALID,
    ),
  };
  const match =
    /^receipts\/v2\/activation-component-manifests\/([0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})\/([0-9a-f]{64})\/([0-9a-f]{64})\/([0-9a-f]{64})\.json$/u.exec(
      parsedWorm.key,
    );
  const matchedManifestId = match?.[3];
  const matchedManifestSha256 = match?.[4];
  const workerVersionId = match?.[1];
  const setIdHex = match?.[2];
  if (
    parsedWorm.digest !== manifestSha256 ||
    workerVersionId === undefined ||
    setIdHex === undefined ||
    matchedManifestId !== manifestId.slice("sha256:".length) ||
    matchedManifestSha256 !== manifestSha256.slice("sha256:".length)
  ) {
    throw componentError(MANIFEST_INVALID);
  }
  const ownedWorm = Object.freeze(parsedWorm);
  const document = Object.freeze({
    manifest_id: manifestId,
    manifest_sha256: manifestSha256,
    worm: Object.freeze(activationComponentWormJson(ownedWorm)),
  });
  return Object.freeze({
    canonicalBytes: Uint8Array.from(decoded.bytes),
    document,
    manifestId,
    manifestSha256,
    setId: `sha256:${setIdHex}`,
    trust: "UNTRUSTED" as const,
    workerVersionId,
    worm: ownedWorm,
  });
}

export function activationComponentWormJson(worm: ActivationWorm): JsonObject {
  return {
    digest: worm.digest,
    key: worm.key,
    retention_until: worm.retentionUntil,
    version_id: worm.versionId,
  };
}

export function copyActivationComponentWorm(worm: ActivationWorm): ActivationWorm {
  return {
    digest: worm.digest,
    key: worm.key,
    retentionUntil: worm.retentionUntil,
    versionId: worm.versionId,
  };
}

function assertActivationComponentRetention(worm: ActivationWorm, committedAt: string): void {
  const retentionUntil = activationTimestamp(worm.retentionUntil, MANIFEST_INVALID);
  const committed = activationTimestamp(committedAt, MANIFEST_INVALID);
  if (
    !ACTIVATION_COMPONENT_WORM_VERSION.test(worm.versionId) ||
    Date.parse(retentionUntil) < Date.parse(committed) + RETENTION_MILLISECONDS
  ) {
    throw componentError(MANIFEST_INVALID);
  }
}
