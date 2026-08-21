import { canonicalBytes, sha256Hex, timingSafeEqual } from "./canonical";
import { BrokerError } from "./errors";
import type { JsonObject } from "./types";

const RETENTION_DAYS = 2557;

export interface B2ObservedVersion {
  readonly contentSha1: string | null;
  readonly deleteMarker: boolean;
  readonly digest: string | null;
  readonly isLatest: boolean;
  readonly retentionMode: "COMPLIANCE" | null;
  readonly retentionUntil: string | null;
  readonly size: number;
  readonly versionId: string;
}

export interface B2VersionInventory {
  readonly bucket: {
    readonly defaultRetentionDays: number;
    readonly encryption: string;
    readonly objectLockEnabled: boolean;
    readonly type: string;
  };
  readonly digest: string;
  readonly key: string;
  readonly versions: readonly B2ObservedVersion[];
}

export interface B2VersionObserver {
  inspectExactKey(key: string): Promise<B2VersionInventory>;
}

export interface InventorySummary {
  readonly identicalVersionIds: readonly string[];
  readonly inventoryDigest: string;
  readonly latestVersionId: string | null;
  readonly retentionByVersion: ReadonlyMap<string, string>;
}

export async function validateInventory(
  inventory: B2VersionInventory,
  expectedKey: string,
  expectedSize: number,
  expectedDigest: string,
  expectedSha1: string,
  minimumRetentionMs: number,
): Promise<InventorySummary> {
  const bucket = inventory.bucket;
  if (
    inventory.key !== expectedKey ||
    !/^sha256:[0-9a-f]{64}$/u.test(inventory.digest) ||
    inventory.versions.length > 16 ||
    bucket.defaultRetentionDays !== RETENTION_DAYS ||
    bucket.encryption !== "SSE-B2" ||
    !bucket.objectLockEnabled ||
    bucket.type !== "allPrivate"
  ) {
    throw new BrokerError("B2_VERSION_INVENTORY_INVALID", 503, false);
  }
  const ids: string[] = [];
  const retentionByVersion = new Map<string, string>();
  let latestVersionId: string | null = null;
  let latestCount = 0;
  for (const version of inventory.versions) {
    validateVersionId(version.versionId);
    const retentionMs = Date.parse(version.retentionUntil ?? "");
    if (
      version.deleteMarker ||
      version.digest !== expectedDigest ||
      version.contentSha1 !== expectedSha1 ||
      version.size !== expectedSize ||
      version.retentionMode !== "COMPLIANCE" ||
      version.retentionUntil === null ||
      !Number.isFinite(retentionMs) ||
      retentionMs < minimumRetentionMs
    ) {
      throw new BrokerError("B2_VERSION_HISTORY_CONFLICT", 500, false);
    }
    if (version.isLatest) {
      latestCount += 1;
      latestVersionId = version.versionId;
    }
    ids.push(version.versionId);
    retentionByVersion.set(version.versionId, version.retentionUntil);
  }
  if (
    new Set(ids).size !== ids.length ||
    [...ids].sort().join("\n") !== ids.join("\n") ||
    latestCount !== (ids.length === 0 ? 0 : 1)
  ) {
    throw new BrokerError("B2_VERSION_INVENTORY_INVALID", 503, false);
  }
  const digestPayload = inventoryDigestPayload(inventory);
  const computed = `sha256:${await sha256Hex(canonicalBytes(digestPayload))}`;
  if (!timingSafeEqual(computed, inventory.digest)) {
    throw new BrokerError("B2_VERSION_INVENTORY_DIGEST_MISMATCH", 503, false);
  }
  return {
    identicalVersionIds: ids,
    inventoryDigest: inventory.digest,
    latestVersionId,
    retentionByVersion,
  };
}

export function inventoryDigestPayload(inventory: B2VersionInventory): JsonObject {
  return {
    bucket: {
      default_retention_days: inventory.bucket.defaultRetentionDays,
      encryption: inventory.bucket.encryption,
      object_lock_enabled: inventory.bucket.objectLockEnabled,
      type: inventory.bucket.type,
    },
    key: inventory.key,
    versions: inventory.versions.map((version) => ({
      content_sha1: version.contentSha1,
      delete_marker: version.deleteMarker,
      digest: version.digest,
      is_latest: version.isLatest,
      retention_mode: version.retentionMode,
      retention_until: version.retentionUntil,
      size: version.size,
      version_id: version.versionId,
    })),
  };
}

export function validateVersionId(value: string): void {
  if (value.length === 0 || value.length > 512) {
    throw new BrokerError("B2_VERSION_ID_INVALID", 503, false);
  }
}
