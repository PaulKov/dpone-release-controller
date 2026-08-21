import type { B2ObservedVersion, B2VersionInventory, B2VersionObserver } from "./b2";
import { assertAllowedB2ExactKey } from "./b2-key";
import { INTERNAL_RESPONSE_READ_POLICY, readBoundedBytes } from "./bounded";
import { canonicalBytes, canonicalJson, sha256Hex } from "./canonical";
import { assert, BrokerError } from "./errors";
import { assertPinnedServiceVersion, callPinnedService } from "./service-version";
import type { JsonObject, PrivateServicePin } from "./types";
import { exactObject, requireBoolean, requireInteger, requireString } from "./validation";

/** Closed client for the isolated B2 list/read retention observer Worker. */
export class B2VersionObserverClient implements B2VersionObserver {
  public constructor(
    private readonly service: Fetcher,
    private readonly pin: PrivateServicePin,
  ) {}

  public async inspectExactKey(key: string): Promise<B2VersionInventory> {
    assertAllowedB2ExactKey(key);
    const requestBody = {
      key,
      schema: "dpone.release-b2-version-inventory-request.v1",
      schema_version: 1,
    };
    const bytes = canonicalBytes(requestBody);
    const response = await callPinnedService(this.service, this.pin, {
      body: Uint8Array.from(bytes).buffer,
      headers: {
        "content-length": String(bytes.byteLength),
        "content-type": "application/json",
      },
      method: "POST",
      path: "/rpc/v1/object-versions",
    });
    if (!response.ok) {
      throw new BrokerError(
        "B2_OBSERVER_FAILED",
        503,
        response.status === 429 || response.status >= 500,
      );
    }
    const responseBytes = await readBoundedBytes(
      response,
      32_768,
      "B2_OBSERVER_RESPONSE_TOO_LARGE",
      INTERNAL_RESPONSE_READ_POLICY,
    );
    const text = new TextDecoder("utf-8", { fatal: true }).decode(responseBytes);
    let decoded: unknown;
    try {
      decoded = JSON.parse(text);
    } catch {
      throw new BrokerError("B2_OBSERVER_RESPONSE_INVALID", 503, false);
    }
    const result = exactObject(decoded, [
      "bucket",
      "digest",
      "key",
      "schema",
      "schema_version",
      "versions",
      "worker_version_id",
    ]);
    assert(text === canonicalJson(result), "B2_OBSERVER_RESPONSE_NONCANONICAL", 503);
    requireLiteral(result, "schema", "dpone.release-b2-version-inventory.v1");
    requireExactInteger(result, "schema_version", 1);
    requireLiteral(result, "key", key);
    assertPinnedServiceVersion(requireString(result, "worker_version_id", 128), this.pin);
    const rawVersions = result.versions;
    assert(
      Array.isArray(rawVersions) && rawVersions.length <= 16,
      "B2_OBSERVER_RESPONSE_INVALID",
      503,
    );
    const versions = rawVersions.map(parseVersion);
    const rawBucket = exactObject(result.bucket, [
      "default_retention_days",
      "encryption",
      "object_lock_enabled",
      "type",
    ]);
    requireExactInteger(rawBucket, "default_retention_days", 2557);
    requireLiteral(rawBucket, "encryption", "SSE-B2");
    requireLiteral(rawBucket, "type", "allPrivate");
    assert(requireBoolean(rawBucket, "object_lock_enabled"), "B2_OBSERVER_RESPONSE_INVALID", 503);
    const digest = requireString(result, "digest", 71, /^sha256:[0-9a-f]{64}$/u);
    const expected = `sha256:${await sha256Hex(
      canonicalBytes({ bucket: rawBucket, key, versions: rawVersions }),
    )}`;
    assert(digest === expected, "B2_OBSERVER_DIGEST_MISMATCH", 503);
    return {
      bucket: {
        defaultRetentionDays: 2557,
        encryption: "SSE-B2",
        objectLockEnabled: true,
        type: "allPrivate",
      },
      digest,
      key,
      versions,
    };
  }
}

function parseVersion(value: unknown): B2ObservedVersion {
  const version = exactObject(value, [
    "content_sha1",
    "delete_marker",
    "digest",
    "is_latest",
    "retention_mode",
    "retention_until",
    "size",
    "version_id",
  ]);
  const digest = nullableString(version, "digest", 71);
  if (digest !== null) {
    assert(/^sha256:[0-9a-f]{64}$/u.test(digest), "B2_OBSERVER_RESPONSE_INVALID", 503);
  }
  const retentionMode = nullableString(version, "retention_mode", 32);
  assert(
    retentionMode === null || retentionMode === "COMPLIANCE",
    "B2_OBSERVER_RESPONSE_INVALID",
    503,
  );
  return {
    contentSha1: requireString(version, "content_sha1", 40, /^[0-9a-f]{40}$/u),
    deleteMarker: requireBoolean(version, "delete_marker"),
    digest,
    isLatest: requireBoolean(version, "is_latest"),
    retentionMode,
    retentionUntil: nullableString(version, "retention_until", 32),
    size: requireInteger(version, "size", 0, 65_536),
    versionId: requireString(version, "version_id", 512),
  };
}

function nullableString(object: JsonObject, key: string, maxLength: number): string | null {
  const value = object[key];
  assert(
    value === null || (typeof value === "string" && value.length > 0 && value.length <= maxLength),
    "B2_OBSERVER_RESPONSE_INVALID",
    503,
  );
  return value;
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, expected.length) === expected,
    "B2_OBSERVER_RESPONSE_INVALID",
    503,
  );
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "B2_OBSERVER_RESPONSE_INVALID",
    503,
  );
}
