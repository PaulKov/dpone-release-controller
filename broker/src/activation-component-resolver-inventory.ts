import { sha256Hex, timingSafeEqual } from "./canonical";
import {
  ACTIVATION_COMPONENT_KINDS,
  ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
} from "./activation-component-contract";
import { activationTimestamp, componentError } from "./activation-component-codec";
import type { ActivationComponentNamespaceSnapshot } from "./activation-component-resolver-contract";
import type { ActivationWorm } from "./types";
import { BrokerError } from "./errors";
import { ownExactUint8Array } from "./exact-uint8array";

const INVENTORY_INVALID = "ACTIVATION_COMPONENT_RESOLVER_INVENTORY_INVALID";
const SHA1 = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const VERSION = /^[A-Za-z0-9._=-]{1,512}$/u;
const KEY = /^receipts\/v2\/[A-Za-z0-9._/-]{1,500}\.json$/u;

export interface ActivationComponentExpectedObject {
  readonly worm: ActivationWorm;
}

export interface OwnedActivationComponentVersion {
  readonly canonicalBytes: Uint8Array<ArrayBuffer>;
  readonly contentSha1: string;
  readonly contentType: "application/json";
  readonly deleteMarker: false;
  readonly digest: string;
  readonly encryption: "SSE-B2";
  readonly isLatest: true;
  readonly key: string;
  readonly retentionMode: "COMPLIANCE";
  readonly retentionUntil: string;
  readonly size: number;
  readonly versionId: string;
}

export interface OwnedActivationComponentNamespace {
  readonly bucket: {
    readonly bucketId: string;
    readonly bucketName: string;
    readonly cloudflareAccountId: string;
    readonly defaultRetentionDays: 2557;
    readonly encryption: "SSE-B2";
    readonly objectLockEnabled: true;
    readonly type: "allPrivate";
  };
  readonly complete: true;
  readonly versions: readonly OwnedActivationComponentVersion[];
}

/**
 * Own and validate a complete namespace response. Cardinality is checked
 * before mapping or copying any caller-owned body.
 */
export async function resolveExactActivationComponentNamespace(
  input: ActivationComponentNamespaceSnapshot,
  expected: readonly ActivationComponentExpectedObject[],
  maximumVersions: 2 | 16,
): Promise<OwnedActivationComponentNamespace> {
  const expectedSnapshot = expectedObjects(expected, maximumVersions);
  const snapshot = snapshotActivationComponentNamespaceAuthority(
    input,
    expectedSnapshot.ordered.length,
    maximumVersions,
  );
  const expectedByKey = expectedSnapshot.byKey;
  const verifiedByKey = new Map<string, OwnedActivationComponentVersion>();
  const observedVersions = new Set<string>();
  for (const candidate of snapshot.versions) {
    const authority = expectedByKey.get(candidate.key);
    if (
      authority === undefined ||
      observedVersions.has(candidate.versionId) ||
      !sameWorm(candidate, authority.worm) ||
      candidate.size !== candidate.canonicalBytes.byteLength ||
      !timingSafeEqual(candidate.digest, `sha256:${await sha256Hex(candidate.canonicalBytes)}`) ||
      !timingSafeEqual(candidate.contentSha1, await sha1Hex(candidate.canonicalBytes))
    ) {
      throw componentError(INVENTORY_INVALID);
    }
    observedVersions.add(candidate.versionId);
    verifiedByKey.set(candidate.key, candidate);
  }
  if (verifiedByKey.size !== expectedByKey.size) throw componentError(INVENTORY_INVALID);
  return Object.freeze({
    bucket: snapshot.bucket,
    complete: true,
    versions: Object.freeze(
      expectedSnapshot.ordered.map(({ worm }) => {
        const candidate = verifiedByKey.get(worm.key);
        if (candidate === undefined) throw componentError(INVENTORY_INVALID);
        return candidate;
      }),
    ),
  });
}

/** Own provider inventory synchronously; exact WORM/digest verification remains mandatory. */
export function snapshotActivationComponentNamespaceAuthority(
  input: ActivationComponentNamespaceSnapshot,
  expectedCount: number,
  maximumVersions: 2 | 16,
): OwnedActivationComponentNamespace {
  try {
    return snapshotNamespace(input, expectedCount, maximumVersions);
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw componentError(INVENTORY_INVALID);
  }
}

function snapshotNamespace(
  input: ActivationComponentNamespaceSnapshot,
  expectedCount: number,
  maximumVersions: 2 | 16,
): OwnedActivationComponentNamespace {
  const record = exactRecord(input, ["bucket", "complete", "versions"]);
  if (record.complete !== true) throw componentError(INVENTORY_INVALID);
  const bucket = exactRecord(record.bucket, [
    "bucketId",
    "bucketName",
    "cloudflareAccountId",
    "defaultRetentionDays",
    "encryption",
    "objectLockEnabled",
    "type",
  ]);
  if (
    !/^[0-9a-f]{32}$/u.test(exactString(bucket.cloudflareAccountId, /^[0-9a-f]{32}$/u)) ||
    !/^[0-9a-f]{24}$/u.test(exactString(bucket.bucketId, /^[0-9a-f]{24}$/u)) ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$/u.test(
      exactString(bucket.bucketName, /^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$/u),
    ) ||
    bucket.defaultRetentionDays !== 2557 ||
    bucket.encryption !== "SSE-B2" ||
    bucket.objectLockEnabled !== true ||
    bucket.type !== "allPrivate"
  ) {
    throw componentError(INVENTORY_INVALID);
  }
  const rawVersions = snapshotDenseArray(record.versions, expectedCount, maximumVersions);
  const versions: OwnedActivationComponentVersion[] = [];
  for (let index = 0; index < expectedCount; index += 1) {
    const raw = exactRecord(rawVersions[index], [
      "canonicalBytes",
      "contentSha1",
      "contentType",
      "deleteMarker",
      "digest",
      "encryption",
      "isLatest",
      "key",
      "retentionMode",
      "retentionUntil",
      "size",
      "versionId",
    ]);
    const bytes = exactBytes(raw.canonicalBytes);
    if (
      raw.deleteMarker !== false ||
      raw.contentType !== "application/json" ||
      raw.encryption !== "SSE-B2" ||
      raw.isLatest !== true ||
      raw.retentionMode !== "COMPLIANCE" ||
      typeof raw.size !== "number" ||
      !Number.isSafeInteger(raw.size) ||
      raw.size < 1 ||
      raw.size > ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES
    ) {
      throw componentError(INVENTORY_INVALID);
    }
    versions.push(
      Object.freeze({
        canonicalBytes: bytes,
        contentSha1: exactString(raw.contentSha1, SHA1),
        contentType: "application/json",
        deleteMarker: false,
        digest: exactString(raw.digest, DIGEST),
        encryption: "SSE-B2",
        isLatest: true,
        key: exactString(raw.key, KEY),
        retentionMode: "COMPLIANCE",
        retentionUntil: activationTimestamp(
          exactString(raw.retentionUntil, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u),
          INVENTORY_INVALID,
        ),
        size: raw.size,
        versionId: exactString(raw.versionId, VERSION),
      }),
    );
  }
  return Object.freeze({
    bucket: Object.freeze({
      bucketId: exactString(bucket.bucketId, /^[0-9a-f]{24}$/u),
      bucketName: exactString(bucket.bucketName, /^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$/u),
      cloudflareAccountId: exactString(bucket.cloudflareAccountId, /^[0-9a-f]{32}$/u),
      defaultRetentionDays: 2557,
      encryption: "SSE-B2",
      objectLockEnabled: true,
      type: "allPrivate",
    }),
    complete: true,
    versions: Object.freeze(versions),
  });
}

function expectedObjects(
  input: readonly ActivationComponentExpectedObject[],
  maximumVersions: 2 | 16,
): {
  readonly byKey: ReadonlyMap<string, ActivationComponentExpectedObject>;
  readonly ordered: readonly ActivationComponentExpectedObject[];
} {
  try {
    const candidates = snapshotDenseArray(input, undefined, maximumVersions);
    const expectedLength = maximumVersions === 2 ? 1 : ACTIVATION_COMPONENT_KINDS.length;
    if (candidates.length !== expectedLength) {
      throw componentError(INVENTORY_INVALID, 500);
    }
    const byKey = new Map<string, ActivationComponentExpectedObject>();
    const ordered: ActivationComponentExpectedObject[] = [];
    for (const candidate of candidates) {
      const authority = exactRecord(candidate, ["worm"]);
      const source = exactRecord(authority.worm, ["digest", "key", "retentionUntil", "versionId"]);
      const worm = Object.freeze({
        digest: exactString(source.digest, DIGEST),
        key: exactString(source.key, KEY),
        retentionUntil: activationTimestamp(
          exactString(source.retentionUntil, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u),
          INVENTORY_INVALID,
        ),
        versionId: exactString(source.versionId, VERSION),
      });
      const key = worm.key;
      if (byKey.has(key)) throw componentError(INVENTORY_INVALID);
      const snapshot = Object.freeze({ worm });
      byKey.set(key, snapshot);
      ordered.push(snapshot);
    }
    return Object.freeze({ byKey, ordered: Object.freeze(ordered) });
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw componentError(INVENTORY_INVALID);
  }
}

function sameWorm(candidate: OwnedActivationComponentVersion, expected: ActivationWorm): boolean {
  return (
    candidate.digest === expected.digest &&
    candidate.key === expected.key &&
    candidate.retentionUntil === expected.retentionUntil &&
    candidate.versionId === expected.versionId
  );
}

function exactRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw componentError(INVENTORY_INVALID);
  }
  const record = value as Record<string, unknown>;
  const prototype = Reflect.getPrototypeOf(record);
  if (prototype !== Object.prototype && prototype !== null) {
    throw componentError(INVENTORY_INVALID);
  }
  const descriptors = Object.getOwnPropertyDescriptors(record);
  const actual = Reflect.ownKeys(descriptors);
  if (actual.some((key) => typeof key !== "string")) throw componentError(INVENTORY_INVALID);
  const actualStrings = (actual as string[]).sort();
  const expected = [...fields].sort();
  if (
    actualStrings.length !== expected.length ||
    actualStrings.some((key, index) => key !== expected[index]) ||
    actualStrings.some((key) => {
      const descriptor = descriptors[key];
      return descriptor === undefined || !descriptor.enumerable || !("value" in descriptor);
    })
  ) {
    throw componentError(INVENTORY_INVALID);
  }
  return Object.freeze(
    Object.fromEntries(
      fields.map((key) => {
        const descriptor = descriptors[key];
        if (descriptor === undefined || !("value" in descriptor)) {
          throw componentError(INVENTORY_INVALID);
        }
        return [key, descriptor.value as unknown] as const;
      }),
    ),
  );
}

function snapshotDenseArray(
  value: unknown,
  expectedLength: number | undefined,
  maximumLength: 2 | 16,
): readonly unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    throw componentError(INVENTORY_INVALID);
  }
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (
    lengthDescriptor === undefined ||
    !("value" in lengthDescriptor) ||
    typeof lengthDescriptor.value !== "number" ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0 ||
    (expectedLength !== undefined && lengthDescriptor.value !== expectedLength) ||
    lengthDescriptor.value > maximumLength
  ) {
    throw componentError(INVENTORY_INVALID);
  }
  const expected = Array.from({ length: lengthDescriptor.value }, (_, index) => String(index));
  expected.push("length");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index]) ||
    expected.slice(0, -1).some((key) => {
      const descriptor = descriptors[key];
      return descriptor === undefined || !descriptor.enumerable || !("value" in descriptor);
    })
  ) {
    throw componentError(INVENTORY_INVALID);
  }
  return Object.freeze(
    expected.slice(0, -1).map((key) => {
      const descriptor = descriptors[key];
      if (descriptor === undefined || !("value" in descriptor)) {
        throw componentError(INVENTORY_INVALID);
      }
      return descriptor.value as unknown;
    }),
  );
}

function exactBytes(value: unknown): Uint8Array<ArrayBuffer> {
  return ownExactUint8Array(value, {
    code: INVENTORY_INVALID,
    invalidStatus: 409,
    maximum: ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
    minimum: 1,
    sizeStatus: 409,
  });
}

function exactString(value: unknown, pattern: RegExp): string {
  pattern.lastIndex = 0;
  if (typeof value !== "string" || pattern.exec(value)?.[0] !== value) {
    throw componentError(INVENTORY_INVALID);
  }
  return value;
}

async function sha1Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", bytes);
  return Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, "0")).join(
    "",
  );
}
