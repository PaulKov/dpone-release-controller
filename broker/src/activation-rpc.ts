import { canonicalJson } from "./canonical";
import { assert, BrokerError } from "./errors";
import type { ActivationRecordView, ActivationSnapshot, ActivationWorm, JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

/** Decodes the canonical-string RPC wire returned by ActivationRegistry. */
export function parseActivationSnapshotCanonical(text: string): ActivationSnapshot | null {
  if (text.length === 0 || new TextEncoder().encode(text).byteLength > 131_072) {
    throw new BrokerError("ACTIVATION_SNAPSHOT_SIZE_INVALID", 503, false);
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(text);
  } catch {
    throw new BrokerError("ACTIVATION_SNAPSHOT_INVALID", 503, false);
  }
  const snapshot = exactObject(decoded, ["activated", "provisioned", "schema", "schema_version"]);
  assert(text === canonicalJson(snapshot), "ACTIVATION_SNAPSHOT_NONCANONICAL", 503);
  requireLiteral(snapshot, "schema", "dpone.release-broker-activation-snapshot.v1");
  requireExactInteger(snapshot, "schema_version", 1);
  const activated = snapshot.activated;
  assert(
    activated === null || (typeof activated === "object" && !Array.isArray(activated)),
    "ACTIVATION_SNAPSHOT_INVALID",
    503,
  );
  return {
    activated: activated === null ? null : parseRecord(activated, 1),
    provisioned: parseRecord(snapshot.provisioned, 0),
  };
}

/** Canonical, closed JSON projection shared by activation and head RPCs. */
export function activationSnapshotJson(snapshot: ActivationSnapshot): JsonObject {
  return {
    activated: snapshot.activated === null ? null : recordJson(snapshot.activated),
    provisioned: recordJson(snapshot.provisioned),
    schema: "dpone.release-broker-activation-snapshot.v1",
    schema_version: 1,
  };
}

function recordJson(record: ActivationRecordView): JsonObject {
  return {
    digest: record.digest,
    envelope: record.envelope,
    record_id: record.recordId,
    sequence: record.sequence,
    worm: {
      digest: record.worm.digest,
      key: record.worm.key,
      retention_until: record.worm.retentionUntil,
      version_id: record.worm.versionId,
    },
  };
}

function parseRecord(value: unknown, sequence: 0 | 1): ActivationRecordView {
  const record = exactObject(value, ["digest", "envelope", "record_id", "sequence", "worm"]);
  const envelope = record.envelope;
  assert(
    envelope !== null && typeof envelope === "object" && !Array.isArray(envelope),
    "ACTIVATION_SNAPSHOT_INVALID",
    503,
  );
  requireExactInteger(record, "sequence", sequence);
  const digest = taggedDigest(record, "digest");
  const recordId = taggedDigest(record, "record_id");
  assert(
    envelope.record_id === recordId && envelope.sequence === sequence,
    "ACTIVATION_SNAPSHOT_BINDING_INVALID",
    503,
  );
  return {
    digest,
    envelope,
    recordId,
    sequence,
    worm: parseWorm(record.worm, digest),
  };
}

function parseWorm(value: unknown, digest: string): ActivationWorm {
  const worm = exactObject(value, ["digest", "key", "retention_until", "version_id"]);
  requireLiteral(worm, "digest", digest);
  return {
    digest,
    key: requireString(worm, "key", 512, /^receipts\/v1\/activation\/.+\.json$/u),
    retentionUntil: requireString(
      worm,
      "retention_until",
      32,
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u,
    ),
    versionId: requireString(worm, "version_id", 512),
  };
}

function taggedDigest(object: JsonObject, key: string): string {
  return requireString(object, key, 71, /^sha256:[0-9a-f]{64}$/u);
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, Math.max(1, expected.length)) === expected,
    "ACTIVATION_SNAPSHOT_INVALID",
    503,
  );
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "ACTIVATION_SNAPSHOT_INVALID",
    503,
  );
}
