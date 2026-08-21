import { canonicalJson, sha256Hex } from "./canonical";
import { LIMITS } from "./config";
import { BrokerError } from "./errors";
import type {
  ActivationRecordView,
  ActivationSnapshot,
  ActivationWorm,
  JsonObject,
  LiveConfigEnv,
} from "./types";

/** Decode an exact canonical activation object from trusted local bytes. */
export function decodeCanonicalObject(bytes: Uint8Array): JsonObject {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new BrokerError("ACTIVATION_STORED_BYTES_INVALID", 503, false);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new BrokerError("ACTIVATION_STORED_BYTES_INVALID", 503, false);
  }
  const object = parsed as JsonObject;
  if (canonicalJson(object) !== text) {
    throw new BrokerError("ACTIVATION_STORED_BYTES_NONCANONICAL", 503, false);
  }
  return object;
}

/** Decode one canonical, fixed-bound private activation RPC body. */
export function decodeCanonicalText(text: string): JsonObject {
  const bytes = new TextEncoder().encode(text);
  if (bytes.byteLength === 0 || bytes.byteLength > LIMITS.bodyBytes) {
    throw new BrokerError("ACTIVATION_RPC_BODY_INVALID", 400, false);
  }
  return decodeCanonicalObject(bytes);
}

export function encodeAdminResult(record: ActivationRecordView): string {
  return canonicalJson({
    digest: record.digest,
    record: record.envelope,
    record_id: record.recordId,
    schema: "dpone.release-broker-admin-activation-result.v1",
    schema_version: 1,
    sequence: record.sequence,
    worm: wormJson(record.worm),
  });
}

export function snapshotJson(snapshot: ActivationSnapshot): JsonObject {
  return {
    activated: snapshot.activated === null ? null : recordViewJson(snapshot.activated),
    provisioned: recordViewJson(snapshot.provisioned),
    schema: "dpone.release-broker-activation-snapshot.v1",
    schema_version: 1,
  };
}

export function requireObjectField(parent: JsonObject, key: string): JsonObject {
  const value = parent[key];
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("ACTIVATION_STORED_RECORD_INVALID", 503, false);
  }
  return value;
}

export function requireStringField(parent: JsonObject, key: string): string {
  const value = parent[key];
  if (typeof value !== "string") {
    throw new BrokerError("ACTIVATION_STORED_RECORD_INVALID", 503, false);
  }
  return value;
}

export function requirePrivateFetcher(value: Fetcher | undefined, code: string): Fetcher {
  if (value === undefined || typeof value.fetch !== "function") {
    throw new BrokerError(code, 503, false);
  }
  return value;
}

export function requireGlobalHeadNamespace(
  value: LiveConfigEnv["GLOBAL_ACTIVATED_AUTHORITY_HEAD"],
): NonNullable<LiveConfigEnv["GLOBAL_ACTIVATED_AUTHORITY_HEAD"]> {
  if (value === undefined || typeof value.getByName !== "function") {
    throw new BrokerError("GLOBAL_ACTIVATED_AUTHORITY_HEAD_UNAVAILABLE", 503, true);
  }
  return value;
}

export function canonicalTimestamp(nowMs: number): string {
  return new Date(nowMs).toISOString();
}

export async function digestBytes(bytes: Uint8Array): Promise<string> {
  return `sha256:${await sha256Hex(bytes)}`;
}

export function assertActivationChronology(
  provisionedCommittedAt: string,
  promotion: JsonObject,
  observation: JsonObject,
  activatedCommitMs: number,
): void {
  const a0 = Date.parse(provisionedCommittedAt);
  const started = Date.parse(requireStringField(promotion, "started_at"));
  const completed = Date.parse(requireStringField(promotion, "completed_at"));
  const observed = Date.parse(requireStringField(observation, "observed_at"));
  const accepted = Date.parse(requireStringField(observation, "broker_accepted_at"));
  if (
    ![a0, started, completed, observed, accepted, activatedCommitMs].every(Number.isFinite) ||
    !(
      a0 < started &&
      started <= completed &&
      completed <= observed &&
      observed <= accepted &&
      accepted <= activatedCommitMs &&
      activatedCommitMs - accepted <= 60_000
    )
  ) {
    throw new BrokerError("ACTIVATION_PROMOTION_CHRONOLOGY_INVALID", 409, false);
  }
}

export function assertAuthorityObservationCommitFreshness(
  observation: JsonObject,
  committedAtMs: number,
): void {
  const observed = Date.parse(requireStringField(observation, "observed_at"));
  const accepted = Date.parse(requireStringField(observation, "broker_accepted_at"));
  if (
    ![observed, accepted, committedAtMs].every(Number.isFinite) ||
    observed > accepted ||
    accepted > committedAtMs ||
    committedAtMs - accepted > 60_000
  ) {
    throw new BrokerError("ACTIVATION_AUTHORITY_OBSERVATION_STALE", 409, false);
  }
}

function recordViewJson(record: ActivationRecordView): JsonObject {
  return {
    digest: record.digest,
    envelope: record.envelope,
    record_id: record.recordId,
    sequence: record.sequence,
    worm: wormJson(record.worm),
  };
}

function wormJson(worm: ActivationWorm): JsonObject {
  return {
    digest: worm.digest,
    key: worm.key,
    retention_until: worm.retentionUntil,
    version_id: worm.versionId,
  };
}
