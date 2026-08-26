import { canonicalBytes, canonicalJson, sha256Hex } from "./canonical";
import { CLOUDFLARE_UUID } from "./cloudflare-ids";
import { LIMITS } from "./config";
import { assert } from "./errors";
import type { ActivationWorm, JsonObject, JsonValue } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export const ACTIVATED_AUTHORITY_HEAD_SCHEMA = "dpone.activated-service-authority-head.v1" as const;

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const GENERATION_MAX = Number.MAX_SAFE_INTEGER;

export interface ActivatedAuthorityHeadInput {
  readonly activatedRecordId: string;
  readonly activatedRecordSha256: string;
  readonly activatedServiceAuthoritiesSha256: string;
  readonly activatedWorm: ActivationWorm;
  readonly committedAt: string;
  readonly generation: number;
  readonly ingressWorkerVersionId: string;
  readonly previous: "GENESIS" | JsonObject;
}

/** Build the self-derived, canonical, nonsemantic global activation witness. */
export async function buildActivatedAuthorityHead(
  input: ActivatedAuthorityHeadInput,
): Promise<JsonObject> {
  const activatedRecordSha256 = tagged(input.activatedRecordSha256);
  const ingressWorkerVersionId = workerVersion(input.ingressWorkerVersionId);
  const withoutId: JsonObject = {
    activated: {
      record_id: tagged(input.activatedRecordId),
      record_sha256: activatedRecordSha256,
      worm: activationWormJson(input.activatedWorm, activatedRecordSha256, ingressWorkerVersionId),
    },
    activated_service_authorities_sha256: tagged(input.activatedServiceAuthoritiesSha256),
    committed_at: timestamp(input.committedAt),
    generation: generation(input.generation),
    ingress_worker_version_id: ingressWorkerVersionId,
    previous: previousJson(input.previous, input.generation),
    schema: ACTIVATED_AUTHORITY_HEAD_SCHEMA,
    schema_version: 1,
  };
  const head: JsonObject = {
    ...withoutId,
    record_id: `sha256:${await sha256Hex(canonicalBytes(withoutId))}`,
  };
  assertCanonicalSize(head);
  return head;
}

/** Parse and independently recompute a canonical global-head witness. */
export async function parseActivatedAuthorityHead(value: unknown): Promise<JsonObject> {
  const head = headObject(value);
  literal(head, "schema", ACTIVATED_AUTHORITY_HEAD_SCHEMA);
  exactInteger(head, "schema_version", 1);
  const currentGeneration = requireInteger(head, "generation", 1, GENERATION_MAX);
  const activated = activatedObject(head.activated);
  const recordSha256 = taggedField(activated, "record_sha256");
  const rebuilt = await buildActivatedAuthorityHead({
    activatedRecordId: taggedField(activated, "record_id"),
    activatedRecordSha256: recordSha256,
    activatedServiceAuthoritiesSha256: taggedField(head, "activated_service_authorities_sha256"),
    activatedWorm: parseActivationWorm(
      activated.worm,
      recordSha256,
      requireString(head, "ingress_worker_version_id", 36, CLOUDFLARE_UUID),
    ),
    committedAt: requireString(head, "committed_at", 32, TIMESTAMP),
    generation: currentGeneration,
    ingressWorkerVersionId: requireString(head, "ingress_worker_version_id", 36, CLOUDFLARE_UUID),
    previous: parsePrevious(head.previous),
  });
  assert(
    canonicalJson(head) === canonicalJson(rebuilt) && head.record_id === rebuilt.record_id,
    "ACTIVATED_AUTHORITY_HEAD_DIGEST_INVALID",
    503,
  );
  return head;
}

export async function activatedAuthorityHeadRecordSha256(head: JsonObject): Promise<string> {
  return `sha256:${await sha256Hex(canonicalBytes(await parseActivatedAuthorityHead(head)))}`;
}

export async function activatedAuthorityHeadKey(head: JsonObject): Promise<string> {
  const value = requireInteger(head, "generation", 1, GENERATION_MAX);
  const recordSha256 = (await activatedAuthorityHeadRecordSha256(head)).slice("sha256:".length);
  return `receipts/v1/activation-head/generations/${String(value).padStart(20, "0")}-${recordSha256}.json`;
}

/** Extract the exact compact A1_PRECOMMIT authority aggregate digest. */
export function activatedServiceAuthoritiesSha256(activatedEnvelope: JsonObject): string {
  const authorities = exactObject(activatedEnvelope.service_authorities, [
    "a1_precommit_observation",
    "expectation_sha256",
  ]);
  const observation = exactObject(authorities.a1_precommit_observation, [
    "broker_accepted_at",
    "cloudflare_provider_observation_sha256",
    "expectation_sha256",
    "network_surface",
    "observed_at",
    "observer_service_identity",
    "observer_worker_version_id",
    "phase",
    "provider_observation_sha256",
    "schema",
    "schema_version",
    "services",
  ]);
  literal(observation, "phase", "A1_PRECOMMIT");
  return taggedField(observation, "provider_observation_sha256");
}

function headObject(value: unknown): JsonObject {
  return exactObject(value, [
    "activated",
    "activated_service_authorities_sha256",
    "committed_at",
    "generation",
    "ingress_worker_version_id",
    "previous",
    "record_id",
    "schema",
    "schema_version",
  ]);
}

function activatedObject(value: JsonValue | undefined): JsonObject {
  return exactObject(value, ["record_id", "record_sha256", "worm"]);
}

function parsePrevious(value: JsonValue | undefined): "GENESIS" | JsonObject {
  if (value === "GENESIS") return value;
  const previous = exactObject(value, ["generation", "record_id", "record_sha256"]);
  requireInteger(previous, "generation", 1, GENERATION_MAX - 1);
  taggedField(previous, "record_id");
  taggedField(previous, "record_sha256");
  return previous;
}

function previousJson(value: "GENESIS" | JsonObject, current: number): JsonValue {
  if (current === 1) {
    assert(value === "GENESIS", "ACTIVATED_AUTHORITY_HEAD_PREVIOUS_INVALID", 409);
    return value;
  }
  const previous = exactObject(value, ["generation", "record_id", "record_sha256"]);
  assert(
    requireInteger(previous, "generation", 1, GENERATION_MAX - 1) === current - 1,
    "ACTIVATED_AUTHORITY_HEAD_PREVIOUS_INVALID",
    409,
  );
  return {
    generation: previous.generation ?? null,
    record_id: taggedField(previous, "record_id"),
    record_sha256: taggedField(previous, "record_sha256"),
  };
}

function parseActivationWorm(
  value: JsonValue | undefined,
  digest: string,
  ingressWorkerVersionId: string,
): ActivationWorm {
  const worm = exactObject(value, ["digest", "key", "retention_until", "version_id"]);
  literal(worm, "digest", digest);
  const expectedKey =
    `receipts/v1/activation/${ingressWorkerVersionId}/` +
    `1-${digest.slice("sha256:".length)}.json`;
  return {
    digest,
    key: literalValue(worm, "key", expectedKey),
    retentionUntil: requireString(worm, "retention_until", 32, TIMESTAMP),
    versionId: requireString(worm, "version_id", 512, /^[A-Za-z0-9._=-]{1,512}$/u),
  };
}

function activationWormJson(
  worm: ActivationWorm,
  digest: string,
  ingressWorkerVersionId: string,
): JsonObject {
  assert(worm.digest === digest, "ACTIVATED_AUTHORITY_HEAD_WORM_INVALID", 503);
  const normalized = parseActivationWorm(
    {
      digest,
      key: worm.key,
      retention_until: worm.retentionUntil,
      version_id: worm.versionId,
    },
    digest,
    ingressWorkerVersionId,
  );
  return {
    digest,
    key: normalized.key,
    retention_until: timestamp(normalized.retentionUntil),
    version_id: normalized.versionId,
  };
}

function generation(value: number): number {
  assert(
    Number.isSafeInteger(value) && value >= 1 && value <= GENERATION_MAX,
    "ACTIVATED_AUTHORITY_HEAD_INVALID",
    500,
  );
  return value;
}

function workerVersion(value: string): string {
  assert(CLOUDFLARE_UUID.test(value), "ACTIVATED_AUTHORITY_HEAD_INVALID", 500);
  return value;
}

function timestamp(value: string): string {
  assert(
    TIMESTAMP.test(value) && new Date(Date.parse(value)).toISOString() === value,
    "ACTIVATED_AUTHORITY_HEAD_INVALID",
    500,
  );
  return value;
}

function literalValue(object: JsonObject, key: string, expected: string): string {
  literal(object, key, expected);
  return expected;
}

function assertCanonicalSize(value: JsonObject): void {
  assert(
    canonicalBytes(value).byteLength > 0 && canonicalBytes(value).byteLength <= LIMITS.bodyBytes,
    "ACTIVATED_AUTHORITY_HEAD_SIZE_INVALID",
    413,
  );
}

function tagged(value: string): string {
  assert(DIGEST.test(value), "ACTIVATED_AUTHORITY_HEAD_INVALID", 500);
  return value;
}

function taggedField(object: JsonObject, key: string): string {
  return requireString(object, key, 71, DIGEST);
}

function literal(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, expected.length) === expected,
    "ACTIVATED_AUTHORITY_HEAD_INVALID",
    503,
  );
}

function exactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "ACTIVATED_AUTHORITY_HEAD_INVALID",
    503,
  );
}
