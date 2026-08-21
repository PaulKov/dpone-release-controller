import { canonicalBytes, canonicalJson, digestObject } from "./canonical";
import { CLOUDFLARE_DEPLOYMENT_OBSERVATION_SCHEMA } from "./cloudflare-deployment-observation-contract";
import {
  B2_OBSERVER_IDENTITY,
  BATCH_DIGEST,
  BATCH_UUID,
  WORM_IDENTITY,
} from "./cloudflare-evidence-batch-codec";
import type {
  AnyCloudflareEvidenceBatchBinding,
  CloudflareEvidenceBatchBinding,
  CloudflareEvidenceBatchBindingV2,
  CloudflareEvidenceBatchContext,
  CloudflareEvidenceBatchExecution,
  CloudflareEvidenceBatchSlotInput,
} from "./cloudflare-evidence-batch-contract";
import { BrokerError } from "./errors";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export const MAX_STORED_CLOUDFLARE_OBSERVATION_BYTES = 1_048_576;

export interface CloudflareEvidenceBatchRow extends Record<string, SqlStorageValue> {
  readonly activation_issuance_id: string | null;
  readonly activation_issuance_ordinal: number | null;
  readonly activation_sequence: number | null;
  readonly batch_id: string;
  readonly binding_schema_version: number;
  readonly b2_observer_service_identity: string;
  readonly b2_observer_worker_version_id: string;
  readonly cloudflare_observer_service_identity: string | null;
  readonly committed_at: string;
  readonly delegation_committed_at: string | null;
  readonly delegation_fresh_until: string | null;
  readonly delegation_issued_at: string | null;
  readonly delegation_sha256: string | null;
  readonly expectation_sha256: string;
  readonly observation_canonical_bytes: ArrayBuffer;
  readonly observed_at: string;
  readonly observer_worker_version_id: string;
  readonly phase: string;
  readonly provider_observation_sha256: string;
  readonly seal_sha256: string;
  readonly status: string;
  readonly worm_service_identity: string;
  readonly worm_worker_version_id: string;
}

/** Validate and clone the sanitized provider projection retained for recovery. */
export async function validateCloudflareEvidenceBatchObservation(
  value: JsonObject,
  binding: AnyCloudflareEvidenceBatchBinding,
  observedAt: string,
  inputs: readonly CloudflareEvidenceBatchSlotInput[],
): Promise<JsonObject> {
  const observation = exactObject(value, [
    "cloudflare_account_id",
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
  if (
    requireString(observation, "schema", CLOUDFLARE_DEPLOYMENT_OBSERVATION_SCHEMA.length) !==
      CLOUDFLARE_DEPLOYMENT_OBSERVATION_SCHEMA ||
    requireInteger(observation, "schema_version", 1, 1) !== 1 ||
    requireString(observation, "expectation_sha256", 71, BATCH_DIGEST) !==
      binding.expectationSha256 ||
    requireString(observation, "observer_worker_version_id", 36, BATCH_UUID) !==
      binding.observerWorkerVersionId ||
    requireString(observation, "phase", 12) !== binding.phase ||
    requireString(observation, "observed_at", 24) !== observedAt
  ) {
    fail("CLOUDFLARE_EVIDENCE_BATCH_OBSERVATION_INVALID");
  }
  const providerDigest = requireString(
    observation,
    "provider_observation_sha256",
    71,
    BATCH_DIGEST,
  );
  const withoutDigest = { ...observation };
  delete withoutDigest.provider_observation_sha256;
  if (
    (await digestObject(withoutDigest)) !== providerDigest ||
    providerDigest !== providerDigestFromSlots(inputs)
  ) {
    fail("CLOUDFLARE_EVIDENCE_BATCH_OBSERVATION_INVALID");
  }
  if (!Array.isArray(observation.services) || observation.services.length !== inputs.length - 1) {
    fail("CLOUDFLARE_EVIDENCE_BATCH_OBSERVATION_INVALID");
  }
  for (let index = 0; index < observation.services.length; index += 1) {
    const input = requireSlot(inputs[index]);
    if (
      canonicalJson(observation.services[index]) !==
      canonicalJson(input.sanitized.record.service_observation)
    ) {
      fail("CLOUDFLARE_EVIDENCE_BATCH_OBSERVATION_INVALID");
    }
  }
  const network = requireSlot(inputs.at(-1));
  if (
    canonicalJson(observation.network_surface) !==
    canonicalJson(network.sanitized.record.network_surface_observation)
  ) {
    fail("CLOUDFLARE_EVIDENCE_BATCH_OBSERVATION_INVALID");
  }
  const bytes = canonicalBytes(observation);
  assertSanitizedCloudflareProjectionBytes(bytes, MAX_STORED_CLOUDFLARE_OBSERVATION_BYTES);
  return decodeCanonicalBatchObject(Uint8Array.from(bytes).buffer);
}

export function validateCloudflareEvidenceBatchExecution(
  execution: CloudflareEvidenceBatchExecution,
): void {
  if (
    !B2_OBSERVER_IDENTITY.test(execution.b2ObserverServiceIdentity) ||
    !BATCH_UUID.test(execution.b2ObserverWorkerVersionId) ||
    !execution.b2ObserverServiceIdentity.endsWith(`@${execution.b2ObserverWorkerVersionId}`) ||
    !WORM_IDENTITY.test(execution.wormServiceIdentity) ||
    !BATCH_UUID.test(execution.wormWorkerVersionId) ||
    !execution.wormServiceIdentity.endsWith(`@${execution.wormWorkerVersionId}`)
  ) {
    fail("CLOUDFLARE_EVIDENCE_BATCH_EXECUTION_INVALID");
  }
}

export function decodeCloudflareEvidenceBatchContext(
  row: CloudflareEvidenceBatchRow,
): CloudflareEvidenceBatchContext {
  const common: CloudflareEvidenceBatchBinding = {
    batchId: exactDigest(row.batch_id),
    expectationSha256: exactDigest(row.expectation_sha256),
    observerWorkerVersionId: exact(row.observer_worker_version_id, BATCH_UUID),
    phase: exactPhase(row.phase),
  };
  const binding = decodeBinding(row, common);
  const execution: CloudflareEvidenceBatchExecution = {
    b2ObserverServiceIdentity: row.b2_observer_service_identity,
    b2ObserverWorkerVersionId: row.b2_observer_worker_version_id,
    wormServiceIdentity: row.worm_service_identity,
    wormWorkerVersionId: row.worm_worker_version_id,
  };
  validateCloudflareEvidenceBatchExecution(execution);
  return {
    binding,
    committedAt: exactTimestamp(row.committed_at),
    execution,
    observation: decodeCanonicalBatchObject(row.observation_canonical_bytes),
    observedAt: exactTimestamp(row.observed_at),
    operation: decodeOperationContext(row, binding, execution),
    providerObservationSha256: exactDigest(row.provider_observation_sha256),
  };
}

function decodeOperationContext(
  row: CloudflareEvidenceBatchRow,
  binding: AnyCloudflareEvidenceBatchBinding,
  execution: CloudflareEvidenceBatchExecution,
): CloudflareEvidenceBatchContext["operation"] {
  if (!("activationIssuanceId" in binding)) return null;
  if (
    row.cloudflare_observer_service_identity === null ||
    row.delegation_sha256 === null ||
    row.delegation_committed_at === null ||
    row.delegation_issued_at === null ||
    row.delegation_fresh_until === null
  ) {
    fail("CLOUDFLARE_EVIDENCE_BATCH_STORED_INVALID");
  }
  return {
    authorityPins: {
      b2ObserverServiceIdentity: execution.b2ObserverServiceIdentity,
      b2ObserverWorkerVersionId: execution.b2ObserverWorkerVersionId,
      cloudflareObserverServiceIdentity: row.cloudflare_observer_service_identity,
      cloudflareObserverWorkerVersionId: binding.observerWorkerVersionId,
      wormServiceIdentity: execution.wormServiceIdentity,
      wormWorkerVersionId: execution.wormWorkerVersionId,
    },
    committedAt: exactTimestamp(row.delegation_committed_at),
    delegationSha256: exactDigest(row.delegation_sha256),
    freshUntil: exactTimestamp(row.delegation_fresh_until),
    issuedAt: exactTimestamp(row.delegation_issued_at),
  };
}

function decodeBinding(
  row: CloudflareEvidenceBatchRow,
  common: CloudflareEvidenceBatchBinding,
): AnyCloudflareEvidenceBatchBinding {
  if (row.binding_schema_version === 1) {
    if (
      row.activation_issuance_id !== null ||
      row.activation_issuance_ordinal !== null ||
      row.activation_sequence !== null
    ) {
      fail("CLOUDFLARE_EVIDENCE_BATCH_STORED_INVALID");
    }
    return common;
  }
  if (
    row.binding_schema_version !== 2 ||
    row.activation_issuance_id === null ||
    !BATCH_DIGEST.test(row.activation_issuance_id) ||
    !Number.isSafeInteger(row.activation_issuance_ordinal) ||
    row.activation_issuance_ordinal === null ||
    row.activation_issuance_ordinal < 1 ||
    row.activation_issuance_ordinal > 1_000_000 ||
    (row.activation_sequence !== 0 && row.activation_sequence !== 1)
  ) {
    fail("CLOUDFLARE_EVIDENCE_BATCH_STORED_INVALID");
  }
  return {
    ...common,
    activationIssuanceId: row.activation_issuance_id,
    activationIssuanceOrdinal: row.activation_issuance_ordinal,
    activationSequence: row.activation_sequence,
  } satisfies CloudflareEvidenceBatchBindingV2;
}

export function decodeCanonicalBatchObject(value: ArrayBuffer): JsonObject {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(value));
    const decoded: unknown = JSON.parse(text);
    if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded))
      throw new Error();
    const record = decoded as JsonObject;
    if (canonicalJson(record) !== text) throw new Error();
    return record;
  } catch {
    fail("CLOUDFLARE_EVIDENCE_BATCH_STORED_INVALID");
  }
}

export function assertSanitizedCloudflareProjectionBytes(bytes: Uint8Array, maximum: number): void {
  const text = new TextDecoder().decode(bytes);
  if (
    bytes.byteLength === 0 ||
    bytes.byteLength > maximum ||
    /raw_body_base64|author_email|author_id|workers\/message|workers\/triggered_by/iu.test(text) ||
    /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/iu.test(text)
  ) {
    fail("CLOUDFLARE_EVIDENCE_BATCH_PRIVACY_INVALID");
  }
}

function providerDigestFromSlots(inputs: readonly CloudflareEvidenceBatchSlotInput[]): string {
  const values = inputs.map((input) => input.sanitized.record.provider_observation_sha256);
  const first = values[0];
  if (
    typeof first !== "string" ||
    !BATCH_DIGEST.test(first) ||
    values.some((value) => value !== first)
  ) {
    fail("CLOUDFLARE_EVIDENCE_BATCH_PROVIDER_DIGEST_INVALID");
  }
  return first;
}

function requireSlot(
  value: CloudflareEvidenceBatchSlotInput | undefined,
): CloudflareEvidenceBatchSlotInput {
  if (value === undefined) fail("CLOUDFLARE_EVIDENCE_BATCH_SLOT_ORDER_INVALID");
  return value;
}

function exactDigest(value: string): string {
  return exact(value, BATCH_DIGEST);
}

function exactTimestamp(value: string): string {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    fail("CLOUDFLARE_EVIDENCE_BATCH_STORED_INVALID");
  }
  return value;
}

function exactPhase(value: string): string {
  if (value !== "A0_PRE" && value !== "A1_PRECOMMIT") {
    fail("CLOUDFLARE_EVIDENCE_BATCH_STORED_INVALID");
  }
  return value;
}

function exact(value: string, pattern: RegExp): string {
  if (!pattern.test(value)) fail("CLOUDFLARE_EVIDENCE_BATCH_STORED_INVALID");
  return value;
}

function fail(code: string): never {
  throw new BrokerError(code, 409, false);
}
