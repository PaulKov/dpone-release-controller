import {
  ACTIVATION_ANCHOR_VECTOR_V2_SCHEMA,
  ACTIVATION_RECORD_V2_SERVICE_ROLES,
  CLOUDFLARE_BATCH_INTENT_V2_SCHEMA,
  type ActivationRecordV2Sequence,
} from "./activation-record-v2-contract";
import {
  ACTIVATION_RECORD_V2_UUID,
  exactRecordV2Array,
  exactRecordV2Object,
  recordV2Digest,
  recordV2Fail,
  recordV2Integer,
  recordV2Timestamp,
} from "./activation-record-v2-codec";
import {
  type ParsedActivationRecordV2Operation,
  validateActivationRecordV2Worm,
} from "./activation-record-v2-evidence";
import { digestObject } from "./canonical";
import type { JsonObject } from "./types";

const SERVICE_FIELDS = [
  "batch_id",
  "batch_result_sha256",
  "batch_sealed_at",
  "cloudflare_provider_observation_sha256",
  "delegation_committed_at",
  "delegation_sha256",
  "expectation_sha256",
  "observed_at",
  "phase",
  "provider_observation_sha256",
  "records",
  "records_sha256",
] as const;
const RECORD_FIELDS = [
  "authority_role",
  "kind",
  "record_id",
  "record_sha256",
  "slot_index",
  "worm",
] as const;

export interface ParsedActivationRecordV2ServiceAuthority {
  readonly batchId: string;
  readonly batchSealedAt: string;
  readonly delegationCommittedAt: string;
  readonly expectationSha256: string;
  readonly observedAt: string;
  readonly observerWorkerVersionId: string;
}

export async function activationRecordV2BatchId(
  issuanceId: string,
  issuanceOrdinal: number,
  sequence: ActivationRecordV2Sequence,
): Promise<string> {
  return digestObject({
    activation_issuance_id: issuanceId,
    activation_issuance_ordinal: issuanceOrdinal,
    activation_sequence: sequence,
    schema: CLOUDFLARE_BATCH_INTENT_V2_SCHEMA,
    schema_version: 2,
  });
}

export function activationRecordV2AnchorVectorDigest(records: JsonObject[]): Promise<string> {
  return digestObject({
    records,
    schema: ACTIVATION_ANCHOR_VECTOR_V2_SCHEMA,
    schema_version: 2,
  });
}

/** Validate the compact 14-service plus network anchor vector without fetching its bodies. */
export async function validateActivationRecordV2ServiceAuthority(
  value: unknown,
  sequence: ActivationRecordV2Sequence,
  rootCommittedAt: string,
  operation: ParsedActivationRecordV2Operation,
): Promise<ParsedActivationRecordV2ServiceAuthority> {
  const authority = exactRecordV2Object(value, SERVICE_FIELDS);
  const batchId = recordV2Digest(authority, "batch_id");
  recordV2Digest(authority, "batch_result_sha256");
  recordV2Digest(authority, "cloudflare_provider_observation_sha256");
  const delegationSha256 = recordV2Digest(authority, "delegation_sha256");
  const expectationSha256 = recordV2Digest(authority, "expectation_sha256");
  recordV2Digest(authority, "provider_observation_sha256");
  const delegationCommittedAt = recordV2Timestamp(authority, "delegation_committed_at");
  const observedAt = recordV2Timestamp(authority, "observed_at");
  const batchSealedAt = recordV2Timestamp(authority, "batch_sealed_at");
  const expectedPhase = sequence === 0 ? "A0_PRE" : "A1_PRECOMMIT";
  if (
    authority.phase !== expectedPhase ||
    batchId !==
      (await activationRecordV2BatchId(
        operation.issuanceId,
        operation.issuanceOrdinal,
        sequence,
      )) ||
    batchSealedAt !== rootCommittedAt ||
    Date.parse(operation.issuedAt) > Date.parse(delegationCommittedAt) ||
    Date.parse(delegationCommittedAt) > Date.parse(observedAt) ||
    Date.parse(observedAt) > Date.parse(batchSealedAt) ||
    Date.parse(batchSealedAt) > Date.parse(operation.freshUntil) ||
    Date.parse(batchSealedAt) - Date.parse(operation.issuedAt) > 60_000
  ) {
    recordV2Fail("ACTIVATION_RECORD_V2_SERVICE_BINDING_INVALID");
  }
  const records = exactRecordV2Array(
    authority.records,
    ACTIVATION_RECORD_V2_SERVICE_ROLES.length + 1,
  ).map((candidate, index) => validateRecord(candidate, index, batchId, batchSealedAt));
  const observerWorkers = records.map(({ observerWorkerVersionId }) => observerWorkerVersionId);
  if (new Set(observerWorkers).size !== 1) {
    recordV2Fail("ACTIVATION_RECORD_V2_SERVICE_OBSERVER_INVALID");
  }
  const recordsSha256 = recordV2Digest(authority, "records_sha256");
  if (
    recordsSha256 !== (await activationRecordV2AnchorVectorDigest(records.map(({ row }) => row)))
  ) {
    recordV2Fail("ACTIVATION_RECORD_V2_SERVICE_BINDING_INVALID");
  }
  assertUnique(
    records.map(({ recordId }) => recordId),
    records.map(({ recordSha256 }) => recordSha256),
    records.map(({ wormKey }) => wormKey),
    records.map(({ wormVersionId }) => wormVersionId),
  );
  if (delegationSha256 === expectationSha256) {
    recordV2Fail("ACTIVATION_RECORD_V2_SERVICE_ALIAS_INVALID");
  }
  const observerWorkerVersionId = observerWorkers[0];
  if (observerWorkerVersionId === undefined) {
    recordV2Fail("ACTIVATION_RECORD_V2_SERVICE_OBSERVER_INVALID", 500);
  }
  return {
    batchId,
    batchSealedAt,
    delegationCommittedAt,
    expectationSha256,
    observedAt,
    observerWorkerVersionId,
  };
}

function validateRecord(
  value: unknown,
  index: number,
  batchId: string,
  batchSealedAt: string,
): {
  readonly observerWorkerVersionId: string;
  readonly recordId: string;
  readonly recordSha256: string;
  readonly row: JsonObject;
  readonly wormKey: string;
  readonly wormVersionId: string;
} {
  const row = exactRecordV2Object(value, RECORD_FIELDS);
  const expectedRole = ACTIVATION_RECORD_V2_SERVICE_ROLES[index] ?? null;
  const expectedKind =
    expectedRole === null ? "cloudflare_network_surface" : "cloudflare_service_deployments";
  if (
    row.authority_role !== expectedRole ||
    row.kind !== expectedKind ||
    recordV2Integer(row, "slot_index", index, index) !== index
  ) {
    recordV2Fail("ACTIVATION_RECORD_V2_SERVICE_ORDER_INVALID");
  }
  const recordId = recordV2Digest(row, "record_id");
  const recordSha256 = recordV2Digest(row, "record_sha256");
  const worm = validateActivationRecordV2Worm(row.worm, recordSha256, batchSealedAt);
  const match = new RegExp(
    "^receipts/v1/cloudflare-observations-v2/" +
      "([0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})/" +
      `${batchId.slice(7)}/${expectedKind}/${recordId.slice(7)}\\.json$`,
    "u",
  ).exec(worm.key);
  const observerWorkerVersionId = match?.[1];
  if (
    observerWorkerVersionId === undefined ||
    !ACTIVATION_RECORD_V2_UUID.test(observerWorkerVersionId)
  ) {
    recordV2Fail("ACTIVATION_RECORD_V2_SERVICE_WORM_KEY_INVALID");
  }
  return {
    observerWorkerVersionId,
    recordId,
    recordSha256,
    row,
    wormKey: worm.key,
    wormVersionId: worm.versionId,
  };
}

function assertUnique(...vectors: readonly (readonly string[])[]): void {
  if (vectors.some((vector) => new Set(vector).size !== vector.length)) {
    recordV2Fail("ACTIVATION_RECORD_V2_SERVICE_ALIAS_INVALID");
  }
}
