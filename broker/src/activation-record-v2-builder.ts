import {
  ACTIVATION_ACTIVATED_RECORD_V2_SCHEMA,
  ACTIVATION_PROVISIONED_RECORD_V2_SCHEMA,
  ACTIVATION_RECORD_V2_BODY_FIELDS,
  ACTIVATION_RECORD_V2_RETENTION_DAYS,
  ACTIVATION_RECORD_V2_ROOT_FIELDS,
  type ActivationRecordV2Sequence,
  type UntrustedActivationRecordV2,
  type UntrustedActivationRecordV2Chain,
} from "./activation-record-v2-contract";
import {
  ACTIVATION_RECORD_V2_UUID,
  decodeActivationRecordV2Bytes,
  exactRecordV2Object,
  freezeRecordV2Json,
  recordV2Digest,
  recordV2Fail,
  recordV2Literal,
  recordV2String,
  recordV2Timestamp,
  snapshotActivationRecordV2Data,
} from "./activation-record-v2-codec";
import {
  activationRecordV2IntentSha256,
  validateActivationRecordV2ComponentAuthority,
  validateActivationRecordV2DirectEvidence,
  validateActivationRecordV2Operation,
} from "./activation-record-v2-evidence";
import { validateActivationRecordV2Finalize } from "./activation-record-v2-finalize";
import {
  activationRecordV2DocumentFullDigest,
  activationRecordV2SelfId,
} from "./activation-record-v2-identity";
import { validateActivationRecordV2ServiceAuthority } from "./activation-record-v2-service";
import { canonicalBytes } from "./canonical";
import type { JsonObject } from "./types";

/** Build an untrusted A0 structural value from a closed data-only body. */
export function buildActivationProvisionedRecordV2(
  input: JsonObject,
): Promise<UntrustedActivationRecordV2> {
  return buildActivationRecordV2(input, 0);
}

/** Build an untrusted A1 structural value from a closed data-only body. */
export function buildActivationActivatedRecordV2(
  input: JsonObject,
): Promise<UntrustedActivationRecordV2> {
  return buildActivationRecordV2(input, 1);
}

export async function parseActivationProvisionedRecordV2(
  input: Uint8Array,
): Promise<UntrustedActivationRecordV2> {
  const decoded = decodeActivationRecordV2Bytes(input);
  return validateDecodedRecord(decoded.bytes, decoded.document, 0);
}

export async function parseActivationActivatedRecordV2(
  input: Uint8Array,
): Promise<UntrustedActivationRecordV2> {
  const decoded = decodeActivationRecordV2Bytes(input);
  return validateDecodedRecord(decoded.bytes, decoded.document, 1);
}

/** Dispatch only the two v2 schemas; legacy or mixed-version records fail closed. */
export async function parseActivationRecordV2(
  input: Uint8Array,
): Promise<UntrustedActivationRecordV2> {
  const decoded = decodeActivationRecordV2Bytes(input);
  const schema = decoded.document.schema;
  if (schema === ACTIVATION_PROVISIONED_RECORD_V2_SCHEMA) {
    return validateDecodedRecord(decoded.bytes, decoded.document, 0);
  }
  if (schema === ACTIVATION_ACTIVATED_RECORD_V2_SCHEMA) {
    return validateDecodedRecord(decoded.bytes, decoded.document, 1);
  }
  recordV2Fail("ACTIVATION_RECORD_V2_SCHEMA_INVALID");
}

/** Parse and cross-bind one exact A0-v2 -> A1-v2 chain. */
export async function parseActivationRecordV2Chain(
  provisionedBytes: Uint8Array,
  activatedBytes: Uint8Array,
): Promise<UntrustedActivationRecordV2Chain> {
  const provisioned = await parseActivationRecordV2(provisionedBytes);
  const activated = await parseActivationRecordV2(activatedBytes);
  if (provisioned.sequence !== 0 || activated.sequence !== 1) {
    recordV2Fail("ACTIVATION_RECORD_V2_MIXED_CHAIN");
  }
  validateChain(provisioned, activated);
  return Object.freeze({ activated, provisioned, trust: "UNTRUSTED" as const });
}

async function buildActivationRecordV2(
  input: JsonObject,
  sequence: ActivationRecordV2Sequence,
): Promise<UntrustedActivationRecordV2> {
  const body = exactRecordV2Object(
    snapshotActivationRecordV2Data(input),
    ACTIVATION_RECORD_V2_BODY_FIELDS[sequence],
  );
  const recordId = await activationRecordV2SelfId(body);
  const document: JsonObject = { ...body, record_id: recordId };
  const bytes = canonicalBytes(document);
  return sequence === 0
    ? parseActivationProvisionedRecordV2(bytes)
    : parseActivationActivatedRecordV2(bytes);
}

async function validateDecodedRecord(
  bytes: Uint8Array,
  input: JsonObject,
  sequence: ActivationRecordV2Sequence,
): Promise<UntrustedActivationRecordV2> {
  const document = exactRecordV2Object(input, ACTIVATION_RECORD_V2_ROOT_FIELDS[sequence]);
  const schema =
    sequence === 0
      ? ACTIVATION_PROVISIONED_RECORD_V2_SCHEMA
      : ACTIVATION_ACTIVATED_RECORD_V2_SCHEMA;
  recordV2Literal(document, "schema", schema);
  recordV2Literal(document, "schema_version", 2);
  recordV2Literal(document, "sequence", sequence);
  recordV2Literal(document, "fencing_token", sequence + 1);
  const workerVersionId = recordV2String(
    document,
    "worker_version_id",
    ACTIVATION_RECORD_V2_UUID,
    36,
  );
  const committedAt = recordV2Timestamp(document, "committed_at");
  if (recordV2Timestamp(document, "observed_at") !== committedAt) {
    recordV2Fail("ACTIVATION_RECORD_V2_TIME_INVALID");
  }
  if (sequence === 0) {
    await validateProvisioned(document, workerVersionId, committedAt);
  } else {
    await validateActivated(document, workerVersionId, committedAt);
  }
  const recordId = recordV2Digest(document, "record_id");
  if (recordId !== (await activationRecordV2SelfId(document))) {
    recordV2Fail("ACTIVATION_RECORD_V2_SELF_ID_INVALID");
  }
  const recordSha256 = await activationRecordV2DocumentFullDigest(document);
  const stableBytes = Uint8Array.from(bytes);
  const stableDocument = freezeRecordV2Json(document);
  return Object.freeze({
    get canonicalBytes(): Uint8Array {
      return Uint8Array.from(stableBytes);
    },
    document: stableDocument,
    recordId,
    recordSha256,
    sequence,
    trust: "UNTRUSTED" as const,
  });
}

async function validateProvisioned(
  document: JsonObject,
  workerVersionId: string,
  committedAt: string,
): Promise<void> {
  recordV2Literal(document, "previous", "GENESIS");
  const component = await validateActivationRecordV2ComponentAuthority(
    document.component_authority,
    workerVersionId,
  );
  const intentSha256 = await activationRecordV2IntentSha256(component.intent, 0);
  const operation = await validateActivationRecordV2Operation(
    document.operation,
    intentSha256,
    0,
    workerVersionId,
  );
  const service = await validateActivationRecordV2ServiceAuthority(
    document.service_authority,
    0,
    committedAt,
    operation,
  );
  validateActivationRecordV2DirectEvidence(
    document.provider_evidence,
    workerVersionId,
    service.delegationCommittedAt,
  );
  if (Date.parse(component.descriptorCommittedAt) > Date.parse(operation.issuedAt)) {
    recordV2Fail("ACTIVATION_RECORD_V2_TIME_INVALID");
  }
}

async function validateActivated(
  document: JsonObject,
  workerVersionId: string,
  committedAt: string,
): Promise<void> {
  const previous = recordV2Digest(document, "previous");
  const finalize = validateActivationRecordV2Finalize(document, workerVersionId);
  if (previous !== finalize.provisionedRecordId) {
    recordV2Fail("ACTIVATION_RECORD_V2_PREDECESSOR_INVALID");
  }
  const intentSha256 = await activationRecordV2IntentSha256(finalize.semantic, 1);
  const operation = await validateActivationRecordV2Operation(
    document.operation,
    intentSha256,
    1,
    workerVersionId,
  );
  await validateActivationRecordV2ServiceAuthority(
    document.service_authority,
    1,
    committedAt,
    operation,
  );
  if (Date.parse(finalize.completedAt) > Date.parse(operation.issuedAt)) {
    recordV2Fail("ACTIVATION_RECORD_V2_TIME_INVALID");
  }
}

function validateChain(
  provisioned: UntrustedActivationRecordV2,
  activated: UntrustedActivationRecordV2,
): void {
  const a0 = provisioned.document;
  const a1 = activated.document;
  const pointer = exactRecordV2Object(a1.provisioned, [
    "component_set_id",
    "manifest_pointer_sha256",
    "record_id",
    "record_sha256",
    "resolved_projection_sha256",
    "worker_version_id",
    "worm",
  ]);
  const authority = exactRecordV2Object(a0.component_authority, [
    "descriptor",
    "manifest_pointer",
    "manifest_pointer_sha256",
    "resolved_projection_sha256",
    "session",
  ]);
  const descriptor = exactRecordV2Object(authority.descriptor, [
    "committed_at",
    "descriptor_id",
    "descriptor_sha256",
    "set_id",
    "worker_version_id",
  ]);
  const promotion = exactRecordV2Object(a1.promotion, [
    "completed_at",
    "deployment_id",
    "promotion_report_record_id",
    "promotion_report_record_sha256",
    "promotion_report_worm",
    "provider_observation_sha256",
    "started_at",
    "worker_version_id",
  ]);
  const worm = exactRecordV2Object(pointer.worm, [
    "digest",
    "key",
    "retention_until",
    "version_id",
  ]);
  const a0CommittedAt = recordV2Timestamp(a0, "committed_at");
  const retentionUntil = recordV2Timestamp(worm, "retention_until");
  if (
    a1.previous !== provisioned.recordId ||
    pointer.record_id !== provisioned.recordId ||
    pointer.record_sha256 !== provisioned.recordSha256 ||
    pointer.component_set_id !== descriptor.set_id ||
    pointer.manifest_pointer_sha256 !== authority.manifest_pointer_sha256 ||
    pointer.resolved_projection_sha256 !== authority.resolved_projection_sha256 ||
    pointer.worker_version_id !== a0.worker_version_id ||
    a1.worker_version_id !== a0.worker_version_id ||
    Date.parse(a0CommittedAt) >= Date.parse(recordV2Timestamp(promotion, "started_at")) ||
    Date.parse(retentionUntil) <
      Date.parse(a0CommittedAt) + ACTIVATION_RECORD_V2_RETENTION_DAYS * 86_400_000
  ) {
    recordV2Fail("ACTIVATION_RECORD_V2_CHAIN_INVALID");
  }
}
