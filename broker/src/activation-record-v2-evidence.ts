import {
  ACTIVATION_ATTEMPT_V2_SCHEMA,
  ACTIVATION_FINALIZE_REQUEST_V2_SCHEMA,
  ACTIVATION_ISSUANCE_V2_SCHEMA,
  ACTIVATION_PROVISION_INTENT_V2_SCHEMA,
  ACTIVATION_RECORD_V2_DIRECT_KINDS,
  ACTIVATION_RECORD_V2_DIRECT_SLOTS,
  ACTIVATION_RECORD_V2_MAX_ISSUANCE_ORDINAL,
  ACTIVATION_RECORD_V2_RETENTION_DAYS,
  type ActivationRecordV2Sequence,
} from "./activation-record-v2-contract";
import {
  ACTIVATION_RECORD_V2_DIGEST,
  ACTIVATION_RECORD_V2_UUID,
  ACTIVATION_RECORD_V2_VERSION,
  exactRecordV2Array,
  exactRecordV2Object,
  recordV2Digest,
  recordV2Fail,
  recordV2Integer,
  recordV2Literal,
  recordV2String,
  recordV2Timestamp,
} from "./activation-record-v2-codec";
import {
  activationComponentJournalSessionId,
  journalFreshUntil,
} from "./activation-component-journal-validation";
import { canonicalBytes, digestObject } from "./canonical";
import type { JsonObject } from "./types";

const WORM_FIELDS = ["digest", "key", "retention_until", "version_id"] as const;
const OPERATION_FIELDS = [
  "attempt_id",
  "fresh_until",
  "internal_request_id",
  "intent_sha256",
  "issuance_id",
  "issuance_ordinal",
  "issued_at",
] as const;

export interface ParsedActivationRecordV2Operation {
  readonly freshUntil: string;
  readonly internalRequestId: string;
  readonly issuanceId: string;
  readonly issuanceOrdinal: number;
  readonly issuedAt: string;
}

export interface ParsedActivationRecordV2Worm {
  readonly digest: string;
  readonly key: string;
  readonly retentionUntil: string;
  readonly versionId: string;
}

/** Validate and project the selected journal/resolver commitments used by the A0 intent. */
export async function validateActivationRecordV2ComponentAuthority(
  value: unknown,
  workerVersionId: string,
): Promise<{ readonly intent: JsonObject; readonly descriptorCommittedAt: string }> {
  const authority = exactRecordV2Object(value, [
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
  const descriptorCommittedAt = recordV2Timestamp(descriptor, "committed_at");
  const descriptorId = recordV2Digest(descriptor, "descriptor_id");
  const descriptorSha256 = recordV2Digest(descriptor, "descriptor_sha256");
  const setId = recordV2Digest(descriptor, "set_id");
  if (
    recordV2String(descriptor, "worker_version_id", ACTIVATION_RECORD_V2_UUID, 36) !==
    workerVersionId
  ) {
    recordV2Fail("ACTIVATION_RECORD_V2_COMPONENT_TRANSPLANT");
  }
  const pointer = exactRecordV2Object(authority.manifest_pointer, [
    "manifest_id",
    "manifest_sha256",
    "worm",
  ]);
  const manifestId = recordV2Digest(pointer, "manifest_id");
  const manifestSha256 = recordV2Digest(pointer, "manifest_sha256");
  const expectedManifestKey =
    `receipts/v2/activation-component-manifests/${workerVersionId}/` +
    `${setId.slice(7)}/${manifestId.slice(7)}/${manifestSha256.slice(7)}.json`;
  validateActivationRecordV2Worm(
    pointer.worm,
    manifestSha256,
    descriptorCommittedAt,
    expectedManifestKey,
  );
  const pointerSha256 = recordV2Digest(authority, "manifest_pointer_sha256");
  if (pointerSha256 !== (await digestObject(pointer))) {
    recordV2Fail("ACTIVATION_RECORD_V2_COMPONENT_TRANSPLANT");
  }
  const resolvedProjectionSha256 = recordV2Digest(authority, "resolved_projection_sha256");
  const session = exactRecordV2Object(authority.session, [
    "fresh_until",
    "generation",
    "journal_ordinal",
    "predecessor_session_id",
    "session_id",
    "state",
  ]);
  recordV2Literal(session, "state", "SELECTED");
  const freshUntil = recordV2Timestamp(session, "fresh_until");
  const generation = recordV2Integer(session, "generation", 1, 8);
  const journalOrdinal = recordV2Integer(session, "journal_ordinal", 1, 8);
  const predecessor = session.predecessor_session_id;
  if (
    (generation === 1 && predecessor !== null) ||
    (generation > 1 &&
      (typeof predecessor !== "string" || !ACTIVATION_RECORD_V2_DIGEST.test(predecessor))) ||
    freshUntil !== journalFreshUntil(descriptorCommittedAt)
  ) {
    recordV2Fail("ACTIVATION_RECORD_V2_COMPONENT_SESSION_INVALID");
  }
  const sessionId = recordV2Digest(session, "session_id");
  const rebuiltSessionId = await activationComponentJournalSessionId(
    workerVersionId,
    setId,
    descriptorId,
    descriptorSha256,
    generation,
    journalOrdinal,
    predecessor as string | null,
  );
  if (sessionId !== rebuiltSessionId) {
    recordV2Fail("ACTIVATION_RECORD_V2_COMPONENT_SESSION_INVALID");
  }
  return {
    descriptorCommittedAt,
    intent: {
      descriptor_id: descriptorId,
      descriptor_sha256: descriptorSha256,
      manifest_pointer: pointer,
      manifest_pointer_sha256: pointerSha256,
      resolved_projection_sha256: resolvedProjectionSha256,
      selected_session_id: sessionId,
      set_id: setId,
      worker_version_id: workerVersionId,
    },
  };
}

export async function activationRecordV2IntentSha256(
  semantic: JsonObject,
  sequence: ActivationRecordV2Sequence,
): Promise<string> {
  const document =
    sequence === 0
      ? {
          component_authority: semantic,
          schema: ACTIVATION_PROVISION_INTENT_V2_SCHEMA,
          schema_version: 2,
        }
      : {
          approvals: semantic.approvals ?? null,
          promotion: semantic.promotion ?? null,
          provisioned: semantic.provisioned ?? null,
          schema: ACTIVATION_FINALIZE_REQUEST_V2_SCHEMA,
          schema_version: 2,
          target: semantic.target ?? null,
        };
  return digestObject(document);
}

export async function activationRecordV2AttemptId(
  intentSha256: string,
  sequence: ActivationRecordV2Sequence,
  workerVersionId: string,
): Promise<string> {
  if (
    !ACTIVATION_RECORD_V2_DIGEST.test(intentSha256) ||
    !ACTIVATION_RECORD_V2_UUID.test(workerVersionId)
  ) {
    recordV2Fail("ACTIVATION_RECORD_V2_OPERATION_INVALID");
  }
  return digestObject({
    intent_sha256: intentSha256,
    schema: ACTIVATION_ATTEMPT_V2_SCHEMA,
    schema_version: 2,
    sequence,
    worker_version_id: workerVersionId,
  });
}

export async function activationRecordV2IssuanceId(
  attemptId: string,
  ordinal: number,
): Promise<string> {
  if (
    !ACTIVATION_RECORD_V2_DIGEST.test(attemptId) ||
    !Number.isSafeInteger(ordinal) ||
    ordinal < 1 ||
    ordinal > ACTIVATION_RECORD_V2_MAX_ISSUANCE_ORDINAL
  ) {
    recordV2Fail("ACTIVATION_RECORD_V2_OPERATION_INVALID");
  }
  return digestObject({
    attempt_id: attemptId,
    broker_issued_ordinal: ordinal,
    schema: ACTIVATION_ISSUANCE_V2_SCHEMA,
    schema_version: 2,
  });
}

export async function validateActivationRecordV2Operation(
  value: unknown,
  expectedIntentSha256: string,
  sequence: ActivationRecordV2Sequence,
  workerVersionId: string,
): Promise<ParsedActivationRecordV2Operation> {
  const operation = exactRecordV2Object(value, OPERATION_FIELDS);
  const intentSha256 = recordV2Digest(operation, "intent_sha256");
  const attemptId = recordV2Digest(operation, "attempt_id");
  const issuanceId = recordV2Digest(operation, "issuance_id");
  const issuanceOrdinal = recordV2Integer(
    operation,
    "issuance_ordinal",
    1,
    ACTIVATION_RECORD_V2_MAX_ISSUANCE_ORDINAL,
  );
  const issuedAt = recordV2Timestamp(operation, "issued_at");
  const freshUntil = recordV2Timestamp(operation, "fresh_until");
  if (
    intentSha256 !== expectedIntentSha256 ||
    attemptId !== (await activationRecordV2AttemptId(intentSha256, sequence, workerVersionId)) ||
    issuanceId !== (await activationRecordV2IssuanceId(attemptId, issuanceOrdinal)) ||
    recordV2String(operation, "internal_request_id", /^activation-[0-9a-f]{64}$/u, 75) !==
      `activation-${issuanceId.slice(7)}` ||
    Date.parse(issuedAt) >= Date.parse(freshUntil)
  ) {
    recordV2Fail("ACTIVATION_RECORD_V2_OPERATION_INVALID");
  }
  return {
    freshUntil,
    internalRequestId: `activation-${issuanceId.slice(7)}`,
    issuanceId,
    issuanceOrdinal,
    issuedAt,
  };
}

/** Validate the four fixed A0 pointers. Evidence bodies and executor pins remain off-record. */
export function validateActivationRecordV2DirectEvidence(
  value: unknown,
  workerVersionId: string,
  committedAt: string,
): void {
  const rows = exactRecordV2Array(value, ACTIVATION_RECORD_V2_DIRECT_SLOTS.length);
  const keys: string[] = [];
  const versions: string[] = [];
  rows.forEach((candidate, index) => {
    const row = exactRecordV2Object(candidate, [
      "absence_inventory_sha256",
      "effect_id",
      "evidence_sha256",
      "provider_request_sha256",
      "result_sha256",
      "slot_id",
      "worm",
    ]);
    const slot = ACTIVATION_RECORD_V2_DIRECT_SLOTS[index];
    const kind = ACTIVATION_RECORD_V2_DIRECT_KINDS[index];
    if (slot === undefined || kind === undefined || row.slot_id !== slot) {
      recordV2Fail("ACTIVATION_RECORD_V2_DIRECT_ORDER_INVALID");
    }
    recordV2Digest(row, "absence_inventory_sha256");
    recordV2Digest(row, "effect_id");
    const evidenceSha256 = recordV2Digest(row, "evidence_sha256");
    recordV2Digest(row, "provider_request_sha256");
    recordV2Digest(row, "result_sha256");
    const key =
      `receipts/v2/activation-evidence/${workerVersionId}/${kind}/` +
      `${evidenceSha256.slice(7)}.json`;
    const worm = validateActivationRecordV2Worm(row.worm, evidenceSha256, committedAt, key);
    keys.push(worm.key);
    versions.push(worm.versionId);
  });
  assertUnique(keys, versions);
}

export function validateActivationRecordV2Worm(
  value: unknown,
  expectedDigest: string,
  committedAt: string,
  expectedKey?: string,
): ParsedActivationRecordV2Worm {
  const parsed = parseActivationRecordV2Worm(value, expectedDigest, expectedKey);
  if (
    Date.parse(parsed.retentionUntil) <
    Date.parse(committedAt) + ACTIVATION_RECORD_V2_RETENTION_DAYS * 86_400_000
  ) {
    recordV2Fail("ACTIVATION_RECORD_V2_WORM_INVALID");
  }
  return parsed;
}

/** Parse a pointer whose retention base must be supplied by a resolved predecessor. */
export function parseActivationRecordV2Worm(
  value: unknown,
  expectedDigest: string,
  expectedKey?: string,
): ParsedActivationRecordV2Worm {
  const worm = exactRecordV2Object(value, WORM_FIELDS);
  const digest = recordV2Digest(worm, "digest");
  const key = recordV2String(worm, "key");
  const retentionUntil = recordV2Timestamp(worm, "retention_until");
  const versionId = recordV2String(worm, "version_id", ACTIVATION_RECORD_V2_VERSION);
  if (digest !== expectedDigest || (expectedKey !== undefined && key !== expectedKey)) {
    recordV2Fail("ACTIVATION_RECORD_V2_WORM_INVALID");
  }
  return { digest, key, retentionUntil, versionId };
}

export function activationRecordV2CanonicalDigest(value: JsonObject): Promise<string> {
  return digestObject(value);
}

export function activationRecordV2CanonicalBytes(value: JsonObject): Uint8Array {
  return canonicalBytes(value);
}

function assertUnique(keys: readonly string[], versions: readonly string[]): void {
  if (new Set(keys).size !== keys.length || new Set(versions).size !== versions.length) {
    recordV2Fail("ACTIVATION_RECORD_V2_WORM_ALIAS_INVALID");
  }
}
