import {
  ACTIVATION_RECORD_V2_UUID,
  decodeActivationRecordV2Bytes,
  recordV2Fail,
} from "./activation-record-v2-codec";
import type { ActivationRecordV2Sequence } from "./activation-record-v2-contract";
import { canonicalBytes, digestObject, sha256Hex } from "./canonical";
import type { JsonObject } from "./types";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const KEY =
  /^receipts\/v2\/activation\/([0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})\/([01])-([0-9a-f]{64})\.json$/u;

/** Self-ID excludes only `record_id`; every other compact field is committed. */
export function activationRecordV2SelfId(document: JsonObject): Promise<string> {
  const body = { ...document };
  delete body.record_id;
  return digestObject(body);
}

/** Full digest helper for an already materialized data-only document. */
export async function activationRecordV2DocumentFullDigest(document: JsonObject): Promise<string> {
  return `sha256:${await sha256Hex(canonicalBytes(document))}`;
}

/** Full digest helper for externally supplied canonical compact-v2 bytes. */
export async function activationRecordV2FullDigest(input: Uint8Array): Promise<string> {
  const decoded = decodeActivationRecordV2Bytes(input);
  return `sha256:${await sha256Hex(decoded.bytes)}`;
}

/** Candidate-only WORM namespace. Runtime B2 policy is intentionally not modified. */
export function activationRecordV2WormKey(
  workerVersionId: string,
  sequence: ActivationRecordV2Sequence,
  recordSha256: string,
): string {
  if (
    !ACTIVATION_RECORD_V2_UUID.test(workerVersionId) ||
    !isRecordV2Sequence(sequence) ||
    !DIGEST.test(recordSha256)
  ) {
    recordV2Fail("ACTIVATION_RECORD_V2_WORM_KEY_INVALID");
  }
  return (
    `receipts/v2/activation/${workerVersionId}/${sequence}-` +
    `${recordSha256.slice("sha256:".length)}.json`
  );
}

function isRecordV2Sequence(value: unknown): value is ActivationRecordV2Sequence {
  return value === 0 || value === 1;
}

/** Closed candidate key policy suitable for a future injected generic-effect adapter. */
export function isActivationRecordV2WormKey(
  key: string,
  expected?: {
    readonly recordSha256: string;
    readonly sequence: ActivationRecordV2Sequence;
    readonly workerVersionId: string;
  },
): boolean {
  const match = KEY.exec(key);
  if (match === null) return false;
  if (expected === undefined) return true;
  return (
    match[1] === expected.workerVersionId &&
    Number(match[2]) === expected.sequence &&
    `sha256:${match[3]}` === expected.recordSha256
  );
}
