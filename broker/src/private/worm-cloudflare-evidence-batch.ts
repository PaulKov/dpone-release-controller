import {
  assertCanonicalCloudflareEvidenceBatchText,
  MAX_CLOUDFLARE_EVIDENCE_BATCH_RPC_BYTES,
} from "../cloudflare-evidence-batch-rpc";
import {
  buildCloudflareEvidenceBatchResumeMissingV2,
  parseCloudflareEvidenceBatchResumeV2,
} from "../cloudflare-evidence-batch-resume-v2";
import { BrokerError } from "../errors";
import {
  type WormMirrorEnv,
  assertExpectedB2ObserverPin,
  canonicalResponse,
  exactHeader,
  observerPinFromHeaders,
  TAGGED_DIGEST,
  TIMESTAMP,
} from "./worm-mirror-worker-helpers";

/** Delegate one authenticated transient batch to its deterministic WORM DO. */
export async function handleCloudflareEvidenceBatch(
  canonicalRequest: string,
  headers: Headers,
  env: WormMirrorEnv,
  version: 1 | 2 = 1,
): Promise<Response> {
  const batchId = exactHeader(headers, "x-dpone-batch-id", TAGGED_DIGEST, 71);
  const committedAt =
    version === 1 ? exactHeader(headers, "x-dpone-committed-at", TIMESTAMP, 24) : null;
  const namespace = env.CLOUDFLARE_EVIDENCE_BATCHES;
  if (namespace === undefined || typeof namespace.getByName !== "function") {
    throw new BrokerError("CLOUDFLARE_EVIDENCE_BATCH_UNAVAILABLE", 503, true);
  }
  const observerPin = observerPinFromHeaders(headers);
  assertExpectedB2ObserverPin(observerPin, env);
  const stub = namespace.getByName(batchId);
  const result =
    version === 1
      ? await stub.mirrorBatch(
          canonicalRequest,
          batchId,
          requireCommittedAt(committedAt),
          observerPin,
        )
      : await stub.mirrorBatchV2(canonicalRequest, batchId, observerPin);
  const parsed = assertCanonicalCloudflareEvidenceBatchText(result);
  const bytes = new TextEncoder().encode(result);
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_CLOUDFLARE_EVIDENCE_BATCH_RPC_BYTES) {
    throw new BrokerError("CLOUDFLARE_EVIDENCE_BATCH_RESULT_SIZE_INVALID", 503, false);
  }
  if (parsed.batch_id !== batchId) {
    throw new BrokerError("CLOUDFLARE_EVIDENCE_BATCH_RESULT_BINDING_INVALID", 503, false);
  }
  return canonicalResponse(parsed);
}

/** Resolve an existing v2 batch without accepting any transient provider evidence. */
export async function handleCloudflareEvidenceBatchResume(
  canonicalRequest: string,
  headers: Headers,
  env: WormMirrorEnv,
): Promise<Response> {
  const request = assertCanonicalCloudflareEvidenceBatchText(canonicalRequest);
  const expected = parseCloudflareEvidenceBatchResumeV2(request);
  const batchId = exactHeader(headers, "x-dpone-batch-id", TAGGED_DIGEST, 71);
  if (batchId !== expected.binding.batchId) {
    throw new BrokerError("CLOUDFLARE_EVIDENCE_BATCH_BINDING_INVALID", 400, false);
  }
  const namespace = env.CLOUDFLARE_EVIDENCE_BATCHES;
  if (namespace === undefined || typeof namespace.getByName !== "function") {
    throw new BrokerError("CLOUDFLARE_EVIDENCE_BATCH_UNAVAILABLE", 503, true);
  }
  const observerPin = observerPinFromHeaders(headers);
  assertExpectedB2ObserverPin(observerPin, env);
  const result = await namespace.getByName(batchId).resumeBatchV2(canonicalRequest, observerPin);
  return result === null
    ? canonicalResponse(buildCloudflareEvidenceBatchResumeMissingV2(expected))
    : canonicalResponse(assertCanonicalCloudflareEvidenceBatchText(result));
}

function requireCommittedAt(value: string | null): string {
  if (value === null) {
    throw new BrokerError("CLOUDFLARE_EVIDENCE_BATCH_TIME_INVALID", 400, false);
  }
  return value;
}
