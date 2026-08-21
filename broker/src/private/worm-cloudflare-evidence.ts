import { assertExactObjectAbsent, reconcileExactObject } from "../b2-exact-reconciliation";
import { B2VersionObserverClient } from "../b2-version-observer-client";
import { B2ExactObjectMirror } from "../b2";
import { canonicalJson } from "../canonical";
import {
  assertSanitizedCloudflareEvidenceRecord,
  CLOUDFLARE_DEPLOYMENT_EVIDENCE_KIND,
  sanitizeCloudflareNetworkEvidence,
  sanitizeCloudflareServiceEvidence,
  type SanitizedCloudflareEvidence,
} from "../cloudflare-deployment-observation";
import {
  CLOUDFLARE_EVIDENCE_WORM_ABSENCE_RESULT_SCHEMA,
  CLOUDFLARE_EVIDENCE_WORM_RESULT_SCHEMA,
} from "../cloudflare-evidence-worm-client";
import { BrokerError } from "../errors";
import type { JsonObject } from "../types";
import { requireString } from "../validation";
import { B2NativeWriter } from "./b2-native";
import {
  TAGGED_DIGEST,
  TIMESTAMP,
  VERSION,
  type WormMirrorEnv,
  assertExpectedB2ObserverPin,
  canonicalResponse,
  exactHeader,
  observerPinFromHeaders,
  requireConfig,
  requireVersionId,
} from "./worm-mirror-worker-helpers";

export type CloudflareEvidenceAction = "absence" | "mirror" | "reconcile";

/** Execute one closed Cloudflare evidence operation; raw bytes are never retained. */
export async function handleCloudflareEvidence(
  action: CloudflareEvidenceAction,
  body: JsonObject,
  headers: Headers,
  env: WormMirrorEnv,
): Promise<Response> {
  const kind = exactHeader(
    headers,
    "x-dpone-evidence-kind",
    /^(?:cloudflare_network_surface|cloudflare_service_deployments)$/u,
    64,
  );
  const sanitized = await sanitizeBody(action, kind, body);
  const expectedRecordId = exactHeader(headers, "x-dpone-record-id", TAGGED_DIGEST, 71);
  const expectedRecordSha256 = exactHeader(
    headers,
    "x-dpone-sanitized-record-sha256",
    TAGGED_DIGEST,
    71,
  );
  if (sanitized.recordId !== expectedRecordId || sanitized.recordSha256 !== expectedRecordSha256) {
    throw new BrokerError("CLOUDFLARE_EVIDENCE_SANITIZED_BINDING_INVALID", 400, false);
  }
  const committedAt = exactHeader(headers, "x-dpone-committed-at", TIMESTAMP, 32);
  assertEvidenceChronology(sanitized.record, committedAt);
  if (action === "mirror") requireConfig(env);
  const observer = env.WORM_VERSION_OBSERVER;
  if (observer === undefined || typeof observer.fetch !== "function") {
    throw new BrokerError("B2_OBSERVER_UNAVAILABLE", 503, true);
  }
  const observerPin = observerPinFromHeaders(headers);
  assertExpectedB2ObserverPin(observerPin, env);
  const observerVersion = exactHeader(
    headers,
    "x-dpone-cloudflare-observer-worker-version",
    VERSION,
    128,
  );
  const key =
    `receipts/v1/cloudflare-observations/${observerVersion}/${kind}/` +
    `${sanitized.recordId.slice("sha256:".length)}.json`;
  const bytes = new TextEncoder().encode(canonicalJson(sanitized.record));
  const versionObserver = new B2VersionObserverClient(observer, observerPin);
  if (action === "absence") {
    const inventorySha256 = await assertExactObjectAbsent({
      bytes,
      committedAt,
      digest: sanitized.recordSha256,
      key,
      observer: versionObserver,
    });
    return canonicalResponse({
      inventory_sha256: inventorySha256,
      kind: "cloudflare_evidence_absence",
      record_id: sanitized.recordId,
      schema: CLOUDFLARE_EVIDENCE_WORM_ABSENCE_RESULT_SCHEMA,
      worker_version_id: requireVersionId(env),
    });
  }
  const result =
    action === "reconcile"
      ? await reconcileExactObject({
          bytes,
          committedAt,
          digest: sanitized.recordSha256,
          key,
          observer: versionObserver,
        })
      : await mirrorExactOnce(bytes, committedAt, sanitized, key, versionObserver, env);
  return canonicalResponse({
    digest: result.digest,
    key: result.key,
    kind: "cloudflare_evidence",
    record: sanitized.record,
    record_id: sanitized.recordId,
    record_sha256: sanitized.recordSha256,
    retention_until: new Date(Date.parse(result.retentionUntil)).toISOString(),
    schema: CLOUDFLARE_EVIDENCE_WORM_RESULT_SCHEMA,
    version_id: result.versionId,
    worker_version_id: requireVersionId(env),
  });
}

async function mirrorExactOnce(
  bytes: Uint8Array,
  committedAt: string,
  sanitized: SanitizedCloudflareEvidence,
  key: string,
  observer: B2VersionObserverClient,
  env: WormMirrorEnv,
) {
  const result = await new B2ExactObjectMirror(
    new B2NativeWriter(requireConfig(env)),
    observer,
  ).mirror({
    canonicalBytes: bytes,
    committedAt,
    digest: sanitized.recordSha256,
    key,
  });
  if (
    result.identicalVersionIds.length !== 1 ||
    result.identicalVersionIds[0] !== result.versionId
  ) {
    throw new BrokerError("B2_RECONCILIATION_DUPLICATE_DISPATCH", 409, false);
  }
  return result;
}

async function sanitizeBody(
  action: CloudflareEvidenceAction,
  kind: string,
  body: JsonObject,
): Promise<SanitizedCloudflareEvidence> {
  if (action === "mirror") {
    return kind === CLOUDFLARE_DEPLOYMENT_EVIDENCE_KIND
      ? sanitizeCloudflareServiceEvidence(body)
      : sanitizeCloudflareNetworkEvidence(body);
  }
  const sanitized = await assertSanitizedCloudflareEvidenceRecord(body);
  const expectedKind =
    kind === CLOUDFLARE_DEPLOYMENT_EVIDENCE_KIND
      ? "cloudflare_service_deployment_observation"
      : "cloudflare_network_surface_observation";
  if (sanitized.record.evidence_kind !== expectedKind) {
    throw new BrokerError("CLOUDFLARE_EVIDENCE_SANITIZED_BINDING_INVALID", 400, false);
  }
  return sanitized;
}

function assertEvidenceChronology(record: JsonObject, committedAt: string): void {
  const observedAt = requireString(record, "observed_at", 32, TIMESTAMP);
  const committedMs = Date.parse(committedAt);
  const observedMs = Date.parse(observedAt);
  if (
    !Number.isFinite(committedMs) ||
    !Number.isFinite(observedMs) ||
    committedMs < observedMs ||
    committedMs - observedMs > 60_000
  ) {
    throw new BrokerError("CLOUDFLARE_EVIDENCE_COMMIT_TIME_INVALID", 400, false);
  }
}
