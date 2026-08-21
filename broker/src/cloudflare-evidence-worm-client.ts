import { INTERNAL_RESPONSE_READ_POLICY, readBoundedBytes } from "./bounded";
import { canonicalBytes, canonicalJson, sha256Hex } from "./canonical";
import {
  assertSanitizedCloudflareEvidenceRecord,
  CLOUDFLARE_DEPLOYMENT_EVIDENCE_KIND,
  sanitizeCloudflareNetworkEvidence,
  sanitizeCloudflareServiceEvidence,
  type CLOUDFLARE_NETWORK_EVIDENCE_KIND,
  type SanitizedCloudflareEvidence,
} from "./cloudflare-deployment-observation";
import {
  buildCloudflareEvidenceBatchRequest,
  canonicalCloudflareEvidenceBatchBytes,
  CLOUDFLARE_EVIDENCE_BATCH_RPC_PATH,
  MAX_CLOUDFLARE_EVIDENCE_BATCH_RPC_BYTES,
  parseCloudflareEvidenceBatchResult,
  prepareCloudflareEvidenceBatch,
  type ConfirmedCloudflareEvidenceBatch,
} from "./cloudflare-evidence-batch-rpc";
import { assert, BrokerError } from "./errors";
import { assertPinnedServiceVersion, callPinnedService } from "./service-version";
import { parseStrictJsonObject } from "./strict-json";
import type { ActivationWorm, JsonObject, PrivateServicePin } from "./types";
import { exactObject, requireString } from "./validation";
import { signWormRpcRequest, type WormRpcCallerAuth } from "./worm-rpc-auth";

export const CLOUDFLARE_EVIDENCE_WORM_RPC_PATH = "/rpc/v1/cloudflare-evidence" as const;
export const CLOUDFLARE_EVIDENCE_WORM_ABSENCE_RPC_PATH =
  "/rpc/v1/cloudflare-evidence/absence" as const;
export const CLOUDFLARE_EVIDENCE_WORM_RECONCILE_RPC_PATH =
  "/rpc/v1/cloudflare-evidence/reconcile" as const;
export const CLOUDFLARE_EVIDENCE_WORM_RESULT_SCHEMA =
  "dpone.release-worm-cloudflare-evidence-result.v1";
export const CLOUDFLARE_EVIDENCE_WORM_ABSENCE_RESULT_SCHEMA =
  "dpone.release-worm-cloudflare-evidence-absence-result.v1";

const MAX_BODY_BYTES = 65_536;
const MAX_RESPONSE_BYTES = 65_536;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;

type EvidenceKind =
  | typeof CLOUDFLARE_DEPLOYMENT_EVIDENCE_KIND
  | typeof CLOUDFLARE_NETWORK_EVIDENCE_KIND;

export interface MirroredCloudflareEvidence extends SanitizedCloudflareEvidence {
  readonly worm: ActivationWorm;
}

/** Pinned client for the staged Cloudflare evidence WORM protocol. */
export class CloudflareEvidenceWormClient {
  public constructor(
    private readonly service: Fetcher,
    private readonly pin: PrivateServicePin,
    private readonly b2ObserverPin: PrivateServicePin,
    private readonly callerAuth: WormRpcCallerAuth,
  ) {}

  /**
   * Submit all transient provider reads as one WORM-side staged batch. The
   * WORM Durable Object reparses them, stores only sanitized bytes, seals all
   * fifteen slots, then performs journaled B2 writes and observer reconciliation.
   */
  public async mirrorBatch(
    result: Parameters<typeof buildCloudflareEvidenceBatchRequest>[0],
    committedAt: string,
    signal?: AbortSignal,
  ): Promise<ConfirmedCloudflareEvidenceBatch> {
    const request = buildCloudflareEvidenceBatchRequest(result);
    const prepared = await prepareCloudflareEvidenceBatch(request);
    const bytes = canonicalCloudflareEvidenceBatchBytes(request);
    const headers = new Headers({
      "content-length": String(bytes.byteLength),
      "content-type": "application/json",
      "x-dpone-batch-id": prepared.binding.batchId,
      "x-dpone-callee-service": this.pin.serviceName,
      "x-dpone-callee-service-identity": this.pin.serviceIdentity,
      "x-dpone-callee-version": this.pin.versionId,
      "x-dpone-canonical-sha256": `sha256:${await sha256Hex(bytes)}`,
      "x-dpone-cloudflare-observer-worker-version": this.callerAuth.versionId,
      "x-dpone-committed-at": committedAt,
      "x-dpone-observer-service": this.b2ObserverPin.serviceName,
      "x-dpone-observer-service-identity": this.b2ObserverPin.serviceIdentity,
      "x-dpone-observer-version": this.b2ObserverPin.versionId,
    });
    await signWormRpcRequest(headers, CLOUDFLARE_EVIDENCE_BATCH_RPC_PATH, this.callerAuth);
    const response = await callPinnedService(this.service, this.pin, {
      body: Uint8Array.from(bytes).buffer,
      headers: Object.fromEntries(headers),
      method: "POST",
      path: CLOUDFLARE_EVIDENCE_BATCH_RPC_PATH,
      ...(signal === undefined ? {} : { signal }),
    });
    await requireExactCloudflareEvidenceWormResponse(response);
    const responseBytes = await readBoundedBytes(
      response,
      MAX_CLOUDFLARE_EVIDENCE_BATCH_RPC_BYTES,
      "CLOUDFLARE_EVIDENCE_WORM_RESPONSE_INVALID",
      INTERNAL_RESPONSE_READ_POLICY,
    );
    const parsed = parseStrictJsonObject(
      responseBytes,
      "CLOUDFLARE_EVIDENCE_WORM_RESPONSE_INVALID",
    );
    assertCanonicalCloudflareEvidenceWormResponse(responseBytes, parsed);
    return parseCloudflareEvidenceBatchResult(
      parsed,
      prepared.binding,
      this.pin.versionId,
      this.b2ObserverPin.serviceIdentity,
      this.pin.serviceIdentity,
    );
  }

  /** Dispatch raw transient evidence exactly once after the batch journal seals. */
  public async mirror(
    transient: JsonObject,
    kind: EvidenceKind,
    committedAt: string,
    signal?: AbortSignal,
  ): Promise<MirroredCloudflareEvidence> {
    const expected =
      kind === CLOUDFLARE_DEPLOYMENT_EVIDENCE_KIND
        ? await sanitizeCloudflareServiceEvidence(transient)
        : await sanitizeCloudflareNetworkEvidence(transient);
    const bytes = canonicalBytes(transient);
    if (bytes.byteLength === 0 || bytes.byteLength > MAX_BODY_BYTES) {
      throw new BrokerError("CLOUDFLARE_EVIDENCE_TRANSIENT_SIZE_INVALID", 500, false);
    }
    const responseBytes = await this.call(
      bytes,
      expected,
      kind,
      committedAt,
      CLOUDFLARE_EVIDENCE_WORM_RPC_PATH,
      signal,
    );
    return this.parseMirrored(responseBytes, expected, kind, committedAt);
  }

  /** Persist the observer-only zero-version proof before a writer dispatch. */
  public async assertAbsent(
    expected: SanitizedCloudflareEvidence,
    kind: EvidenceKind,
    committedAt: string,
    signal?: AbortSignal,
  ): Promise<string> {
    const responseBytes = await this.call(
      canonicalBytes(expected.record),
      expected,
      kind,
      committedAt,
      CLOUDFLARE_EVIDENCE_WORM_ABSENCE_RPC_PATH,
      signal,
    );
    const result = exactObject(
      parseStrictJsonObject(responseBytes, "CLOUDFLARE_EVIDENCE_WORM_RESPONSE_INVALID"),
      ["inventory_sha256", "kind", "record_id", "schema", "worker_version_id"],
    );
    assertCanonicalCloudflareEvidenceWormResponse(responseBytes, result);
    requireLiteral(result, "schema", CLOUDFLARE_EVIDENCE_WORM_ABSENCE_RESULT_SCHEMA);
    requireLiteral(result, "kind", "cloudflare_evidence_absence");
    requireLiteral(result, "record_id", expected.recordId);
    assertPinnedServiceVersion(requireString(result, "worker_version_id", 128), this.pin);
    return requireString(result, "inventory_sha256", 71, DIGEST);
  }

  /** Read-only recovery after dispatch intent became ambiguous. Never writes B2. */
  public async reconcile(
    expected: SanitizedCloudflareEvidence,
    kind: EvidenceKind,
    committedAt: string,
    signal?: AbortSignal,
  ): Promise<MirroredCloudflareEvidence> {
    const responseBytes = await this.call(
      canonicalBytes(expected.record),
      expected,
      kind,
      committedAt,
      CLOUDFLARE_EVIDENCE_WORM_RECONCILE_RPC_PATH,
      signal,
    );
    return this.parseMirrored(responseBytes, expected, kind, committedAt);
  }

  private async call(
    bytes: Uint8Array,
    expected: SanitizedCloudflareEvidence,
    kind: EvidenceKind,
    committedAt: string,
    path:
      | typeof CLOUDFLARE_EVIDENCE_WORM_ABSENCE_RPC_PATH
      | typeof CLOUDFLARE_EVIDENCE_WORM_RECONCILE_RPC_PATH
      | typeof CLOUDFLARE_EVIDENCE_WORM_RPC_PATH,
    signal?: AbortSignal,
  ): Promise<Uint8Array> {
    if (bytes.byteLength === 0 || bytes.byteLength > MAX_BODY_BYTES) {
      throw new BrokerError("CLOUDFLARE_EVIDENCE_TRANSIENT_SIZE_INVALID", 500, false);
    }
    assertEvidenceChronology(expected.record, committedAt);
    const headers = new Headers({
      "content-length": String(bytes.byteLength),
      "content-type": "application/json",
      "x-dpone-callee-service": this.pin.serviceName,
      "x-dpone-callee-service-identity": this.pin.serviceIdentity,
      "x-dpone-callee-version": this.pin.versionId,
      "x-dpone-canonical-sha256": `sha256:${await sha256Hex(bytes)}`,
      "x-dpone-cloudflare-observer-worker-version": this.callerAuth.versionId,
      "x-dpone-committed-at": committedAt,
      "x-dpone-evidence-kind": kind,
      "x-dpone-observer-service": this.b2ObserverPin.serviceName,
      "x-dpone-observer-service-identity": this.b2ObserverPin.serviceIdentity,
      "x-dpone-observer-version": this.b2ObserverPin.versionId,
      "x-dpone-record-id": expected.recordId,
      "x-dpone-sanitized-record-sha256": expected.recordSha256,
    });
    await signWormRpcRequest(headers, path, this.callerAuth);
    const response = await callPinnedService(this.service, this.pin, {
      body: Uint8Array.from(bytes).buffer,
      headers: Object.fromEntries(headers),
      method: "POST",
      path,
      ...(signal === undefined ? {} : { signal }),
    });
    await requireExactCloudflareEvidenceWormResponse(response);
    return readBoundedBytes(
      response,
      MAX_RESPONSE_BYTES,
      "CLOUDFLARE_EVIDENCE_WORM_RESPONSE_INVALID",
      INTERNAL_RESPONSE_READ_POLICY,
    );
  }

  private async parseMirrored(
    responseBytes: Uint8Array,
    expected: SanitizedCloudflareEvidence,
    kind: EvidenceKind,
    committedAt: string,
  ): Promise<MirroredCloudflareEvidence> {
    const result = exactObject(
      parseStrictJsonObject(responseBytes, "CLOUDFLARE_EVIDENCE_WORM_RESPONSE_INVALID"),
      [
        "digest",
        "key",
        "kind",
        "record",
        "record_id",
        "record_sha256",
        "retention_until",
        "schema",
        "version_id",
        "worker_version_id",
      ],
    );
    assertCanonicalCloudflareEvidenceWormResponse(responseBytes, result);
    requireLiteral(result, "schema", CLOUDFLARE_EVIDENCE_WORM_RESULT_SCHEMA);
    requireLiteral(result, "kind", "cloudflare_evidence");
    assertPinnedServiceVersion(requireString(result, "worker_version_id", 128), this.pin);
    const accepted = await assertSanitizedCloudflareEvidenceRecord(result.record);
    if (
      accepted.recordId !== expected.recordId ||
      accepted.recordSha256 !== expected.recordSha256 ||
      result.record_id !== expected.recordId ||
      result.record_sha256 !== expected.recordSha256 ||
      result.digest !== expected.recordSha256 ||
      canonicalJson(accepted.record) !== canonicalJson(expected.record)
    ) {
      throw new BrokerError("CLOUDFLARE_EVIDENCE_WORM_BINDING_INVALID", 503, false);
    }
    const expectedKey =
      `receipts/v1/cloudflare-observations/${this.callerAuth.versionId}/${kind}/` +
      `${expected.recordId.slice("sha256:".length)}.json`;
    const key = requireString(result, "key", 512);
    const retentionUntil = requireString(result, "retention_until", 32, TIMESTAMP);
    const retentionMs = Date.parse(retentionUntil);
    if (
      key !== expectedKey ||
      !Number.isFinite(retentionMs) ||
      new Date(retentionMs).toISOString() !== retentionUntil ||
      retentionMs < Date.parse(committedAt) + 2557 * 86_400_000
    ) {
      throw new BrokerError("CLOUDFLARE_EVIDENCE_WORM_POINTER_INVALID", 503, false);
    }
    return {
      ...accepted,
      worm: {
        digest: expected.recordSha256,
        key,
        retentionUntil,
        versionId: requireString(result, "version_id", 512, /^[A-Za-z0-9._=-]{1,512}$/u),
      },
    };
  }
}

export async function requireExactCloudflareEvidenceWormResponse(
  response: Response,
): Promise<void> {
  const media = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (
    response.status !== 200 ||
    media !== "application/json" ||
    response.headers.has("content-encoding") ||
    response.headers.has("content-range") ||
    response.headers.has("location") ||
    response.headers.has("set-cookie") ||
    response.headers.has("transfer-encoding")
  ) {
    await response.body?.cancel("CLOUDFLARE_EVIDENCE_WORM_RESPONSE_INVALID").catch(() => undefined);
    throw new BrokerError("CLOUDFLARE_EVIDENCE_WORM_RESPONSE_INVALID", 503, false);
  }
}

function assertEvidenceChronology(record: JsonObject, committedAt: string): void {
  const observedMs = Date.parse(requireString(record, "observed_at", 32, TIMESTAMP));
  const committedMs = Date.parse(committedAt);
  if (
    !Number.isFinite(observedMs) ||
    !Number.isFinite(committedMs) ||
    committedMs < observedMs ||
    committedMs - observedMs > 60_000
  ) {
    throw new BrokerError("CLOUDFLARE_EVIDENCE_COMMIT_TIME_INVALID", 500, false);
  }
}

export function assertCanonicalCloudflareEvidenceWormResponse(
  bytes: Uint8Array,
  value: JsonObject,
): void {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  assert(text === canonicalJson(value), "CLOUDFLARE_EVIDENCE_WORM_RESPONSE_NONCANONICAL", 503);
}

function requireLiteral(value: JsonObject, key: string, expected: string): void {
  if (requireString(value, key, expected.length) !== expected) {
    throw new BrokerError("CLOUDFLARE_EVIDENCE_WORM_RESPONSE_INVALID", 503, false);
  }
}
