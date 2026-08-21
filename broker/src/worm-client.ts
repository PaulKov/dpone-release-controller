import { canonicalJson } from "./canonical";
import { readBoundedBytes } from "./bounded";
import { isSha256, LIMITS } from "./config";
import { assert, BrokerError } from "./errors";
import {
  assertRetainableProviderEvidence,
  type RawProviderEvidenceKind,
} from "./provider-evidence";
import { assertPinnedServiceVersion, callPinnedService } from "./service-version";
import type { ActivationWorm, JsonObject, PrivateServicePin } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";
import { signWormRpcRequest, type WormRpcCallerAuth } from "./worm-rpc-auth";
import { validateActivationWorm } from "./activation-worm-binding";

const ACTIVATION_SCHEMAS = new Set([
  "dpone.release-broker-activated.v1",
  "dpone.release-broker-provisioned.v1",
]);

/** Narrow client for the private WORM mirror Service Binding. */
export class WormMirrorClient {
  public constructor(
    private readonly service: Fetcher,
    private readonly pin: PrivateServicePin,
    private readonly observerPin: PrivateServicePin,
    private readonly callerAuth: WormRpcCallerAuth,
  ) {}

  public async mirrorActivation(input: {
    readonly bytes: Uint8Array;
    readonly committedAt: string;
    readonly digest: string;
    readonly recordId: string;
    readonly sequence: 0 | 1;
  }): Promise<ActivationWorm> {
    assert(input.bytes.byteLength <= LIMITS.bodyBytes, "MIRROR_BODY_SIZE_INVALID", 500);
    assert(isSha256(input.digest), "MIRROR_DIGEST_INVALID", 500);
    assert(isSha256(input.recordId), "MIRROR_RECORD_ID_INVALID", 500);
    const envelope = decodeEnvelope(input.bytes);
    const schema = requireString(envelope, "schema", 64);
    assert(ACTIVATION_SCHEMAS.has(schema), "MIRROR_SCHEMA_INVALID", 500);
    assert(
      envelope.record_id === input.recordId &&
        envelope.sequence === input.sequence &&
        envelope.committed_at === input.committedAt,
      "MIRROR_ACTIVATION_BINDING_INVALID",
      500,
    );
    const path = "/rpc/v1/activation" as const;
    const ingressWorkerVersion = extractIngressWorkerVersion(envelope);
    const headers = new Headers({
      "content-length": String(input.bytes.byteLength),
      "content-type": "application/json",
      "x-dpone-committed-at": input.committedAt,
      "x-dpone-canonical-sha256": input.digest,
      "x-dpone-callee-service": this.pin.serviceName,
      "x-dpone-callee-service-identity": this.pin.serviceIdentity,
      "x-dpone-callee-version": this.pin.versionId,
      "x-dpone-ingress-worker-version": ingressWorkerVersion,
      "x-dpone-observer-service": this.observerPin.serviceName,
      "x-dpone-observer-service-identity": this.observerPin.serviceIdentity,
      "x-dpone-observer-version": this.observerPin.versionId,
      "x-dpone-record-id": input.recordId,
      "x-dpone-sequence": String(input.sequence),
    });
    await signWormRpcRequest(headers, path, this.callerAuth);
    const response = await callPinnedService(this.service, this.pin, {
      body: Uint8Array.from(input.bytes).buffer,
      headers: Object.fromEntries(headers),
      method: "POST",
      path,
    });
    if (!response.ok) {
      throw new BrokerError(
        "WORM_MIRROR_FAILED",
        503,
        response.status >= 500 || response.status === 429,
      );
    }
    const bytes = await readBoundedBytes(response, 4096, "WORM_MIRROR_RESPONSE_TOO_LARGE");
    let decoded: unknown;
    try {
      decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      throw new BrokerError("WORM_MIRROR_RESPONSE_INVALID", 503, false);
    }
    const result = exactObject(decoded, [
      "digest",
      "key",
      "kind",
      "retention_until",
      "schema",
      "version_id",
      "worker_version_id",
    ]);
    assert(
      new TextDecoder().decode(bytes) === canonicalJson(result),
      "WORM_MIRROR_RESPONSE_NONCANONICAL",
      503,
    );
    requireLiteral(result, "schema", "dpone.release-worm-mirror-result.v1");
    requireLiteral(result, "kind", "activation");
    assertPinnedServiceVersion(requireString(result, "worker_version_id", 128), this.pin);
    assert(result.digest === input.digest, "WORM_MIRROR_DIGEST_MISMATCH", 503);
    const key = requireString(result, "key", 512);
    const versionId = requireString(result, "version_id", 512);
    const retentionUntil = requireString(
      result,
      "retention_until",
      32,
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u,
    );
    const minimum = Date.parse(input.committedAt) + 2557 * 86_400_000;
    assert(
      Number.isFinite(Date.parse(retentionUntil)) && Date.parse(retentionUntil) >= minimum,
      "WORM_MIRROR_RETENTION_INVALID",
      503,
    );
    return validateActivationWorm(
      {
        digest: input.digest,
        key,
        retentionUntil: new Date(Date.parse(retentionUntil)).toISOString(),
        versionId,
      },
      envelope,
      input.digest,
      input.sequence,
      input.committedAt,
    );
  }

  /** Mirrors one independently retrievable A0 evidence object before A0 append. */
  public async mirrorEvidence(input: {
    readonly bytes: Uint8Array;
    readonly committedAt: string;
    readonly digest: string;
    readonly evidenceKind: RawProviderEvidenceKind;
    readonly ingressWorkerVersion: string;
  }): Promise<ActivationWorm> {
    assert(input.bytes.byteLength <= LIMITS.bodyBytes, "MIRROR_BODY_SIZE_INVALID", 500);
    assert(isSha256(input.digest), "MIRROR_DIGEST_INVALID", 500);
    const envelope = decodeEnvelope(input.bytes);
    const expectedSchema = "dpone.release-broker-provider-evidence-entry.v1";
    assert(
      envelope.schema === expectedSchema && envelope.evidence_kind === input.evidenceKind,
      "MIRROR_EVIDENCE_BINDING_INVALID",
      500,
    );
    await assertRetainableProviderEvidence(envelope, input.evidenceKind);
    const path = "/rpc/v1/activation-evidence" as const;
    const headers = new Headers({
      "content-length": String(input.bytes.byteLength),
      "content-type": "application/json",
      "x-dpone-callee-service": this.pin.serviceName,
      "x-dpone-callee-service-identity": this.pin.serviceIdentity,
      "x-dpone-callee-version": this.pin.versionId,
      "x-dpone-canonical-sha256": input.digest,
      "x-dpone-committed-at": input.committedAt,
      "x-dpone-evidence-kind": input.evidenceKind,
      "x-dpone-ingress-worker-version": input.ingressWorkerVersion,
      "x-dpone-observer-service": this.observerPin.serviceName,
      "x-dpone-observer-service-identity": this.observerPin.serviceIdentity,
      "x-dpone-observer-version": this.observerPin.versionId,
    });
    await signWormRpcRequest(headers, path, this.callerAuth);
    const response = await callPinnedService(this.service, this.pin, {
      body: Uint8Array.from(input.bytes).buffer,
      headers: Object.fromEntries(headers),
      method: "POST",
      path,
    });
    const worm = await parseMirrorResponse(
      response,
      this.pin,
      input.digest,
      "activation_evidence",
      input.committedAt,
    );
    const expectedKey = [
      "receipts",
      "v1",
      "activation-evidence",
      input.ingressWorkerVersion,
      input.evidenceKind,
      `${input.digest.slice("sha256:".length)}.json`,
    ].join("/");
    assert(worm.key === expectedKey, "WORM_MIRROR_KEY_MISMATCH", 503);
    return worm;
  }
}

async function parseMirrorResponse(
  response: Response,
  pin: PrivateServicePin,
  expectedDigest: string,
  expectedKind: "activation_evidence",
  committedAt: string,
): Promise<ActivationWorm> {
  if (!response.ok) {
    throw new BrokerError(
      "WORM_MIRROR_FAILED",
      503,
      response.status >= 500 || response.status === 429,
    );
  }
  const bytes = await readBoundedBytes(response, 4096, "WORM_MIRROR_RESPONSE_TOO_LARGE");
  let decoded: unknown;
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  try {
    decoded = JSON.parse(text);
  } catch {
    throw new BrokerError("WORM_MIRROR_RESPONSE_INVALID", 503, false);
  }
  const result = exactObject(decoded, [
    "digest",
    "key",
    "kind",
    "retention_until",
    "schema",
    "version_id",
    "worker_version_id",
  ]);
  assert(text === canonicalJson(result), "WORM_MIRROR_RESPONSE_NONCANONICAL", 503);
  requireLiteral(result, "schema", "dpone.release-worm-mirror-result.v1");
  requireLiteral(result, "kind", expectedKind);
  assertPinnedServiceVersion(requireString(result, "worker_version_id", 128), pin);
  assert(result.digest === expectedDigest, "WORM_MIRROR_DIGEST_MISMATCH", 503);
  const key = requireString(result, "key", 512, /^receipts\/v1\/activation-evidence\/.+\.json$/u);
  const versionId = requireString(result, "version_id", 512);
  const retentionUntil = requireString(
    result,
    "retention_until",
    32,
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u,
  );
  assert(
    Date.parse(retentionUntil) >= Date.parse(committedAt) + 2557 * 86_400_000,
    "WORM_MIRROR_RETENTION_INVALID",
    503,
  );
  return { digest: expectedDigest, key, retentionUntil, versionId };
}

function extractIngressWorkerVersion(envelope: JsonObject): string {
  const sequence = requireInteger(envelope, "sequence", 0, 1);
  const container = sequence === 0 ? envelope.evidence : envelope.provisioned;
  const outer = exactObject(
    container,
    sequence === 0
      ? [
          "admin_access",
          "b2",
          "broker",
          "controller",
          "controller_governance",
          "github_apps",
          "oidc",
          "service_authorities",
          "target_governance",
          "trusted_publishers",
        ]
      : ["digest", "record_id", "worker_version_id", "worm_key", "worm_version_id"],
  );
  if (sequence === 1) {
    return requireString(outer, "worker_version_id", 128);
  }
  const broker = outer.broker;
  assert(
    broker !== null && typeof broker === "object" && !Array.isArray(broker),
    "MIRROR_BODY_INVALID",
    500,
  );
  return requireString(broker, "worker_version_id", 128);
}

function decodeEnvelope(bytes: Uint8Array): JsonObject {
  let decoded: unknown;
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    decoded = JSON.parse(text);
    const object = decoded as JsonObject;
    assert(text === canonicalJson(object), "MIRROR_BODY_NONCANONICAL", 500);
  } catch (error) {
    if (error instanceof BrokerError) {
      throw error;
    }
    throw new BrokerError("MIRROR_BODY_INVALID", 500, false);
  }
  return decoded as JsonObject;
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, expected.length) === expected,
    "WORM_MIRROR_RESPONSE_INVALID",
    503,
  );
}

export function parseMirrorSequence(value: JsonObject): 0 | 1 {
  const sequence = requireInteger(value, "sequence", 0, 1);
  return sequence as 0 | 1;
}
