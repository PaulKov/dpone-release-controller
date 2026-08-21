import {
  activatedAuthorityHeadKey,
  activatedAuthorityHeadRecordSha256,
  parseActivatedAuthorityHead,
} from "./activated-authority-head";
import { INTERNAL_RESPONSE_READ_POLICY, readBoundedBytes } from "./bounded";
import { canonicalBytes, canonicalJson } from "./canonical";
import { assert, BrokerError } from "./errors";
import { requireExactInternalJsonResponse } from "./internal-json-response";
import { assertPinnedServiceVersion, callPinnedService } from "./service-version";
import type { ActivationWorm, JsonObject, PrivateServicePin } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";
import { signWormRpcRequest, type WormRpcCallerAuth } from "./worm-rpc-auth";

export const ACTIVATED_AUTHORITY_HEAD_WORM_PATH = "/rpc/v1/activation-head" as const;

/** Private, immutable-version client for one exact global-head witness mirror. */
export class ActivatedAuthorityHeadWormClient {
  public constructor(
    private readonly service: Fetcher,
    private readonly pin: PrivateServicePin,
    private readonly observerPin: PrivateServicePin,
    private readonly callerAuth: WormRpcCallerAuth,
  ) {}

  public async mirror(rawHead: JsonObject): Promise<ActivationWorm> {
    const head = await parseActivatedAuthorityHead(rawHead);
    const bytes = canonicalBytes(head);
    const digest = await activatedAuthorityHeadRecordSha256(head);
    const key = await activatedAuthorityHeadKey(head);
    const headers = new Headers({
      "content-length": String(bytes.byteLength),
      "content-type": "application/json",
      "x-dpone-callee-service": this.pin.serviceName,
      "x-dpone-callee-service-identity": this.pin.serviceIdentity,
      "x-dpone-callee-version": this.pin.versionId,
      "x-dpone-canonical-sha256": digest,
      "x-dpone-committed-at": requireString(head, "committed_at", 32),
      "x-dpone-generation": String(requireInteger(head, "generation", 1)),
      "x-dpone-ingress-worker-version": requireString(head, "ingress_worker_version_id", 36),
      "x-dpone-observer-service": this.observerPin.serviceName,
      "x-dpone-observer-service-identity": this.observerPin.serviceIdentity,
      "x-dpone-observer-version": this.observerPin.versionId,
      "x-dpone-record-id": requireString(head, "record_id", 71),
    });
    await signWormRpcRequest(headers, ACTIVATED_AUTHORITY_HEAD_WORM_PATH, this.callerAuth);
    const response = await callPinnedService(this.service, this.pin, {
      body: Uint8Array.from(bytes).buffer,
      headers: Object.fromEntries(headers),
      method: "POST",
      path: ACTIVATED_AUTHORITY_HEAD_WORM_PATH,
    });
    await requireExactInternalJsonResponse(
      response,
      200,
      "ACTIVATED_AUTHORITY_HEAD_WORM_RESPONSE_INVALID",
    );
    const responseBytes = await readBoundedBytes(
      response,
      4096,
      "ACTIVATED_AUTHORITY_HEAD_WORM_RESPONSE_TOO_LARGE",
      INTERNAL_RESPONSE_READ_POLICY,
    );
    const text = new TextDecoder("utf-8", { fatal: true }).decode(responseBytes);
    let decoded: unknown;
    try {
      decoded = JSON.parse(text);
    } catch {
      throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_WORM_RESPONSE_INVALID", 503, false);
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
    assert(text === canonicalJson(result), "ACTIVATED_AUTHORITY_HEAD_WORM_RESPONSE_NONCANONICAL");
    literal(result, "schema", "dpone.release-worm-mirror-result.v1");
    literal(result, "kind", "activation_head");
    literal(result, "digest", digest);
    literal(result, "key", key);
    assertPinnedServiceVersion(requireString(result, "worker_version_id", 36), this.pin);
    return {
      digest,
      key,
      retentionUntil: requireString(
        result,
        "retention_until",
        32,
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u,
      ),
      versionId: requireString(result, "version_id", 512),
    };
  }
}

function literal(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, expected.length) === expected,
    "ACTIVATED_AUTHORITY_HEAD_WORM_RESPONSE_INVALID",
    503,
  );
}
