import { INTERNAL_RESPONSE_READ_POLICY, readBoundedBytes } from "./bounded";
import type { ActivationOperationCloudflareRequest } from "./activation-operation-cloudflare-request";
import { canonicalBytes, sha256Hex } from "./canonical";
import {
  buildCloudflareEvidenceBatchRequestV2,
  canonicalCloudflareEvidenceBatchBytes,
  CLOUDFLARE_EVIDENCE_BATCH_RPC_PATH_V2,
  MAX_CLOUDFLARE_EVIDENCE_BATCH_RPC_BYTES,
  prepareCloudflareEvidenceBatchV2,
} from "./cloudflare-evidence-batch-rpc";
import {
  parseCloudflareEvidenceBatchResultV2,
  type ConfirmedCloudflareEvidenceBatchV2,
} from "./cloudflare-evidence-batch-result-v2";
import {
  buildCloudflareEvidenceBatchResumeV2,
  CLOUDFLARE_EVIDENCE_BATCH_RESUME_RPC_PATH_V2,
  isCloudflareEvidenceBatchResumeMissingV2,
  parseCloudflareEvidenceBatchResumeV2,
} from "./cloudflare-evidence-batch-resume-v2";
import {
  assertCanonicalCloudflareEvidenceWormResponse,
  requireExactCloudflareEvidenceWormResponse,
} from "./cloudflare-evidence-worm-client";
import { callPinnedService } from "./service-version";
import { parseStrictJsonObject } from "./strict-json";
import type { CloudflareDeploymentObservationResult } from "./cloudflare-deployment-observation";
import type { PrivateServicePin } from "./types";
import { signWormRpcRequest, type WormRpcCallerAuth } from "./worm-rpc-auth";

export interface CloudflareEvidenceBatchV2Response {
  readonly canonicalResultBytes: Uint8Array;
  readonly confirmed: ConfirmedCloudflareEvidenceBatchV2;
}

/** Operation-scoped client for the ordinal-bound v2 WORM batch protocol. */
export class CloudflareEvidenceWormBatchV2Client {
  public constructor(
    private readonly service: Fetcher,
    private readonly wormPin: PrivateServicePin,
    private readonly b2ObserverPin: PrivateServicePin,
    private readonly callerAuth: WormRpcCallerAuth,
  ) {}

  public async mirror(
    result: CloudflareDeploymentObservationResult,
    delegation: ActivationOperationCloudflareRequest,
    batchSealedAt: string,
    signal?: AbortSignal,
  ): Promise<CloudflareEvidenceBatchV2Response> {
    const request = buildCloudflareEvidenceBatchRequestV2(result, delegation, batchSealedAt);
    const prepared = await prepareCloudflareEvidenceBatchV2(request);
    const bytes = canonicalCloudflareEvidenceBatchBytes(request);
    const headers = new Headers({
      "content-length": String(bytes.byteLength),
      "content-type": "application/json",
      "x-dpone-batch-id": prepared.binding.batchId,
      "x-dpone-callee-service": this.wormPin.serviceName,
      "x-dpone-callee-service-identity": this.wormPin.serviceIdentity,
      "x-dpone-callee-version": this.wormPin.versionId,
      "x-dpone-canonical-sha256": `sha256:${await sha256Hex(bytes)}`,
      "x-dpone-cloudflare-observer-worker-version": this.callerAuth.versionId,
      "x-dpone-observer-service": this.b2ObserverPin.serviceName,
      "x-dpone-observer-service-identity": this.b2ObserverPin.serviceIdentity,
      "x-dpone-observer-version": this.b2ObserverPin.versionId,
    });
    await signWormRpcRequest(headers, CLOUDFLARE_EVIDENCE_BATCH_RPC_PATH_V2, this.callerAuth);
    const response = await callPinnedService(this.service, this.wormPin, {
      body: Uint8Array.from(bytes).buffer,
      headers: Object.fromEntries(headers),
      method: "POST",
      path: CLOUDFLARE_EVIDENCE_BATCH_RPC_PATH_V2,
      ...(signal === undefined ? {} : { signal }),
    });
    await requireExactCloudflareEvidenceWormResponse(response);
    const responseBytes = await readBoundedBytes(
      response,
      MAX_CLOUDFLARE_EVIDENCE_BATCH_RPC_BYTES,
      "CLOUDFLARE_EVIDENCE_WORM_RESPONSE_INVALID",
      INTERNAL_RESPONSE_READ_POLICY,
    );
    return {
      canonicalResultBytes: Uint8Array.from(responseBytes),
      confirmed: await parseCloudflareEvidenceBatchResultV2(responseBytes, delegation),
    };
  }

  /** Resolve the same ordinal without issuing any new Cloudflare provider read. */
  public async resume(
    delegation: ActivationOperationCloudflareRequest,
    signal?: AbortSignal,
  ): Promise<CloudflareEvidenceBatchV2Response | undefined> {
    const request = buildCloudflareEvidenceBatchResumeV2(delegation);
    const expected = parseCloudflareEvidenceBatchResumeV2(request);
    const bytes = canonicalBytes(request);
    const headers = await this.headers(bytes, expected.binding.batchId);
    await signWormRpcRequest(
      headers,
      CLOUDFLARE_EVIDENCE_BATCH_RESUME_RPC_PATH_V2,
      this.callerAuth,
    );
    const response = await callPinnedService(this.service, this.wormPin, {
      body: Uint8Array.from(bytes).buffer,
      headers: Object.fromEntries(headers),
      method: "POST",
      path: CLOUDFLARE_EVIDENCE_BATCH_RESUME_RPC_PATH_V2,
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
    if (isCloudflareEvidenceBatchResumeMissingV2(parsed, expected)) return undefined;
    return {
      canonicalResultBytes: Uint8Array.from(responseBytes),
      confirmed: await parseCloudflareEvidenceBatchResultV2(responseBytes, delegation),
    };
  }

  private async headers(bytes: Uint8Array, batchId: string): Promise<Headers> {
    return new Headers({
      "content-length": String(bytes.byteLength),
      "content-type": "application/json",
      "x-dpone-batch-id": batchId,
      "x-dpone-callee-service": this.wormPin.serviceName,
      "x-dpone-callee-service-identity": this.wormPin.serviceIdentity,
      "x-dpone-callee-version": this.wormPin.versionId,
      "x-dpone-canonical-sha256": `sha256:${await sha256Hex(bytes)}`,
      "x-dpone-cloudflare-observer-worker-version": this.callerAuth.versionId,
      "x-dpone-observer-service": this.b2ObserverPin.serviceName,
      "x-dpone-observer-service-identity": this.b2ObserverPin.serviceIdentity,
      "x-dpone-observer-version": this.b2ObserverPin.versionId,
    });
  }
}
