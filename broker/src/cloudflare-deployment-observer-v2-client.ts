import { INTERNAL_RESPONSE_READ_POLICY, readBoundedBytes } from "./bounded";
import {
  parseActivationOperationCloudflareRequest,
  type ActivationOperationCloudflareRequest,
} from "./activation-operation-cloudflare-request";
import { sha256Hex } from "./canonical";
import {
  parseCloudflareEvidenceBatchResultV2,
  type ConfirmedCloudflareEvidenceBatchV2,
} from "./cloudflare-evidence-batch-result-v2";
import { BrokerError } from "./errors";
import { callPinnedService } from "./service-version";
import type { PrivateServicePin } from "./types";
import {
  CLOUDFLARE_OBSERVER_RPC_PATH_V2,
  signCloudflareObserverRpcRequest,
  type WormRpcCallerAuth,
} from "./worm-rpc-auth";

const MAX_RESULT_BYTES = 1_048_576;

export interface AcceptedCloudflareDeploymentObservationV2 {
  readonly canonicalResultBytes: Uint8Array;
  readonly confirmed: ConfirmedCloudflareEvidenceBatchV2;
}

/** Pinned ingress client for the durable resume-first v2 observer protocol. */
export class CloudflareDeploymentObserverV2Client {
  public constructor(
    private readonly service: Fetcher,
    private readonly pin: PrivateServicePin,
    private readonly callerAuth: WormRpcCallerAuth,
  ) {}

  public async observe(
    delegation: ActivationOperationCloudflareRequest,
    signal?: AbortSignal,
  ): Promise<AcceptedCloudflareDeploymentObservationV2> {
    const ownedDelegation = await parseActivationOperationCloudflareRequest(
      delegation.canonicalBytes,
      delegation.issuance,
    );
    const bytes = ownedDelegation.canonicalBytes;
    if (
      this.pin.serviceIdentity !== ownedDelegation.pins.cloudflareObserverServiceIdentity ||
      this.pin.versionId !== ownedDelegation.pins.cloudflareObserverWorkerVersionId
    ) {
      throw new BrokerError("CLOUDFLARE_OBSERVER_V2_PIN_INVALID", 409, false);
    }
    const headers = new Headers({
      "content-length": String(bytes.byteLength),
      "content-type": "application/json",
      "x-dpone-callee-service": this.pin.serviceName,
      "x-dpone-callee-service-identity": this.pin.serviceIdentity,
      "x-dpone-callee-version": this.pin.versionId,
      "x-dpone-canonical-sha256": `sha256:${await sha256Hex(bytes)}`,
      "x-dpone-ingress-worker-version": this.callerAuth.versionId,
      "x-request-id": ownedDelegation.observerRequest.requestId,
    });
    await signCloudflareObserverRpcRequest(
      headers,
      this.callerAuth,
      CLOUDFLARE_OBSERVER_RPC_PATH_V2,
    );
    const response = await callPinnedService(this.service, this.pin, {
      body: Uint8Array.from(bytes).buffer,
      headers: Object.fromEntries(headers),
      method: "POST",
      path: CLOUDFLARE_OBSERVER_RPC_PATH_V2,
      ...(signal === undefined ? {} : { signal }),
    });
    await requireExactResponse(response, ownedDelegation.observerRequest.requestId);
    const resultBytes = await readBoundedBytes(
      response,
      MAX_RESULT_BYTES,
      "CLOUDFLARE_DEPLOYMENT_RESULT_INVALID",
      INTERNAL_RESPONSE_READ_POLICY,
    );
    return {
      canonicalResultBytes: Uint8Array.from(resultBytes),
      confirmed: await parseCloudflareEvidenceBatchResultV2(resultBytes, ownedDelegation),
    };
  }
}

async function requireExactResponse(response: Response, requestId: string): Promise<void> {
  const mediaType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (
    response.status !== 200 ||
    mediaType !== "application/json" ||
    response.headers.get("x-request-id") !== requestId ||
    response.headers.has("content-encoding") ||
    response.headers.has("content-range") ||
    response.headers.has("location") ||
    response.headers.has("set-cookie") ||
    response.headers.has("transfer-encoding")
  ) {
    await response.body?.cancel("CLOUDFLARE_DEPLOYMENT_RESULT_INVALID").catch(() => undefined);
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_RESULT_INVALID", 503, false);
  }
}
