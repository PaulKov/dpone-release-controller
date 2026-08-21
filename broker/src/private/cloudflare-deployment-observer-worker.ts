import {
  CLOUDFLARE_DEPLOYMENT_OBSERVATION_RPC_PATH,
  CLOUDFLARE_DEPLOYMENT_RESULT_SCHEMA,
  CloudflareDeploymentObserver,
  assertCloudflareObserverRequestFreshness,
  parseCloudflareDeploymentObservationRequest,
  type CloudflareDeploymentObservationRpcRequest,
} from "../cloudflare-deployment-observation";
import { canonicalBytes, canonicalJson, sha256Hex } from "../canonical";
import { CloudflareEvidenceWormClient } from "../cloudflare-evidence-worm-client";
import type { ConfirmedCloudflareEvidence } from "../cloudflare-evidence-batch-contract";
import { BrokerError, errorResponse } from "../errors";
import type { JsonObject, PrivateServicePin } from "../types";
import { parseJsonObject, requestId } from "../validation";
import {
  CLOUDFLARE_OBSERVER_RPC_PATH_V2,
  verifyCloudflareObserverRpcRequest,
} from "../worm-rpc-auth";
import { CloudflareWorkersDeploymentReader } from "./cloudflare-provider";
import {
  requireCloudflareDeploymentObserverConfig,
  type CloudflareDeploymentObserverEnv,
} from "./cloudflare-deployment-observer-config";
import { observeCloudflareDeploymentV2 } from "./cloudflare-deployment-observer-v2";

const MAX_RESULT_BYTES = 1_048_576;
const EVIDENCE_MIRROR_ABSOLUTE_TIMEOUT_MS = 45_000;

/**
 * Route-less read-only control-plane observer. Its token has only exact
 * account-scoped Workers Scripts Read and this handler exposes no mutation
 * method, arbitrary URL, script selector or public route.
 */
export default {
  async fetch(request: Request, env: CloudflareDeploymentObserverEnv): Promise<Response> {
    let currentRequestId: string = crypto.randomUUID();
    try {
      currentRequestId = requestId(request);
      const url = new URL(request.url);
      const v2 = url.pathname === CLOUDFLARE_OBSERVER_RPC_PATH_V2;
      if (
        request.method !== "POST" ||
        (url.pathname !== CLOUDFLARE_DEPLOYMENT_OBSERVATION_RPC_PATH && !v2) ||
        url.search !== ""
      ) {
        throw new BrokerError("PRIVATE_ROUTE_NOT_FOUND", 404, false);
      }
      if (request.headers.get("x-request-id") !== currentRequestId) {
        throw new BrokerError("REQUEST_ID_REQUIRED", 400, false);
      }
      const config = requireCloudflareDeploymentObserverConfig(env);
      assertExpectedCallee(request.headers, config.serviceIdentity, config.workerVersionId);
      await verifyCloudflareObserverRpcRequest(
        request.headers,
        config.observerRpcAuthKey,
        config.expectedIngressServiceIdentity,
        v2 ? CLOUDFLARE_OBSERVER_RPC_PATH_V2 : CLOUDFLARE_DEPLOYMENT_OBSERVATION_RPC_PATH,
      );
      const body = await parseJsonObject(request);
      const bodyDigest = `sha256:${await sha256Hex(canonicalBytes(body))}`;
      if (request.headers.get("x-dpone-canonical-sha256") !== bodyDigest) {
        throw new BrokerError("CLOUDFLARE_OBSERVER_RPC_BODY_DIGEST_MISMATCH", 400, false);
      }
      if (v2) {
        return exactResultResponse(
          await observeCloudflareDeploymentV2(body, currentRequestId, config),
          currentRequestId,
        );
      }
      const input = parseCloudflareDeploymentObservationRequest(body, config.accountId);
      assertCloudflareObserverRequestFreshness(input.requestedAt, Date.now());
      if (input.requestId !== currentRequestId) {
        throw new BrokerError("REQUEST_ID_MISMATCH", 400, false);
      }
      if (
        input.expectedNetworkSurface.hostname !== config.approvedIngressHostname ||
        input.expectedNetworkSurface.zone_id !== config.approvedIngressZoneId
      ) {
        throw new BrokerError("CLOUDFLARE_NETWORK_SCOPE_MISMATCH", 409, false);
      }
      const serviceIdentity = `cloudflare-worker:${config.accountId}/${config.serviceName}@${config.workerVersionId}`;
      const result = await new CloudflareDeploymentObserver(
        new CloudflareWorkersDeploymentReader(config.accountId, config.apiToken),
        config.accountId,
        serviceIdentity,
        config.workerVersionId,
      ).observe(input);
      const worm = new CloudflareEvidenceWormClient(
        config.wormService,
        authorityPin(input.inventory, "worm_mirror"),
        authorityPin(input.inventory, "worm_version_observer"),
        config.wormCallerAuth,
      );
      const mirrored = await mirrorEvidenceSet(worm, result);
      const serviceEvidenceEntries = mirrored.services.map((entry) => ({
        authority_role: entry.record.authority_role ?? null,
        deployment_observation_record: entry.record,
        deployment_observation_record_id: entry.recordId,
        deployment_observation_record_sha256: entry.recordSha256,
        deployment_observation_sha256: entry.record.deployment_observation_sha256 ?? null,
        worm: wormProjection(entry.worm),
      }));
      const mirroredNetwork = mirrored.network;
      const text = canonicalJson({
        b2_observer_service_identity: mirrored.b2ObserverServiceIdentity,
        network_surface_evidence_entry: {
          network_surface_observation_record: mirroredNetwork.record,
          network_surface_observation_record_id: mirroredNetwork.recordId,
          network_surface_observation_record_sha256: mirroredNetwork.recordSha256,
          network_surface_observation_sha256:
            mirroredNetwork.record.network_surface_observation_sha256 ?? null,
          worm: wormProjection(mirroredNetwork.worm),
        },
        observation: mirrored.observation,
        schema: CLOUDFLARE_DEPLOYMENT_RESULT_SCHEMA,
        schema_version: 1,
        service_evidence_entries: serviceEvidenceEntries,
        worm_service_identity: mirrored.wormServiceIdentity,
      });
      const bytes = new TextEncoder().encode(text);
      if (bytes.byteLength > MAX_RESULT_BYTES) {
        throw new BrokerError("CLOUDFLARE_DEPLOYMENT_RESULT_TOO_LARGE", 503, false);
      }
      return new Response(bytes, {
        headers: {
          "cache-control": "no-store",
          "content-type": "application/json; charset=utf-8",
          "x-content-type-options": "nosniff",
          "x-request-id": currentRequestId,
        },
        status: 200,
      });
    } catch (error) {
      return errorResponse(error, currentRequestId);
    }
  },
} satisfies ExportedHandler<CloudflareDeploymentObserverEnv>;

async function mirrorEvidenceSet(
  worm: CloudflareEvidenceWormClient,
  result: {
    readonly evidenceEntries: readonly JsonObject[];
    readonly networkEvidenceEntry: JsonObject;
    readonly observation: JsonObject;
  },
): Promise<{
  readonly b2ObserverServiceIdentity: string;
  readonly network: ConfirmedCloudflareEvidence;
  readonly observation: JsonObject;
  readonly services: readonly ConfirmedCloudflareEvidence[];
  readonly wormServiceIdentity: string;
}> {
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort("CLOUDFLARE_EVIDENCE_MIRROR_TIMEOUT"),
    EVIDENCE_MIRROR_ABSOLUTE_TIMEOUT_MS,
  );
  try {
    const mirrored = await worm.mirrorBatch(
      result,
      new Date(Date.now()).toISOString(),
      controller.signal,
    );
    return {
      b2ObserverServiceIdentity: mirrored.b2ObserverServiceIdentity,
      network: mirrored.network,
      observation: mirrored.observation,
      services: mirrored.services,
      wormServiceIdentity: mirrored.wormServiceIdentity,
    };
  } catch (error) {
    if (controller.signal.aborted) {
      throw new BrokerError("CLOUDFLARE_EVIDENCE_MIRROR_TIMEOUT", 503, true);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function authorityPin(
  inventory: CloudflareDeploymentObservationRpcRequest["inventory"],
  role: "worm_mirror" | "worm_version_observer",
): PrivateServicePin {
  const authority = inventory.find((row) => row.authority_role === role);
  if (authority === undefined) {
    throw new BrokerError("CLOUDFLARE_OBSERVER_AUTHORITY_PIN_MISSING", 503, false);
  }
  return {
    serviceIdentity: authority.service_identity,
    serviceName: authority.service,
    versionId: authority.worker_version_id,
  };
}

function assertExpectedCallee(
  headers: Headers,
  serviceIdentity: string,
  workerVersionId: string,
): void {
  if (
    headers.get("x-dpone-callee-service") !== "dpone-release-cloudflare-deployment-observer" ||
    headers.get("x-dpone-callee-service-identity") !== serviceIdentity ||
    headers.get("x-dpone-callee-version") !== workerVersionId
  ) {
    throw new BrokerError("CLOUDFLARE_OBSERVER_CALLEE_MISMATCH", 503, false);
  }
}

function exactResultResponse(bytes: Uint8Array, requestId: string): Response {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_RESULT_BYTES) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_RESULT_TOO_LARGE", 503, false);
  }
  return new Response(Uint8Array.from(bytes), {
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
      "x-request-id": requestId,
    },
    status: 200,
  });
}

function wormProjection(value: {
  readonly digest: string;
  readonly key: string;
  readonly retentionUntil: string;
  readonly versionId: string;
}) {
  return {
    digest: value.digest,
    key: value.key,
    retention_until: value.retentionUntil,
    version_id: value.versionId,
  };
}
